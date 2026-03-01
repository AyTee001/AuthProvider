using AuthProvider.Client.Data;
using AuthProvider.Client.Http;
using AuthProvider.Client.Workers;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthProvider.Client
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            //TODO: refactor as an aid for local dev

            var keysDirectoryName = "dp-keys";
            var keysPath = Path.Combine(builder.Environment.ContentRootPath, keysDirectoryName);

            if (!Directory.Exists(keysPath))
            {
                Directory.CreateDirectory(keysPath);
            }
            builder.Services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(keysPath))
                .SetApplicationName("Auth-Provider-System");

            builder.Services.AddDbContext<ClientDbContext>(options =>
                {
                    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
                    options.UseOpenIddict();
                });

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddTransient<AuthDelegatingHandler>();

            builder.Services.AddAuthentication(opt => { opt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme; })
                .AddCookie(options =>
                {
                    options.LoginPath = "/login";
                    options.LogoutPath = "/logout";

                    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                    options.SlidingExpiration = true;
                });

            //TODO: turn into options objects
            var authorityUri = builder.Configuration.GetRequiredSection("OpenIddictClient").GetValue<string>("Authority")
                ?? throw new ArgumentNullException("Auth server uri must be provided!");
            var clientId = builder.Configuration.GetRequiredSection("OpenIddictClient").GetValue<string>("ClientId")
                ?? throw new ArgumentNullException("Client id must be provided!");
            var clientSecret = builder.Configuration.GetRequiredSection("OpenIddictClient").GetValue<string>("ClientSecret")
                ?? throw new ArgumentNullException("Client secret must be provided!");

            var baseResourceServerUri = builder.Configuration.GetRequiredSection("ResourceServer").GetValue<string>("BaseUri")
                ?? throw new ArgumentNullException("The base uri of the resource server must be provided!");

            builder.Services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore().UseDbContext<ClientDbContext>();
                })
                .AddClient(opt =>
                {
                    opt.AllowAuthorizationCodeFlow()
                       .AllowRefreshTokenFlow();

                    opt.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                    if (builder.Environment.IsDevelopment())
                    {
                        opt.UseAspNetCore().DisableTransportSecurityRequirement()
                           .EnableStatusCodePagesIntegration()
                           .EnableRedirectionEndpointPassthrough()
                           .EnablePostLogoutRedirectionEndpointPassthrough();
                    }
                    else
                    {
                        opt.UseAspNetCore()
                           .EnableStatusCodePagesIntegration()
                           .EnableRedirectionEndpointPassthrough()
                           .EnablePostLogoutRedirectionEndpointPassthrough();
                    }

                    opt.UseSystemNetHttp()
                           .SetProductInformation(typeof(Program).Assembly);

                    opt.AddRegistration(new OpenIddictClientRegistration
                    {
                        Issuer = new Uri(authorityUri),

                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess },
                        RedirectUri = new Uri("callback/login/local", UriKind.Relative),
                        PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative)
                    });

                });

            builder.Services.AddHostedService<DbSetupWorker>();

            builder.Services.AddHttpClient<ResourceServerService>(client =>
            {
                client.BaseAddress = new Uri(baseResourceServerUri);
            }).AddHttpMessageHandler<AuthDelegatingHandler>();

            builder.Services.AddControllersWithViews();

            builder.Services.AddRouting(options =>
            {
                options.LowercaseUrls = true;
            });

            var app = builder.Build();

            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
            app.MapDefaultControllerRoute();

            app.Run();
        }
    }
}
