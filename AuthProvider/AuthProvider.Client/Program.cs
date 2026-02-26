using AuthProvider.Client.Data;
using AuthProvider.Client.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
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

                    opt.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableRedirectionEndpointPassthrough()
                       .EnablePostLogoutRedirectionEndpointPassthrough();

                    opt.UseSystemNetHttp()
                       .SetProductInformation(typeof(Program).Assembly);

                    opt.AddRegistration(new OpenIddictClientRegistration
                    {
                        Issuer = new Uri("https://localhost:7082/"),

                        ClientId = "mvc-client",
                        ClientSecret = "65bd1ee0-8d7c-4600-bb01-10f633ac1c8d",
                        Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess },
                        RedirectUri = new Uri("callback/login/local", UriKind.Relative),
                        PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative)
                    });

                });

            builder.Services.AddHttpClient<ResourceServerService>(client =>
            {
                client.BaseAddress = new Uri("https://localhost:7240/");
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
