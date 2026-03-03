using AuthProvider.Client.Configuration;
using AuthProvider.Client.Data;
using AuthProvider.Client.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Client;
using System.ComponentModel.DataAnnotations;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthProvider.Client
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var resourceServerSettings = new ResourceServerSettings();
            builder.Configuration.GetRequiredSection(ResourceServerSettings.SectionName).Bind(resourceServerSettings);
            var resourceServerSettingvalidationContext = new ValidationContext(resourceServerSettings);
            Validator.ValidateObject(resourceServerSettings, resourceServerSettingvalidationContext, true);

            var openIddictClientSettings = new OpenIddictClientSettings();
            builder.Configuration.GetRequiredSection(OpenIddictClientSettings.SectionName).Bind(openIddictClientSettings);
            var openIddictClientSettingsValidationContext = new ValidationContext(openIddictClientSettings);
            Validator.ValidateObject(openIddictClientSettings, openIddictClientSettingsValidationContext, true);
            
            var dataProtectionSettings = new DataProtectionSettings();
            builder.Configuration.GetRequiredSection(DataProtectionSettings.SectionName).Bind(dataProtectionSettings);
            var dataProtectionSettingsValidationContext = new ValidationContext(dataProtectionSettings);
            Validator.ValidateObject(dataProtectionSettings, dataProtectionSettingsValidationContext, true);

            builder.Services.AddDataProtection().SetApplicationName(dataProtectionSettings.AppName);

            builder.Services.AddDbContext<ClientDbContext>(options =>
                {
                    options.UseInMemoryDatabase("AuthProvider.Client");
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

                    var aspNetCoreBuilder = opt.UseAspNetCore()
                                    .EnableStatusCodePagesIntegration()
                                    .EnableRedirectionEndpointPassthrough()
                                    .EnablePostLogoutRedirectionEndpointPassthrough();

                    if (builder.Environment.IsDevelopment())
                    {
                        aspNetCoreBuilder.DisableTransportSecurityRequirement();
                    }

                    opt.UseSystemNetHttp()
                           .SetProductInformation(typeof(Program).Assembly);

                    opt.AddRegistration(new OpenIddictClientRegistration
                    {
                        Issuer = new Uri(openIddictClientSettings.Authority),

                        ClientId = openIddictClientSettings.ClientId,
                        ClientSecret = openIddictClientSettings.ClientSecret,
                        Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess },
                        RedirectUri = new Uri("callback/login/local", UriKind.Relative),
                        PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative)
                    });

                });

            builder.Services.AddHttpClient<ResourceServerService>(client =>
            {
                client.BaseAddress = new Uri(resourceServerSettings.BaseUri);
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
