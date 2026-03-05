using AuthProvider.Configuration;
using AuthProvider.Data;
using AuthProvider.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace AuthProvider
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var openIddictSettings = new OpenIddictSettings();
            builder.Configuration.GetRequiredSection(OpenIddictSettings.SectionName).Bind(openIddictSettings);
            Validator.ValidateObject(openIddictSettings, new ValidationContext(openIddictSettings), true);

            var dataProtectionSettings = new DataProtectionSettings();
            builder.Configuration.GetRequiredSection(DataProtectionSettings.SectionName).Bind(dataProtectionSettings);
            Validator.ValidateObject(dataProtectionSettings, new ValidationContext(dataProtectionSettings), true);

            builder.Services.Configure<OpenIddictSettings>(builder.Configuration.GetSection(OpenIddictSettings.SectionName));

            var connectionString = builder.Configuration.GetConnectionString("AuthProviderDbContextConnection")
                ?? throw new InvalidOperationException("Connection string 'AuthProviderDbContextConnection' not found.");

                builder.Services.AddDataProtection().SetApplicationName(dataProtectionSettings.AppName);

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddRazorPages();

            builder.Services.AddDbContext<AuthProviderDbContext>(options => {
                options.UseSqlServer(connectionString);
            });

            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = false)
                .AddEntityFrameworkStores<AuthProviderDbContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddOpenIddict()
                .AddCore(opt =>
                {
                    opt.UseEntityFrameworkCore().UseDbContext<AuthProviderDbContext>();
                })
                .AddServer(opt =>
                {
                    opt.SetAuthorizationEndpointUris("connect/authorize")
                       .SetEndSessionEndpointUris("connect/logout")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserInfoEndpointUris("connect/userinfo")
                       .SetRevocationEndpointUris("connect/revocation");

                    opt.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));

                    opt.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);

                    opt.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
                    opt.AllowRefreshTokenFlow();

                    opt.AddEncryptionKey(new SymmetricSecurityKey(
                        Convert.FromBase64String(openIddictSettings.EncryptionKey)));
                    opt.AddDevelopmentSigningCertificate();


                    var aspNetOptionsBuilder = opt.UseAspNetCore()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableEndSessionEndpointPassthrough()
                        .EnableTokenEndpointPassthrough()
                        .EnableUserInfoEndpointPassthrough()
                        .EnableStatusCodePagesIntegration();

                    if (builder.Environment.IsDevelopment())
                    {
                        aspNetOptionsBuilder.DisableTransportSecurityRequirement();
                    }
                });

            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Identity/Account/Login";
                options.LogoutPath = "/Identity/Account/Logout";
            });

            //Emailing is not used in the current version, but this stub ensures that default services that might use emailing remain content with the setup
            builder.Services.AddSingleton<IEmailSender, NoOpEmailSender>();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseStatusCodePagesWithReExecute("~/error");
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapStaticAssets();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}")
                .WithStaticAssets();
            app.MapControllers();
            app.MapRazorPages();


            app.Run();
        }
    }
}
