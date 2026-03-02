using AuthProvider.Data;
using AuthProvider.Entities;
using AuthProvider.Workers;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace AuthProvider
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var connectionString = builder.Configuration.GetConnectionString("AuthProviderDbContextConnection")
                ?? throw new InvalidOperationException("Connection string 'AuthProviderDbContextConnection' not found.");
            var encryptionKey = builder.Configuration["OpenIddictServer:Clients:MvcClient:EncryptionKey"]
                ?? throw new ArgumentNullException("Token encryption key must be provided!");

            if (builder.Environment.IsDevelopment())
            {
                builder.Services.AddDataProtection().SetApplicationName("Auth-Provider-System");
            }

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddRazorPages();

            builder.Services.AddDbContext<AuthProviderDbContext>(options => {
                options.UseSqlServer(connectionString);
                options.UseOpenIddict();
            });

            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = false)
                .AddEntityFrameworkStores<AuthProviderDbContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddQuartz(options =>
            {
                options.UseSimpleTypeLoader();
                options.UseInMemoryStore();
            });
            builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

            builder.Services.AddOpenIddict()
                .AddCore(opt =>
                {
                    opt.UseEntityFrameworkCore().UseDbContext<AuthProviderDbContext>();
                    opt.UseQuartz();
                })
                .AddServer(opt =>
                {
                    opt.SetAuthorizationEndpointUris("connect/authorize")
                       .SetEndSessionEndpointUris("connect/logout")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserInfoEndpointUris("connect/userinfo")
                       .SetRevocationEndpointUris("connect/revocation");

                    opt.SetRefreshTokenLifetime(TimeSpan.FromMinutes(10));

                    opt.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);

                    opt.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
                    opt.AllowRefreshTokenFlow();

                    opt.AddEncryptionKey(new SymmetricSecurityKey(
                        Convert.FromBase64String(encryptionKey)));
                    opt.AddDevelopmentSigningCertificate();

                    if (builder.Environment.IsDevelopment())
                    {
                        opt.UseAspNetCore().DisableTransportSecurityRequirement()
                            .EnableAuthorizationEndpointPassthrough()
                            .EnableEndSessionEndpointPassthrough()
                            .EnableTokenEndpointPassthrough()
                            .EnableUserInfoEndpointPassthrough()
                            .EnableStatusCodePagesIntegration();
                    }
                    else
                    {
                    opt.UseAspNetCore()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableEndSessionEndpointPassthrough()
                        .EnableTokenEndpointPassthrough()
                        .EnableUserInfoEndpointPassthrough()
                        .EnableStatusCodePagesIntegration();
                    }
                })
                .AddValidation(opt =>
                {
                    opt.UseLocalServer();
                    opt.UseAspNetCore();
                });

            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Identity/Account/Login";
                options.LogoutPath = "/Identity/Account/Logout";
            });

            builder.Services.AddHostedService<SeedWorker>();
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
