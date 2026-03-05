using AuthProvider.Data;
using AuthProvider.Migrator.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using System.ComponentModel.DataAnnotations;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = Host.CreateEmptyApplicationBuilder(new());

var path = Directory.GetCurrentDirectory();
builder.Configuration
    .SetBasePath(path)
    .AddJsonFile("migrator.appsettings.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables();

var connectionString = builder.Configuration.GetConnectionString("AuthProviderDbContextConnection");

builder.Services.AddDbContext<AuthProviderDbContext>(options =>
    options.UseSqlServer(connectionString, x => x.MigrationsAssembly("AuthProvider.Migrator")));

builder.Services.AddOpenIddict()
.AddCore(options =>
{
    options.UseEntityFrameworkCore()
           .UseDbContext<AuthProviderDbContext>();
});


var mvcDemoClientSettings = new MvcDemoClientSettings();
builder.Configuration.GetRequiredSection(MvcDemoClientSettings.SectionName).Bind(mvcDemoClientSettings);
Validator.ValidateObject(mvcDemoClientSettings, new ValidationContext(mvcDemoClientSettings), true);


using var host = builder.Build();

using (var scope = host.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AuthProviderDbContext>();

    Console.WriteLine("Applying migrations...");
    await context.Database.MigrateAsync();

    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    var clientId = mvcDemoClientSettings.ClientId;
    var redirectUri = mvcDemoClientSettings.RedirectUri;
    var postLogoutRedirectUri = mvcDemoClientSettings.PostLogoutRedirectUri;
    var clientSecret = mvcDemoClientSettings.ClientSecret;

    if (await manager.FindByClientIdAsync(clientId) == null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            ConsentType = ConsentTypes.Explicit,
            DisplayName = "MVC Client Application",
            RedirectUris = { new Uri(redirectUri) },
            PostLogoutRedirectUris = { new Uri(postLogoutRedirectUri) },
            Permissions = {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Revocation,

                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,

                        Permissions.ResponseTypes.Code,

                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                    },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange }
        });
    }
}

Console.WriteLine("Migration complete. Exiting.");
