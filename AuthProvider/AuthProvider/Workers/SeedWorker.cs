using AuthProvider.Configuration;
using AuthProvider.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthProvider.Workers
{
    public class SeedWorker(IServiceProvider serviceProvider, IOptions<OpenIddictSettings> openIddictSettings) : IHostedService
    {
        private readonly OpenIddictSettings _openIddictSettings = openIddictSettings.Value;
        private readonly IServiceProvider _serviceProvider = serviceProvider;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<AuthProviderDbContext>();
            await context.Database.MigrateAsync(cancellationToken);

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var clientId = _openIddictSettings.Clients.MvcClient.ClientId;
            var redirectUri = _openIddictSettings.Clients.MvcClient.RedirectUri;
            var postLogoutRedirectUri = _openIddictSettings.Clients.MvcClient.PostLogoutRedirectUri;
            var clientSecret = _openIddictSettings.Clients.MvcClient.ClientSecret;

            if (await manager.FindByClientIdAsync(clientId, cancellationToken) == null)
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
                }, cancellationToken);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
