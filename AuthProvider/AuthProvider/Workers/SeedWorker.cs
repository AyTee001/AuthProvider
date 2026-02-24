using AuthProvider.Data;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static System.Net.WebRequestMethods;

namespace AuthProvider.Workers
{
    public class SeedWorker(IServiceProvider serviceProvider) : IHostedService
    {
        private readonly IServiceProvider _serviceProvider = serviceProvider;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<AuthProviderDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("mvc-client", cancellationToken) == null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "mvc-client",
                    ClientSecret = "65bd1ee0-8d7c-4600-bb01-10f633ac1c8d",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "MVC Client Application",
                    RedirectUris = { new Uri("https://localhost:7197/callback/login/local") },
                    PostLogoutRedirectUris = { new Uri("https://localhost:7197/callback/logout/local") },
                    Permissions = {
                        Permissions.Endpoints.Authorization, 
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.Token,

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
