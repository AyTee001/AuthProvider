
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using System.Net;
using System.Net.Http.Headers;

namespace AuthProvider.Client.Http
{
    public class AuthDelegatingHandler(IHttpContextAccessor httpContextAccessor, OpenIddictClientService clientService) : DelegatingHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
        private readonly OpenIddictClientService _clientService = clientService;

        private static readonly SemaphoreSlim _lock = new(1, 1);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_httpContextAccessor.HttpContext is null)
            {
                return await base.SendAsync(request, cancellationToken);
            }

            var token = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refreshToken = await _httpContextAccessor.HttpContext.GetTokenAsync("refresh_token");
                if (refreshToken is null) return response;

                await _lock.WaitAsync(cancellationToken);
                try
                {
                    var currentToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken);

                    if(currentToken == token)
                    {
                        var newAccessToken = await RefreshTokensAsync(refreshToken);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newAccessToken);
                    } else
                    {
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", currentToken);
                    }

                    response = await base.SendAsync(request, cancellationToken);
                }
                finally { _lock.Release(); }
            }

            return response;
        }

        private async Task<string> RefreshTokensAsync(string token)
        {
            var result = await _clientService.AuthenticateWithRefreshTokenAsync(new()
            {
                RefreshToken = token
            });

            var properties = new AuthenticationProperties(result.Properties);
            List<AuthenticationToken> tokens =
            [
                new AuthenticationToken
                {
                    Name = OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken,
                    Value = result.AccessToken
                },
            ];

            if (result.RefreshToken != null)
            {
                tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = result.RefreshToken });
            }

            properties.StoreTokens(tokens);

            await _httpContextAccessor.HttpContext!.SignInAsync(result.Principal, properties);

            return result.AccessToken;
        }
    }
}
