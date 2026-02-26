using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthProvider.Client.Controllers
{
    public class AuthenticationController(OpenIddictClientService clientService) : Controller
    {
        private readonly OpenIddictClientService _clientService = clientService;

        [HttpGet("~/login")]
        public ActionResult LogIn(string returnUrl)
        {
            var redirectUrl = GetLocalUrlOrBase(returnUrl);

            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };

            return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/logout"), ValidateAntiForgeryToken]
        public async Task<ActionResult> LogOut(string returnUrl)
        {
            var authenticationResult = await HttpContext.AuthenticateAsync();
            if (authenticationResult is not { Succeeded: true })
            {
                return Redirect(GetLocalUrlOrBase(returnUrl));
            }

            // We only revoke the refresh token, which is not stateless, like access token
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token");

            if(refreshToken is not null)
            {
                var revocationRequest = new OpenIddictClientModels.RevocationRequest()
                {
                    Token = refreshToken,
                    TokenTypeHint = "refresh_token"
                };
                await _clientService.RevokeTokenAsync(revocationRequest);
            }

            await HttpContext.SignOutAsync();

            var authPropsDictionary = new Dictionary<string, string?>
            {
                [OpenIddictClientAspNetCoreConstants.Properties.IdentityTokenHint] = authenticationResult.Properties.GetTokenValue(OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken)
            };

            var properties = new AuthenticationProperties(authPropsDictionary)
            {
                RedirectUri = GetLocalUrlOrBase(returnUrl)
            };

            return SignOut(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/callback/login/{provider}"), HttpPost("~/callback/login/{provider}"), IgnoreAntiforgeryToken]
        public async Task<ActionResult> LogInCallback()
        {
            var authenticationResult = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

            if (authenticationResult is not { Succeeded: true, Principal.Identity.IsAuthenticated: true })
            {
                throw new InvalidOperationException("Cannot authenticate the user since no authentication data was issued by the auth server!");
            }

            var identity = new ClaimsIdentity(
                authenticationType: "ExternalLogin",
                nameType: ClaimTypes.Name,
                roleType: ClaimTypes.Role);

            identity.SetClaim(ClaimTypes.Email, authenticationResult.Principal.GetClaim(ClaimTypes.Email))
                    .SetClaim(ClaimTypes.Name, authenticationResult.Principal.GetClaim(ClaimTypes.Name))
                    .SetClaim(ClaimTypes.NameIdentifier, authenticationResult.Principal.GetClaim(ClaimTypes.NameIdentifier));

            identity.SetClaim(Claims.Private.RegistrationId, authenticationResult.Principal.GetClaim(Claims.Private.RegistrationId))
                    .SetClaim(Claims.Private.ProviderName, authenticationResult.Principal.GetClaim(Claims.Private.ProviderName));

            var properties = new AuthenticationProperties(authenticationResult.Properties.Items)
            {
                RedirectUri = authenticationResult.Properties.RedirectUri ?? "/",
                IssuedUtc = null,
                ExpiresUtc = null,
                IsPersistent = true
            };

            properties.StoreTokens(authenticationResult.Properties.GetTokens().Where(token => token.Name is
                OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
                OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken or
                OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken));

            return SignIn(new ClaimsPrincipal(identity), properties);
        }

        [HttpGet("~/callback/logout/{provider}"), HttpPost("~/callback/logout/{provider}"), IgnoreAntiforgeryToken]
        public async Task<ActionResult> LogOutCallback()
        {
            //Read properties set in the process of logging out to determine where to redirect the user after the process is finished
            var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

            return Redirect(result?.Properties?.RedirectUri ?? "/");
        }


        /// <summary>
        /// Checks if the passed url string is a local url and returns base url "/" otherwise, including when the passed value is null or whitespace
        /// </summary>
        private string GetLocalUrlOrBase(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "/";

            return Url.IsLocalUrl(url) ? url : "/";
        }
    }
}