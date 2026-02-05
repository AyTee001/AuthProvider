using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using AuthProvider.Attributes;
using AuthProvider.Extensions;
using AuthProvider.ViewModels;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddictProps = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties;
using AuthProvider.Entities;

namespace AuthProvider.Controllers;

public class AuthorizationController(
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictScopeManager scopeManager,
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager) : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager = applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager = authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager = scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly UserManager<ApplicationUser> _userManager = userManager;

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var authRequest = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Failed to retrieve OpenID Connect request");

        var authResult = await HttpContext.AuthenticateAsync();
        if (authResult is not { Principal: not null } || MustForceAuthentication(authRequest, authResult))
        {
            if (authRequest.HasPromptValue(PromptValues.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictProps.Error] = Errors.LoginRequired,
                        [OpenIddictProps.ErrorDescription] = "The user must log in",
                    }));
            }

            TempData["IgnoreAuthenticationChallenge"] = true;

            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                Request.HasFormContentType ? Request.Form : Request.Query)
            });
        }

        var user = await _userManager.GetUserAsync(authResult.Principal)
            ?? throw new InvalidOperationException("User details not found!");

        var application = await _applicationManager.FindByClientIdAsync(authRequest.ClientId!)
            ?? throw new InvalidOperationException("Details of the calling client application not found!");

        var authorizations = await _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: authRequest.GetScopes())
        .ToListAsync();

        switch (await _applicationManager.GetConsentTypeAsync(application))
        {
            case ConsentTypes.External when authorizations.Count is 0:
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictProps.Error] = Errors.ConsentRequired,
                        [OpenIddictProps.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));

            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Count > 0:
            case ConsentTypes.Explicit when authorizations.Count > 0 && !authRequest.HasPromptValue(PromptValues.Consent):

                var identity = await CreateIdentityWithClaims(user);

                identity.SetScopes(authRequest.GetScopes());
                identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

                var authorization = authorizations.LastOrDefault();
                authorization ??= await _authorizationManager.CreateAsync(
                    identity: identity,
                    subject: await _userManager.GetUserIdAsync(user),
                    client: (await _applicationManager.GetIdAsync(application))!,
                    type: AuthorizationTypes.Permanent,
                    scopes: identity.GetScopes());

                identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(GetDestinations);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            case ConsentTypes.Explicit when authRequest.HasPromptValue(PromptValues.None):
            case ConsentTypes.Systematic when authRequest.HasPromptValue(PromptValues.None):
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        { OpenIddictProps.Error, Errors.ConsentRequired },
                        { OpenIddictProps.ErrorDescription, "Interactive user consent is required." }

                    }));

            default:
                return View(new AuthorizeViewModel
                {
                    ApplicationName = (await _applicationManager.GetLocalizedDisplayNameAsync(application))!,
                    Scope = authRequest.Scope
                });
        }

    }

    [Authorize, FormValue("submit.Accept")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Accept()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var user = await _userManager.GetUserAsync(User) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        var authorizations = await _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        if (authorizations.Count is 0 && await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                }));
        }

        var identity = await CreateIdentityWithClaims(user);

        identity.SetScopes(request.GetScopes());
        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

        var authorization = authorizations.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: identity,
            subject: await _userManager.GetUserIdAsync(user),
            client: (await _applicationManager.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }


    [Authorize, FormValue("submit.Deny")]
    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    public IActionResult Deny() => Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);


    [HttpGet("~/connect/logout")]
    public IActionResult Logout() => View();


    [ActionName(nameof(Logout)), HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutPost()
    {
        await _signInManager.SignOutAsync();

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var user = await _userManager.FindByIdAsync(result.Principal!.GetClaim(Claims.Subject)!);
            if (user is null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));
            }

            var identity = await CreateIdentityWithClaims(user, result.Principal);

            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }



    private async Task<ClaimsIdentity> CreateIdentityWithClaims(ApplicationUser user, ClaimsPrincipal? claimsPrincipal = null)
    {
        var identity = new ClaimsIdentity(claimsPrincipal?.Claims ?? [],
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

        //Always override core claims in case they changed between token issuance
        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
        .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
        .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
        .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
        .SetClaims(Claims.Role, [.. (await _userManager.GetRolesAsync(user))]);

        return identity;
    }


    private bool MustForceAuthentication(OpenIddictRequest? request, AuthenticateResult? authenticateResult)
    {
        if (request is null || authenticateResult is null) return true;

        var authResultFailed = authenticateResult is not { Succeeded: true };

        var loginPromptSpecified = request.HasPromptValue(PromptValues.Login);

        var maxAgeZero = request.MaxAge is 0;

        var now = TimeProvider.System.GetUtcNow();
        var maxAgeExpired = request.MaxAge is not null
                            && authenticateResult.Properties?.IssuedUtc is { } issuedAt
                            && now - issuedAt > TimeSpan.FromSeconds(request.MaxAge.Value);

        var shouldEnforceAuthChallenge = TempData["IgnoreAuthenticationChallenge"] is null or false;

        return authResultFailed || ((loginPromptSpecified || maxAgeZero || maxAgeExpired) && shouldEnforceAuthChallenge);
    }


    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        switch (claim.Type)
        {
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
