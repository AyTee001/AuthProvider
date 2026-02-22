using AuthProvider.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthProvider.Controllers;

[Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
public class UserinfoController(UserManager<ApplicationUser> userManager) : Controller
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;

    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
    [Produces("application/json")]
    public async Task<IActionResult> GetUserinfo()
    {
        var subject = User.GetClaim(Claims.Subject);
        if (string.IsNullOrEmpty(subject))
        {
            return CreateErrorResult(Errors.InvalidToken, "The access token provided does not contain a valid subject claim.");
        }

        var user = await _userManager.FindByIdAsync(subject);
        if (user is null)
        {
            return CreateErrorResult(Errors.InvalidToken, "The identity associated with this token could not be found in the AuthProvider database.");
        }

        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id
        };

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.UserName;
        }

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (User.HasScope(Scopes.Phone))
        {
            claims[Claims.PhoneNumber] = user.PhoneNumber;
        }

        await MapCustomApplicationClaims(user, claims);

        return Ok(claims);
    }

    private async Task MapCustomApplicationClaims(ApplicationUser user, Dictionary<string, object?> claims)
    {
        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        }
    }

    private IActionResult CreateErrorResult(string error, string description)
    {
        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        });

        return Challenge(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}