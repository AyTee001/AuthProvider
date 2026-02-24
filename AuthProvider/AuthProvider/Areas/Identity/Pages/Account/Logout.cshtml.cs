using AuthProvider.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;

namespace AuthProvider.Areas.Identity.Pages.Account
{
    public class LogoutModel(SignInManager<ApplicationUser> signInManager) : PageModel
    {
        [BindProperty(Name = "post_logout_redirect_uri", SupportsGet = true)]
        public string? PostLogoutRedirectUri { get; set; }

        [BindProperty(Name = "client_id", SupportsGet = true)]
        public string? ClientId { get; set; }

        [BindProperty(Name = "id_token_hint", SupportsGet = true)]
        public string? IdTokenHint { get; set; }

        [BindProperty(Name = "state", SupportsGet = true)]
        public string? State { get; set; }

        private readonly SignInManager<ApplicationUser> _signInManager = signInManager;

        public async Task<IActionResult> OnPostAsync()
        {
            await _signInManager.SignOutAsync();

            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });

        }
    }
}
