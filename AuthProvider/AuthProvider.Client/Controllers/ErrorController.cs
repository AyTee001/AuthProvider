using AuthProvider.Client.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace AuthProvider.Client.Controllers
{
    public class ErrorController : Controller
    {
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true), Route("~/error")]
        public IActionResult Error()
        {
            // If the error originated from the OpenIddict client, render the error details.
            var response = HttpContext.GetOpenIddictClientResponse();
            if (response is not null)
            {
                return View(new ErrorViewModel
                {
                    RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                    Error = response.Error,
                    ErrorDescription = response.ErrorDescription
                });
            }

            return View(new ErrorViewModel());
        }
    }
}
