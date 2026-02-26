using AuthProvider.Client.Http;
using AuthProvider.Client.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace AuthProvider.Client.Controllers
{
    public class HomeController(ResourceServerService service) : Controller
    {
        private readonly ResourceServerService _service = service;

        public IActionResult Index(string? joke = null)
        {
            ViewData["Joke"] = joke;
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }


        [HttpPost]
        public async Task<IActionResult> FetchJoke()
        {
            try
            {
                var joke = await _service.GetRandomJoke();
                return RedirectToAction("Index", new { joke });
            }
            catch
            {
                return RedirectToAction("Index", new { joke = "Could not reach the resource server!" });
            }
        }
    }
}
