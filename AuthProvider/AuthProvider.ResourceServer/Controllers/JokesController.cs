using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace AuthProvider.ResourceServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public class JokesController : ControllerBase
    {
        private static readonly string[] Jokes =
        [
            "Why do Java programmers wear glasses? Because they can't C#.",
            "A SQL query walks into a bar, walks up to two tables, and asks, 'Can I join you?'",
            "How many developers does it take to change a light bulb? None, that's a hardware problem.",
            "There are 10 types of people in the world: those who understand binary, and those who don't.",
            "An optimist says 'The glass is half full'. A pessimist says 'The glass is half empty'. An engineer says 'The glass is twice as big as it needs to be'."
        ];

        [HttpGet("random")]
        public IActionResult GetRandomJoke()
        {
            var random = new Random();
            var jokeText = Jokes[random.Next(Jokes.Length)];

            return Ok(jokeText);
        }
    }
}
