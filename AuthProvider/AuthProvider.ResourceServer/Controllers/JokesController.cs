using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthProvider.ResourceServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] //Uses the default scheme to handle auth. In our case, this is the Openiddict validation
    public class JokesController : ControllerBase
    {
        private static readonly string[] Jokes =
        [
            "What's the only way to generate a truly random string?\nAsk a Windows sysadmin to exit VIM.",
            "– Why do programmers confuse Christmas with Halloween? – Because 31 (oct) = 25 (dec)",
            "A TCP packet walks into a bar. 'I’d like a beer.' 'You’d like a beer?' 'Yes, I’d like a beer.'",
            "Why did the developer go broke? Because he used up all his cache.",
            "A DBA walk-ins into a bar and joins two tables together",
            "How many developers does it take to change a light bulb? None, that's a hardware problem.",
            "There are 10 types of people in the world: those who understand binary, and those who don't.",
            "An optimist says 'The glass is half full'. A pessimist says 'The glass is half empty'. An engineer says 'The glass is twice as big as it needs to be'."
        ];

        [HttpGet("random")]
        public IActionResult GetRandomJoke()
        {
            var jokeText = Jokes[Random.Shared.Next(Jokes.Length)];
            return Ok(jokeText);
        }
    }
}
