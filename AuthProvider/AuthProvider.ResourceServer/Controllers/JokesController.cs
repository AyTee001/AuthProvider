using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace AuthProvider.ResourceServer.Controllers
{
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public class JokesController : Controller
    {
        private readonly IReadOnlyList<ProgrammingJoke> Jokes =
        [
            new() { Id = 1, Category = "Computer Science", Text = "There are only 10 kinds of people in this world: those who understand binary and those who don’t." },
            new() { Id = 2, Category = "Computer Science", Text = "A programmer had a problem. He thought to himself, “I know, I’ll solve it with threads!”\r\nhas Now problems. two he" },
            new() { Id = 3, Category = "Networking", Text = "I would tell you a UDP joke, but you might not get it." },

            new() { Id = 4, Category = "Data", Text = "An SQL query goes into a bar, walks up to two tables and asks: “Mind if I join you?”" },
            new() { Id = 5, Category = "Systems", Text = "Distributed systems are just normal systems — but with more ways to fail." },

            new() { Id = 6, Category = "Security", Text = "JWTs never lie. Unless you don’t verify the signature." },
            new() { Id = 7, Category = "Security", Text = "Authentication tells you who someone is. Authorization tells you what they’re allowed to break." },
            new() { Id = 8, Category = "Security", Text = "OAuth went to therapy because it had trust issues." },

            new() { Id = 9, Category = "Engineering", Text = "Always code as if the person who ends up maintaining your code will be a violent psychopath who knows where you live." },

            new() { Id = 10, Category = "Engineering", Text = "In theory, theory and practice are the same. In practice, they are not." },
            new() { Id = 11, Category = "Engineering", Text = "Any sufficiently advanced bug is indistinguishable from a feature." },
            new() { Id = 12, Category = "Engineering", Text = "If you listen to a UNIX shell, can you hear the C?" },
            new() { Id = 13, Category = "Engineering", Text = "Weeks of coding can save you hours of planning." },
            new() { Id = 15, Category = "Engineering", Text = "The first 90% of the code accounts for the first 90% of the development time. The remaining 10% of the code accounts for the other 90% of the development time." },
        ];

        [HttpGet("~/")]
        public IActionResult GetJokes()
        {
            return Ok(Jokes);
        }
    }
}
