using Microsoft.AspNetCore.Identity.UI.Services;

namespace AuthProvider.Services
{
    /// <summary>
    /// In the first implementation of the AuthProvider application no emailing is going to be supported.
    /// To still comply with generated ASP.NET Core Identity code this stub exists that does absolutely nothing.
    /// </summary>
    public class NoOpEmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            return Task.CompletedTask;
        }
    }
}