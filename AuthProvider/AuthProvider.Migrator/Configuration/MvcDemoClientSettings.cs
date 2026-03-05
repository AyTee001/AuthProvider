using System.ComponentModel.DataAnnotations;

namespace AuthProvider.Migrator.Configuration
{
    public class MvcDemoClientSettings
    {
        public const string SectionName = "MvcDemoClient";

        [Required(AllowEmptyStrings = false)]
        public string ClientId { get; init; } = string.Empty;

        [Required]
        public string ClientSecret { get; init; } = string.Empty;

        [Required, Url]
        public string RedirectUri { get; init; } = string.Empty;

        [Required, Url]
        public string PostLogoutRedirectUri { get; init; } = string.Empty;
    }

}
