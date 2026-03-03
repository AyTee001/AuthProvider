using System.ComponentModel.DataAnnotations;

namespace AuthProvider.Client.Configuration
{
    public class OpenIddictClientSettings
    {
        public const string SectionName = "OpenIddictClient";

        [Required, Url]
        public string Authority { get; init; } = string.Empty;

        [Required]
        public string ClientId { get; init; } = string.Empty;

        [Required]
        public string ClientSecret { get; init; } = string.Empty;
    }
}
