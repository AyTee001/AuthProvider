using System.ComponentModel.DataAnnotations;

namespace AuthProvider.Configuration
{
    public class OpenIddictSettings
    {
        public const string SectionName = "OpenIddictServer";

        [Required]
        public string Authority { get; init; } = string.Empty;

        [Required]
        public string EncryptionKey { get; init; } = string.Empty;

        [Required]
        public ClientsSettings Clients { get; init; } = new();
    }

    public class ClientsSettings
    {
        [Required]
        public MvcClientSettings MvcClient { get; init; } = new();
    }

    public class MvcClientSettings
    {
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
