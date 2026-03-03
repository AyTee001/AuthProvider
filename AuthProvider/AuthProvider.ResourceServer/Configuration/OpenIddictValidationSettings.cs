using System.ComponentModel.DataAnnotations;

namespace AuthProvider.ResourceServer.Configuration
{
    public class OpenIddictValidationSettings
    {
        public const string SectionName = "OpenIddictValidation";

        [Required, Url]
        public string Authority { get; init; } = string.Empty;

        [Required]
        public string EncryptionKey { get; init; } = string.Empty;
    }
}
