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

    }
}
