using System.ComponentModel.DataAnnotations;

namespace AuthProvider.Configuration
{
    public class DataProtectionSettings
    {

        public const string SectionName = "DataProtection";

        [Required]
        public string AppName { get; init; } = string.Empty;
    }
}
