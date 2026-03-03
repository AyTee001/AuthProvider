using System.ComponentModel.DataAnnotations;

namespace AuthProvider.Client.Configuration
{
    public class ResourceServerSettings
    {
        public const string SectionName = "ResourceServer";

        [Required, Url]
        public string BaseUri { get; init; } = string.Empty;
    }
}
