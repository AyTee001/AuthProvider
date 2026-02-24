using System.ComponentModel.DataAnnotations;

namespace AuthProvider.Client.Models
{
    public class ErrorViewModel
    {
        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }
    }
}
