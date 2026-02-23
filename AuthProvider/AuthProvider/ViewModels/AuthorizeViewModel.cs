namespace AuthProvider.ViewModels
{
    public class AuthorizeViewModel(string? applicationName, string? scopesString)
    {
        public string? ApplicationName { get; set; } = applicationName;
        public string? Scope { get; set; } = scopesString;

        public string[] ScopeDisplayInfos { get; set; } = GetScopeDisplayInfos(scopesString);

        private static string[] GetScopeDisplayInfos(string? scopesString)
        {
            var scopes = (scopesString ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);

            return [.. scopes.Select(x =>
            {
                return x switch
                {
                    "openid" => "Verify your unique identity.",
                    "profile" => "Access your name and profile photo.",
                    "email" => "View your primary email address.",
                    "offline_access" => "Refresh your session automatically.",
                    _ => "Unknown scope."
                };
            })];
        }
    }
}
