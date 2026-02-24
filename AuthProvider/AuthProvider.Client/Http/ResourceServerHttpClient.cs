namespace AuthProvider.Client.Http
{
    public class ResourceServerService(HttpClient httpClient)
    {
        public async Task<string> GetDataAsync()
        {
            return await httpClient.GetStringAsync("api/data");
        }
    }
}
