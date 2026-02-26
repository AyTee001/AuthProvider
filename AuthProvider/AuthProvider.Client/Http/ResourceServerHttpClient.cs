namespace AuthProvider.Client.Http
{
    public class ResourceServerService(HttpClient httpClient)
    {
        public async Task<string> GetRandomJoke()
        {
            return await httpClient.GetStringAsync("api/jokes/random");
        }
    }
}
