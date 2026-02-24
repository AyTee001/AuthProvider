using Microsoft.EntityFrameworkCore;

namespace AuthProvider.Client.Data
{
    public class ClientDbContext(DbContextOptions options) : DbContext(options)
    {
    }

}
