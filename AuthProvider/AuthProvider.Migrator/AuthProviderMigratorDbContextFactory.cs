using AuthProvider.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace AuthProvider.Migrator
{
    internal class AuthProviderMigratorDbContextFactory : IDesignTimeDbContextFactory<AuthProviderDbContext>
    {
        public AuthProviderDbContext CreateDbContext(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            var builder = new DbContextOptionsBuilder<AuthProviderDbContext>();
            var connectionString = configuration.GetConnectionString("AuthProviderDbContextConnection");

            builder.UseSqlServer(connectionString, b => b.MigrationsAssembly("AuthProvider.Migrator"));

            return new AuthProviderDbContext(builder.Options);
        }
    }
}
