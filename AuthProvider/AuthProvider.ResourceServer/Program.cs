using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;

namespace AuthProvider.ResourceServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var authorityUri = builder.Configuration.GetRequiredSection("OpenIddictValidation").GetValue<string>("Authority")
                ?? throw new ArgumentNullException("Auth server uri must be provided!");
            //TODO: refactor as an aid for local dev
            var keysDirectoryName = "dp-keys";
            var keysPath = Path.Combine(builder.Environment.ContentRootPath, keysDirectoryName);

            if (!Directory.Exists(keysPath))
            {
                Directory.CreateDirectory(keysPath);
            }
            builder.Services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(keysPath))
                .SetApplicationName("Auth-Provider-System");

            builder.Services.AddOpenIddict()
            .AddValidation(options =>
            {
                options.SetIssuer(authorityUri);

                options.AddEncryptionKey(new SymmetricSecurityKey(
                    Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

                options.UseSystemNetHttp();

                options.UseAspNetCore();
            });

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
