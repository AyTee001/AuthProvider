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
            var encryptionKey = builder.Configuration.GetRequiredSection("OpenIddictValidation").GetValue<string>("EncryptionKey")
                ?? throw new ArgumentNullException("Token encryption key must be provided!");

            if (builder.Environment.IsDevelopment())
            {
                builder.Services.AddDataProtection().SetApplicationName("Auth-Provider-System");
            }

            builder.Services.AddOpenIddict()
            .AddValidation(options =>
            {
                options.SetIssuer(authorityUri);

                options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(encryptionKey)));

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
