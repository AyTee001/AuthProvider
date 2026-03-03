using AuthProvider.ResourceServer.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using OpenIddict.Validation.AspNetCore;
using System.ComponentModel.DataAnnotations;

namespace AuthProvider.ResourceServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var openIddictValidationSettings = new OpenIddictValidationSettings();
            builder.Configuration.GetRequiredSection(OpenIddictValidationSettings.SectionName).Bind(openIddictValidationSettings);
            var openIddictSettingsValidationContext = new ValidationContext(openIddictValidationSettings);
            Validator.ValidateObject(openIddictValidationSettings, openIddictSettingsValidationContext, true);


            var dataProtectionSettings = new DataProtectionSettings();
            builder.Configuration.GetRequiredSection(DataProtectionSettings.SectionName).Bind(dataProtectionSettings);
            var dataProtectionSettingsValidationContext = new ValidationContext(dataProtectionSettings);
            Validator.ValidateObject(dataProtectionSettings, dataProtectionSettingsValidationContext, true);

            builder.Services.AddDataProtection().SetApplicationName(dataProtectionSettings.AppName);

            builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

            builder.Services.AddOpenIddict()
            .AddValidation(options =>
            {
                options.SetIssuer(openIddictValidationSettings.Authority);

                options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(openIddictValidationSettings.EncryptionKey)));

                options.UseSystemNetHttp();

                options.UseAspNetCore();
            });

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(opt =>
            {
                opt.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
                {
                    Name = HeaderNames.Authorization,
                    Type = SecuritySchemeType.Http,
                    Scheme = JwtBearerDefaults.AuthenticationScheme,
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Please enter your Access Token below"
                });

                opt.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = JwtBearerDefaults.AuthenticationScheme
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
