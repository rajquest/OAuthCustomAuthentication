using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OAuthCustomAuthentication.IdentityServerConfigs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuthCustomAuthentication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "OAuthCustomAuthentication", Version = "v1" });
            });

            // Specify how IdentityServer behaves and works.
            // Enables CustomTokenRequestValidator to intercept token http request for custom validation before issuing bearer token
            // Replace .AddDeveloperSigningCredential()   to below in PROD environment
            // MachineKeySet	2	Private keys are stored in the local computer store rather than the current user store.
            // .AddSigningCredential(new X509Certificate2(keyFilePath, keyFilePasswd, X509KeyStorageFlags.MachineKeySet))
            services.AddIdentityServer(options => options.InputLengthRestrictions.ClientSecret = 256)
                .AddDeveloperSigningCredential()  
                .AddCustomTokenRequestValidator<CustomTokenRequestValidator>()
                .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                .AddInMemoryApiScopes(IdServerConfig.ApiScopes)
                .AddInMemoryClients(IdServerConfig.Clients);

            services.AddAuthentication("Bearer").AddJwtBearer("Bearer", options =>
            {
                // Application Url Root - base address of the resource being accessed 
                string UrlRoot = Configuration.GetValue<string>("JwtConfig:urlRoot");
                options.Authority = UrlRoot;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidIssuer = UrlRoot,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
            });

            // Enable Cross-Origin Resource Sharing (CORS)
            // CORS is an HTTP-header based mechanism that allows a server to indicate any origins (domain, scheme, or port)
            // other than its own from which a browser should permit loading resources
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(builder =>
                {
                    builder.WithOrigins(Configuration.GetValue<string>("JwtConfig:corsWhiteListUrl"))
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "OAuthCustomAuthentication v1"));
            }

            app.UseHttpsRedirection();
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedProto
            });
            
            app.UseRouting();

            // enable IdentityServer and Authentication/Authorization
            app.UseIdentityServer();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
