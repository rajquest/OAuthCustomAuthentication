using System.Collections.Generic;
using IdentityServer4.Models;

namespace OAuthCustomAuthentication.IdentityServerConfigs
{
    public class IdServerConfig
    {
        public static IEnumerable<ApiScope> ApiScopes => new List<ApiScope> {
            new ApiScope("Device_Admin", "Device Authorization API Scope"),
        };

        public static IEnumerable<Client> Clients => new List<Client> {
            new Client {
                ClientId = "DeviceAuthApiClient",
                AllowedGrantTypes = GrantTypes.ClientCredentials, // refers to which type of authentication flow. Needs clientID and allows Secret to be passed
                AllowedScopes = {
                    "Device_Admin"
                },
                ClientSecrets =
                {
                    new Secret("ClientSecretsPlaceholder".Sha256()) // Accepts dynamic secret
                },
                AccessTokenLifetime = 600, // lifetime token expiry in seconds
                RequireClientSecret = false,
                RequireConsent = false
            }
        };
    }
}
