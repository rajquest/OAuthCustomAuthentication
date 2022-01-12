using System.Collections.Generic;
using IdentityServer4.Models;

namespace OAuthCustomAuthentication.IdentityServerConfigs
{
    public class IdServerConfig
    {
        public static IEnumerable<ApiScope> ApiScopes => new List<ApiScope> {
            new ApiScope("Device_Admin", "Device Authorization API Scope"),
            new ApiScope("UiApis", "Angular UI API Scope")
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
            },
            new Client
            {
                ClientId = "UiApiClient",
                AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                AllowedScopes = { "UiApis" },
                AllowOfflineAccess = true,
                RequireClientSecret = false,
                RequireConsent = false,
                AlwaysSendClientClaims = true, // Dynamic Client Claim (role) inclusion in jwt Token 
                AccessTokenLifetime = 900 // seconds
            }
        };
    }
}
