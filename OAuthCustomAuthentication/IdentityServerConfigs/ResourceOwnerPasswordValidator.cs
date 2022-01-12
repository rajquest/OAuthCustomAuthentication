using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuthCustomAuthentication.IdentityServerConfigs
{
    public class ResourceOwnerPasswordValidator: IResourceOwnerPasswordValidator
    {
        // Validates the resource owner password credential
        // Once complete returns control to customTokenValidator Class
        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            try
            {

                bool isValidCredential = false;
                string scope = string.Empty;

                // Application Url Root - base address of the resource being accessed 
                string UrlRoot = "https://localhost:44330";
                string username = context.UserName;
                string password = context.Password;

                TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1);
                int epochTime = (int)ts.TotalSeconds;

                // Database Authentication
                // Verify if active Username Password exists 
                //isValidCredential = _authService.VerifyCredentialLogin(username, password);
                isValidCredential = true; // replace this line with database verification function

                // Add jwt claims to access token if user authenticated successfully
                if (isValidCredential)
                {
                    List<Claim> claims = new List<Claim>
                    {
                    new Claim(JwtClaimTypes.Subject, username),
                    new Claim(JwtClaimTypes.Issuer, UrlRoot),
                    new Claim(JwtClaimTypes.AuthenticationMethod, "pwd"),
                    new Claim(JwtClaimTypes.IdentityProvider, UrlRoot),
                    new Claim(JwtClaimTypes.AuthenticationTime, epochTime.ToString())
                    };

                    context.Result = new GrantValidationResult(new ClaimsPrincipal(new ClaimsIdentity(claims)));
                }
                else
                {
                    context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Authentication Failed");
                }

                return Task.CompletedTask;
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
