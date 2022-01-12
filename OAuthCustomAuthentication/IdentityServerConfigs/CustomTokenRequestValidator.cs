using IdentityServer4.Validation;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuthCustomAuthentication.IdentityServerConfigs
{
    public class CustomTokenRequestValidator : ICustomTokenRequestValidator
    {

        // Intercept token request to perform validation on ImeiNumber and Hash value Secret
        // 
        public Task ValidateAsync(CustomTokenRequestValidationContext context)
        {
            try
            {
                bool isValidCredential = false;
                string scope = string.Empty;
                foreach (var item in context.Result.ValidatedRequest.RequestedScopes)
                {
                    scope = item;
                }

                string clientApiId = context.Result.ValidatedRequest.Client.ClientId;

                // Handle ResourceOwnerPasswordValidator validation request and Bypass other authentication grants
                if (clientApiId == "UiApiClient" && scope == "UiApis")
                {
                    string userid = context.Result.ValidatedRequest.Raw.Get(3);
                    string password = context.Result.ValidatedRequest.Raw.Get(4);

                    context.Result.ValidatedRequest.ClientClaims.Add(new Claim("role", "Admin"));
                    return Task.CompletedTask;
                }

                string state = context.Result.ValidatedRequest.Secret.Credential.ToString();
                string deviceUniqueNumber = context.Result.ValidatedRequest.Raw.Get(4);
               

                if (scope != null && deviceUniqueNumber != null && state != null)
                {
                    // Validation Check for corresponding Hash value verification
                    // isValidCredential = CompareHashValue(scope,)
                    isValidCredential = true;
                }

                if (!isValidCredential)
                {
                    context.Result.IsError = true;
                    context.Result.Error = "Invalid Credential";
                }

                return Task.CompletedTask;
            }
            catch (Exception)
            {
                context.Result.IsError = true;
                context.Result.Error = "Invalid Credential";
                return Task.CompletedTask;
            }

        }
    }
}
