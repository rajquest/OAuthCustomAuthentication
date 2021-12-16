using IdentityServer4.Validation;
using System;
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
                string clientApiId = context.Result.ValidatedRequest.Client.ClientId;
                string state = context.Result.ValidatedRequest.Secret.Credential.ToString();
                string deviceUniqueNumber = context.Result.ValidatedRequest.Raw.Get(4);
                foreach (var item in context.Result.ValidatedRequest.RequestedScopes)
                {
                    scope = item;
                }

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
