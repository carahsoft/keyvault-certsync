using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using keyvault_certsync.Options;
using Serilog;
using System;

namespace keyvault_certsync.Flows
{
    public abstract class BaseFlow
    {
        protected readonly SecretClient client;

        public BaseFlow(BaseOptions opts, TokenCredential credential)
        {
            var kvUri = "https://" + opts.KeyVault + ".vault.azure.net";
            client = new SecretClient(new Uri(kvUri), credential);
        }

        public int Run()
        {
            try
            {
                return RunFlow();
            }
            catch (CredentialUnavailableException ex)
            {
                Log.Error(ex, "No Azure credential available");
                return -1;
            }
            catch (Azure.RequestFailedException ex)
            {
                Log.Error(ex, "Error accessing Key Vault");
                return -1;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An unknown error occurred");
                return -1;
            }
        }

        protected abstract int RunFlow();
    }
}
