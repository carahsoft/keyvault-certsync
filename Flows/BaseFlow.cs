using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using keyvault_certsync.Options;
using Serilog;
using System;

namespace keyvault_certsync.Flows
{
    public abstract class BaseFlow
    {
        protected const string CERT_PEM = "cert.pem";
        protected const string PRIVKEY_PEM = "privkey.pem";
        protected const string CHAIN_PEM = "chain.pem";
        protected const string FULLCHAIN_PEM = "fullchain.pem";
        protected const string FULLKEYCHAIN_PEM = "fullchain.privkey.pem";

        protected readonly SecretClient client;

        public BaseFlow(BaseOptions opts)
        {
            var kvUri = "https://" + opts.KeyVault + ".vault.azure.net";
            client = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
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
