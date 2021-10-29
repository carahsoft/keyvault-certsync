using Azure.Core;
using keyvault_certsync.Options;
using Serilog;
using System;

namespace keyvault_certsync.Flows
{
    public class DeleteFlow : BaseFlow
    {
        private readonly DeleteOptions opts;

        public DeleteFlow(DeleteOptions opts, TokenCredential credential) : base(credential, opts.KeyVault)
        {
            this.opts = opts;
        }

        protected override int RunFlow()
        {
            var cert = client.GetCertificateDetails(opts.Name);

            if (cert == null)
            {
                Log.Error("Key vault does not contain certificate with name {Name}", opts.Name);
                return -1;
            }

            try
            {
                client.StartDeleteSecret(cert.SecretName);
                Log.Information("Deleted certificate {Name} with key {Key}", opts.Name, cert.SecretName);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error uploading certificate {Name} with key {Key}", opts.Name, cert.SecretName);
                return -1;
            }

            return 0;
        }
    }
}
