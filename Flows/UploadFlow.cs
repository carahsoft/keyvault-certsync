using Azure.Core;
using keyvault_certsync.Options;
using Serilog;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync.Flows
{
    public class UploadFlow : BaseFlow
    {
        private readonly UploadOptions opts;

        public UploadFlow(UploadOptions opts, TokenCredential credential) : base(credential, opts.KeyVault)
        {
            this.opts = opts;
        }

        protected override int RunFlow()
        {
            if (!File.Exists(opts.Certificate))
            {
                Log.Error("Certificate {File} not found", opts.Certificate);
                return -1;
            }

            if (!File.Exists(opts.PrivateKey))
            {
                Log.Error("Private key {File} not found", opts.PrivateKey);
                return -1;
            }

            if (!string.IsNullOrEmpty(opts.Chain) && !File.Exists(opts.Chain))
            {
                Log.Error("Certificate chain {File} not found", opts.PrivateKey);
                return -1;
            }

            var chain = new X509Certificate2Collection();
            try
            {
                chain.Add(X509Certificate2.CreateFromPemFile(opts.Certificate, opts.PrivateKey));
                chain.ImportFromPemFile(opts.Chain);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error reading certificate files {File}", opts.Certificate);
                return -1;
            }

            var cert = client.GetCertificateDetails(opts.Name);

            string key = $"{opts.Name}{Guid.NewGuid()}";

            if (cert != null)
            {
                if (string.Equals(cert.Thumbprint, chain[0].Thumbprint, StringComparison.CurrentCultureIgnoreCase))
                {
                    if (!opts.Force)
                    {
                        Log.Information("Key vault certificate {Name} has identical thumbprint", opts.Name);
                        return 0;
                    }
                    else
                    {
                        Log.Information("Force replacing key vault certificate {Name}", opts.Name);
                    }
                }
                else
                {
                    Log.Debug("Updating key vault certificate {Name}", opts.Name);
                }

                key = cert.SecretName;
            }
            else
            {
                Log.Debug("Creating key vault certificate {Name}", opts.Name);
            }

            var secret = chain.ToKeyVaultSecret(key, opts.Name);

            try
            {
                client.SetSecret(secret);
                Log.Information("Uploaded certificate {Name} to key {Key}", opts.Name, key);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error uploading certificate {Name} to key {Key}", opts.Name, key);
                return -1;
            }

            return 0;
        }
    }
}
