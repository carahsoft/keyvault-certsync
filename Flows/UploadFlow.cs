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

        public UploadFlow(UploadOptions opts, TokenCredential credential) : base(opts, credential)
        {
            this.opts = opts;
        }

        protected override int RunFlow()
        {
            if (!File.Exists(opts.Certificate))
            {
                Log.Error("Certificate {Path} not found", opts.Certificate);
                return -1;
            }

            if (!File.Exists(opts.PrivateKey))
            {
                Log.Error("Private key {Path} not found", opts.PrivateKey);
                return -1;
            }

            if (!string.IsNullOrEmpty(opts.Chain) && !File.Exists(opts.Chain))
            {
                Log.Error("Certificate chain {Path} not found", opts.PrivateKey);
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
                Log.Error(ex, "Error reading certificate files");
                return -1;
            }

            var cert = client.GetCertificateDetails(opts.Name);

            string key = $"{opts.Name}{Guid.NewGuid()}";

            if (cert != null)
            {
                if (string.Equals(cert.Thumbprint, chain[0].Thumbprint, StringComparison.CurrentCultureIgnoreCase))
                {
                    Log.Information("Key vault certificate has identical thumbprint");
                    return 0;
                }

                Log.Information("Replacing exisiting key vault certificate");
                key = cert.SecretName;
            }

            var secret = chain.ToKeyVaultSecret(key, opts.Name);

            client.SetSecret(secret);

            return 0;
        }
    }
}
