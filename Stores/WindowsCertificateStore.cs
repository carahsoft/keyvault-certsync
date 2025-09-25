using keyvault_certsync.Models;
using Serilog;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync.Stores
{
    public class WindowsCertificateStore : ICertificateStore
    {
        private readonly StoreLocation location;

        public WindowsCertificateStore(StoreLocation location)
        {
            this.location = location;
        }

        public X509Certificate2 Get(string thumbprint)
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

            if (certs.Count > 0)
                return certs[0];

            return null;
        }

        public bool Exists(CertificateDetails cert)
        {
            var x509 = Get(cert.Thumbprint);

            if (x509 != null && x509.HasPrivateKey)
                return true;

            return false;
        }

        public DownloadResult Save(CertificateDetails cert, X509Certificate2Collection chain)
        {
            Log.Information("Saving certificate {Name} to {Store}", cert.CertificateName, location.ToString());

            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadWrite);

            // Remove existing certificate with same thumbprint if it exists
            var existingCerts = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
            if (existingCerts.Count > 0)
            {
                Log.Debug("Removing existing certificate with thumbprint {Thumbprint}", cert.Thumbprint);
                foreach (var existingCert in existingCerts)
                {
                    store.Remove(existingCert);
                }
            }
            
            chain[0].FriendlyName = cert.CertificateName;

            Log.Debug("Adding certificate {Subject} with private key", chain[0].Subject);
            store.Add(chain[0]);

            // Verify the private key was stored correctly
            var addedCert = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
            if (addedCert.Count > 0 && !addedCert[0].HasPrivateKey)
            {
                Log.Warning("Private key was not persisted correctly for certificate {Name}", cert.CertificateName);
            }

            // Add intermediate and root certificates to appropriate stores
            using var rootStore = new X509Store(StoreName.Root, location);
            rootStore.Open(OpenFlags.ReadWrite);
            using var caStore = new X509Store(StoreName.CertificateAuthority, location);
            caStore.Open(OpenFlags.ReadWrite);
            
            for (int i = 1; i < chain.Count; i++)
            {
                // Check if this is an intermediate or root certificate
                bool isSelfSigned = chain[i].Subject == chain[i].Issuer;

                if (!isSelfSigned)
                {
                    // Intermediate certificate - add to CA store
                    var existing = caStore.Certificates.Find(X509FindType.FindByThumbprint, chain[i].Thumbprint, false);
                    if (existing.Count == 0)
                    {
                        Log.Debug("Adding intermediate CA certificate {Subject}", chain[i].Subject);
                        caStore.Add(chain[i]);
                    }
                    else
                    {
                        Log.Debug("Skipping existing intermediate CA certificate {Subject}", chain[i].Subject);
                    }
                }
                else
                {
                    // Root certificate - add to Root store
                    var existing = rootStore.Certificates.Find(X509FindType.FindByThumbprint, chain[i].Thumbprint, false);
                    if (existing.Count == 0)
                    {
                        Log.Debug("Adding root CA certificate {Subject}", chain[i].Subject);
                        rootStore.Add(chain[i]);
                    }
                    else
                    {
                        Log.Debug("Skipping existing root CA certificate {Subject}", chain[i].Subject);
                    }
                }
            }

            return new DownloadResult(DownloadStatus.Downloaded, cert);
        }
    }
}
