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
            using var store = new X509Store(location);
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
            using var store = new X509Store(location);
            store.Open(OpenFlags.ReadWrite);

            Log.Information("Saving certificate {Name} to {Store}", cert.CertificateName, location.ToString());

            Log.Debug("Adding certificate {Subject}", chain[0].Subject);

            chain[0].FriendlyName = cert.CertificateName;
            store.Add(chain[0]);

            using var rootStore = new X509Store(StoreName.Root, location);
            rootStore.Open(OpenFlags.ReadWrite);

            for (int i = 1; i < chain.Count; i++)
            {
                Log.Debug("Adding chain certificate {Subject}", chain[i].Subject);
                rootStore.Add(chain[i]);
            }

            return new DownloadResult(DownloadStatus.Downloaded, cert);
        }
    }
}
