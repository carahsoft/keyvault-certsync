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

        public bool Exists(CertificateDetails cert)
        {
            using X509Store store = new X509Store(location);
            store.Open(OpenFlags.ReadOnly);

            var found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);

            if (found.Count > 0 && found[0].HasPrivateKey)
            {
                Log.Information("Local certificate has identical thumbprint");
                return true;
            }

            return false;
        }

        public DownloadResult Save(CertificateDetails cert, X509Certificate2Collection chain, bool force)
        {
            if (!force && Exists(cert))
                return new DownloadResult(DownloadStatus.AlreadyExists, cert);

            using X509Store store = new X509Store(location);
            store.Open(OpenFlags.ReadWrite);

            Log.Information("Adding certificate {Subject}", chain[0].Subject);

            chain[0].FriendlyName = cert.CertificateName;
            store.Add(chain[0]);

            using X509Store rootStore = new X509Store(StoreName.Root, location);
            rootStore.Open(OpenFlags.ReadWrite);

            for (int i = 1; i < chain.Count; i++)
            {
                Log.Information("Adding chain certificate {Subject}", chain[i].Subject);
                rootStore.Add(chain[i]);
            }

            return new DownloadResult(DownloadStatus.Downloaded, cert);
        }
    }
}
