using keyvault_certsync.Models;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync.Stores
{
    public interface ICertificateStore
    {
        bool Exists(CertificateDetails cert);

        DownloadResult Save(CertificateDetails cert, X509Certificate2Collection chain);
    }
}
