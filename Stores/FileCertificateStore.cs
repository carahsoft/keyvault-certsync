using keyvault_certsync.Models;
using Mono.Unix;
using Serilog;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace keyvault_certsync.Stores
{
    public class FileCertificateStore : ICertificateStore
    {
        protected const string CERT_PEM = "cert.pem";
        protected const string PRIVKEY_PEM = "privkey.pem";
        protected const string CHAIN_PEM = "chain.pem";
        protected const string FULLCHAIN_PEM = "fullchain.pem";
        protected const string FULLKEYCHAIN_PEM = "fullchain.privkey.pem";

        private readonly string path;

        public FileCertificateStore(string path)
        {
            this.path = path;
        }

        public bool Exists(CertificateDetails cert)
        {
            if (!File.Exists(cert.GetPath(path, CERT_PEM)))
                return false;

            X509Certificate2 x509;
            try
            {
                x509 = new X509Certificate2(cert.GetPath(path, CERT_PEM));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Exception reading local certificate, replacing");
                return false;
            }

            if (string.Equals(cert.Thumbprint, x509.Thumbprint, StringComparison.CurrentCultureIgnoreCase))
                return true;

            return false;
        }

        public DownloadResult Save(CertificateDetails cert, X509Certificate2Collection chain)
        {
            if (!Directory.Exists(cert.GetPath(path)))
                Directory.CreateDirectory(cert.GetPath(path));

            Log.Information("Saving certificate {Name} to {Path}", cert.CertificateName, cert.GetPath(path));

            var pemFullChain = new StringBuilder();

            Log.Debug("Adding certificate {Subject}", chain[0].Subject);

            string pemCert = chain[0].ToCertificatePEM();
            pemFullChain.AppendLine(pemCert);
            File.WriteAllText(cert.GetPath(path, CERT_PEM), pemCert);

            var pemChain = new StringBuilder();
            for (int i = 1; i < chain.Count; i++)
            {
                Log.Debug("Adding chain certificate {Subject}", chain[i].Subject);

                pemChain.AppendLine(chain[i].ToCertificatePEM());
                pemFullChain.AppendLine(chain[i].ToCertificatePEM());
            }

            File.WriteAllText(cert.GetPath(path, CHAIN_PEM), pemChain.ToString());
            File.WriteAllText(cert.GetPath(path, FULLCHAIN_PEM), pemFullChain.ToString());

            if (chain[0].HasPrivateKey)
            {
                string privKey = chain[0].ToPrivateKeyPEM();

                CreateFileWithUserReadWrite(cert.GetPath(path, PRIVKEY_PEM));
                File.WriteAllText(cert.GetPath(path, PRIVKEY_PEM), privKey);

                pemFullChain.AppendLine(privKey);
                CreateFileWithUserReadWrite(cert.GetPath(path, FULLKEYCHAIN_PEM));
                File.WriteAllText(cert.GetPath(path, FULLKEYCHAIN_PEM), pemFullChain.ToString());
            }

            return new DownloadResult(DownloadStatus.Downloaded, cert)
            {
                Path = cert.GetPath(path)
            };
        }

        private static void CreateFileWithUserReadWrite(string filename)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                File.Create(filename).Dispose();
                new UnixFileInfo(filename).FileAccessPermissions =
                    FileAccessPermissions.UserRead | FileAccessPermissions.UserWrite;
            }
        }
    }
}
