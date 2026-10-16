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
        protected const string KEYSTORE_PFX = "keystore.pfx";

        private readonly string path;
        private readonly FileType fileTypes;
        private readonly string password;

        public FileCertificateStore(string path, FileType fileTypes, string password = null)
        {
            this.path = path;
            this.fileTypes = fileTypes;
            this.password = password;
        }

        public bool Exists(CertificateDetails cert)
        {
            string certPath = null;
            X509Certificate2 x509 = null;

            // Check for cert.pem first
            if (fileTypes.HasFlag(FileType.Cert) && File.Exists(cert.GetPath(path, CERT_PEM)))
            {
                certPath = cert.GetPath(path, CERT_PEM);
            }
            // Fall back to keystore.pfx if Pkcs12 is specified
            else if (fileTypes.HasFlag(FileType.Pkcs12) && File.Exists(cert.GetPath(path, KEYSTORE_PFX)))
            {
                certPath = cert.GetPath(path, KEYSTORE_PFX);
            }
            else
            {
                return false;
            }

            try
            {
                x509 = certPath.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase)
                    ? X509CertificateLoader.LoadPkcs12FromFile(certPath, password)
                    : X509CertificateLoader.LoadCertificateFromFile(certPath);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Exception reading local certificate, replacing");
                return false;
            }

            if (string.Equals(cert.Thumbprint, x509.Thumbprint, StringComparison.OrdinalIgnoreCase))
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

            if (fileTypes.HasFlag(FileType.Pkcs12))
            {
                var pfx = chain.Export(X509ContentType.Pkcs12, password);
                CreateFileWithUserReadWrite(cert.GetPath(path, KEYSTORE_PFX));
                File.WriteAllBytes(cert.GetPath(path, KEYSTORE_PFX), pfx);
            }

            string pemCert = chain[0].ToCertificatePEM();
            pemFullChain.AppendLine(pemCert);

            if (fileTypes.HasFlag(FileType.Cert))
            {
                File.WriteAllText(cert.GetPath(path, CERT_PEM), pemCert);
            }

            var pemChain = new StringBuilder();
            for (int i = 1; i < chain.Count; i++)
            {
                Log.Debug("Adding chain certificate {Subject}", chain[i].Subject);

                pemChain.AppendLine(chain[i].ToCertificatePEM());
                pemFullChain.AppendLine(chain[i].ToCertificatePEM());
            }

            if (fileTypes.HasFlag(FileType.Chain))
            {
                File.WriteAllText(cert.GetPath(path, CHAIN_PEM), pemChain.ToString());
            }

            if (fileTypes.HasFlag(FileType.FullChain))
            {
                File.WriteAllText(cert.GetPath(path, FULLCHAIN_PEM), pemFullChain.ToString());
            }

            if (chain[0].HasPrivateKey)
            {
                string privKey = chain[0].ToPrivateKeyPEM();

                if (fileTypes.HasFlag(FileType.PrivKey))
                {
                    CreateFileWithUserReadWrite(cert.GetPath(path, PRIVKEY_PEM));
                    File.WriteAllText(cert.GetPath(path, PRIVKEY_PEM), privKey);
                }

                pemFullChain.AppendLine(privKey);
                if (fileTypes.HasFlag(FileType.FullChainPrivKey))
                {
                    CreateFileWithUserReadWrite(cert.GetPath(path, FULLKEYCHAIN_PEM));
                    File.WriteAllText(cert.GetPath(path, FULLKEYCHAIN_PEM), pemFullChain.ToString());
                }
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
