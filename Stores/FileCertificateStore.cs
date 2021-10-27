﻿using keyvault_certsync.Models;
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
                Log.Error(ex, "Error reading local certificate");
                return false;
            }

            if (string.Equals(cert.Thumbprint, x509.Thumbprint, StringComparison.CurrentCultureIgnoreCase))
            {
                Log.Information("Local certificate has identical thumbprint");
                return true;
            }

            return false;
        }

        public DownloadResult Save(CertificateDetails cert, X509Certificate2Collection chain, bool force)
        {
            if (!Directory.Exists(cert.GetPath(path)))
                Directory.CreateDirectory(cert.GetPath(path));

            if (!force && Exists(cert))
                return DownloadResult.AlreadyExists;

            Log.Information("Downloading certificate to {Path}", cert.GetPath(path));

            StringBuilder pemFullChain = new StringBuilder();

            Log.Information("Adding certificate {Subject}", chain[0].Subject);

            string pemCert = chain[0].ToCertificatePEM();
            pemFullChain.AppendLine(pemCert);
            File.WriteAllText(cert.GetPath(path, CERT_PEM), pemCert);

            StringBuilder pemChain = new StringBuilder();
            for (int i = 1; i < chain.Count; i++)
            {
                Log.Information("Adding chain certificate {Subject}", chain[i].Subject);

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

            return DownloadResult.Downloaded;
        }

        private void CreateFileWithUserReadWrite(string filename)
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