using Azure.Security.KeyVault.Secrets;
using keyvault_certsync.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync
{
    public static class CertificateExtensions
    {
        public static IEnumerable<CertificateDetails> GetCertificateDetails(this SecretClient secretClient)
        {
            var secrets = secretClient.GetPropertiesOfSecrets();
            return secrets.Select(s => new CertificateDetails(s));
        }

        public static IEnumerable<CertificateDetails> GetCertificateDetails(this SecretClient secretClient, IEnumerable<string> names)
        {
            return secretClient.GetCertificateDetails()
                .Where(w => names.Contains(w.CertificateName, StringComparer.CurrentCultureIgnoreCase));
        }

        public static CertificateDetails GetCertificateDetails(this SecretClient secretClient, string name)
        {
            return secretClient.GetCertificateDetails()
                .SingleOrDefault(s => s.CertificateName.Equals(name, StringComparison.CurrentCultureIgnoreCase));
        }

        public static string GetPath(this CertificateDetails cert, string basePath)
        {
            return Path.Combine(basePath, cert.CertificateName);
        }

        public static string GetPath(this CertificateDetails cert, string basePath, string fileName)
        {
            return Path.Combine(basePath, cert.CertificateName, fileName);
        }

        public static X509Certificate2Collection GetCertificate(this SecretClient secretClient, string secretName, bool keyExportable = false, bool machineKey = false)
        {
            KeyVaultSecret secret = secretClient.GetSecret(secretName);
            return secret.ToCertificate(keyExportable, machineKey);
        }

        public static X509Certificate2Collection ToCertificate(this KeyVaultSecret secret, bool keyExportable = false, bool machineKey = false)
        {
            if ("application/x-pkcs12".Equals(secret.Properties.ContentType, StringComparison.InvariantCultureIgnoreCase))
            {
                byte[] pfx = Convert.FromBase64String(secret.Value);

                var collection = new X509Certificate2Collection();

                var flags = X509KeyStorageFlags.DefaultKeySet;

                if (keyExportable)
                    flags |= X509KeyStorageFlags.Exportable;

                if (machineKey)
                    flags |= X509KeyStorageFlags.MachineKeySet;

                collection.Import(pfx, null, flags);

                return collection;
            }

            throw new NotSupportedException($"Only PKCS#12 is supported. Found Content-Type: {secret.Properties.ContentType}");
        }

        public static KeyVaultSecret ToKeyVaultSecret(this X509Certificate2Collection collection, string key, string name)
        {
            byte[] pfx = collection.Export(X509ContentType.Pkcs12);

            var secret = new KeyVaultSecret(key, Convert.ToBase64String(pfx));
            secret.Properties.ContentType = "application/x-pkcs12";
            secret.Properties.NotBefore = collection[0].NotBefore;
            secret.Properties.ExpiresOn = collection[0].NotAfter;
            secret.Properties.Tags.Add("CertificateId", $"/certificates/{name}");
            secret.Properties.Tags.Add("CertificateState", "Ready");
            secret.Properties.Tags.Add("SerialNumber", collection[0].SerialNumber);
            secret.Properties.Tags.Add("Thumbprint", collection[0].Thumbprint);

            return secret;
        }

        public static string ToCertificatePEM(this X509Certificate2 cert)
        {
            byte[] certificateBytes = cert.Export(X509ContentType.Cert);
            char[] certificate = PemEncoding.Write("CERTIFICATE", certificateBytes);
            return new string(certificate);
        }

        public static string ToPrivateKeyPEM(this X509Certificate2 cert)
        {
            AsymmetricAlgorithm key = cert.GetRSAPrivateKey();
            byte[] privateKeyBytes = key.ExportPkcs8PrivateKey();
            char[] privateKey = PemEncoding.Write("PRIVATE KEY", privateKeyBytes);
            return new string(privateKey);
        }
    }
}
