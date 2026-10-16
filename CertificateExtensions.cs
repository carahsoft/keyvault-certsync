using Azure;
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
            return secrets.Select(s => new CertificateDetails(s)).OrderBy(o => o.CertificateName);
        }

        public static IEnumerable<CertificateDetails> GetCertificateDetails(this SecretClient secretClient, IEnumerable<string> names)
        {
            return secretClient.GetCertificateDetails()
                .Where(w => names.Contains(w.CertificateName, StringComparer.OrdinalIgnoreCase));
        }

        public static CertificateDetails GetCertificateDetails(this SecretClient secretClient, string name)
        {
            return secretClient.GetCertificateDetails()
                .SingleOrDefault(s => s.CertificateName.Equals(name, StringComparison.OrdinalIgnoreCase));
        }

        public static IEnumerable<CertificateDetails> GetCertificateVersions(this SecretClient secretClient, string secretName)
        {
            var versions = secretClient.GetPropertiesOfSecretVersions(secretName);
            return versions.Select(s => new CertificateDetails(s)).OrderByDescending(o => o.ExpiresOn);
        }

        public static string GetPath(this CertificateDetails cert, string basePath)
        {
            // Security: Sanitize certificate name to prevent path traversal attacks
            string safeName = cert.CertificateName.SanitizeFileName();
            return Path.Combine(basePath, safeName);
        }

        public static string GetPath(this CertificateDetails cert, string basePath, string fileName)
        {
            // Security: Sanitize certificate name to prevent path traversal attacks
            string safeName = cert.CertificateName.SanitizeFileName();
            return Path.Combine(basePath, safeName, fileName);
        }

        public static string SanitizeFileName(this string name)
        {
            if (string.IsNullOrEmpty(name))
                throw new ArgumentException("File name cannot be null or empty", nameof(name));

            // Remove any path traversal characters and invalid filename characters
            char[] invalidChars = Path.GetInvalidFileNameChars();
            string sanitized = string.Concat(name.Where(c => !invalidChars.Contains(c) && c != '.' && c != '/'));

            // Prevent relative path components
            sanitized = sanitized.Replace("..", "").Replace("./", "").Replace(".\\", "");

            if (string.IsNullOrEmpty(sanitized))
                throw new ArgumentException($"File name '{name}' contains only invalid characters", nameof(name));

            return sanitized;
        }

        public static X509Certificate2Collection GetCertificate(this SecretClient secretClient, string secretName,
            bool keyExportable = false, bool persistKey = false, bool machineKey = false, string version = null)
        {
            KeyVaultSecret secret = secretClient.GetSecret(secretName, version);
            return secret.ToCertificate(keyExportable, persistKey, machineKey);
        }

        public static X509Certificate2Collection ToCertificate(this KeyVaultSecret secret,
            bool keyExportable = false, bool persistKey = false, bool machineKey = false)
        {
            if ("application/x-pkcs12".Equals(secret.Properties.ContentType, StringComparison.InvariantCultureIgnoreCase))
            {
                byte[] pfx = Convert.FromBase64String(secret.Value);

                var flags = X509KeyStorageFlags.DefaultKeySet;

                if (keyExportable)
                    flags |= X509KeyStorageFlags.Exportable;

                if (persistKey)
                    flags |= X509KeyStorageFlags.PersistKeySet;

                if (machineKey)
                    flags |= X509KeyStorageFlags.MachineKeySet;

                return X509CertificateLoader.LoadPkcs12Collection(pfx, null, flags);
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

        /// <summary>
        /// Validates a certificate chain for completeness, validity, and proper structure
        /// </summary>
        public static ChainValidationResult ValidateChain(this X509Certificate2Collection chain, bool checkExpiration = true)
        {
            var result = new ChainValidationResult();

            // Check if chain is empty
            if (chain == null || chain.Count == 0)
            {
                result.IsValid = false;
                result.Errors.Add("ChainEmpty", "Certificate chain is empty");
                return result;
            }

            var endEntityCert = chain[0];

            // Check if end-entity certificate has a private key
            if (!endEntityCert.HasPrivateKey)
            {
                result.Warnings.Add("NoPrivateKey", "End-entity certificate does not have a private key");
            }

            // Check expiration dates
            if (checkExpiration)
            {
                var now = DateTime.UtcNow;
                for (int i = 0; i < chain.Count; i++)
                {
                    var cert = chain[i];
                    string certType = i == 0 ? "End-entity certificate" :
                                     i == chain.Count - 1 ? "Root certificate" :
                                     $"Intermediate certificate {i}";

                    if (cert.NotBefore > now)
                    {
                        result.IsValid = false;
                        result.Errors.Add($"NotYetValid_{i}", $"{certType} is not yet valid (NotBefore: {cert.NotBefore:u})");
                    }

                    if (cert.NotAfter < now)
                    {
                        result.IsValid = false;
                        result.Errors.Add($"Expired_{i}", $"{certType} has expired (NotAfter: {cert.NotAfter:u})");
                    }
                    else if (cert.NotAfter < now.AddDays(30))
                    {
                        result.Warnings.Add($"ExpiresSoon_{i}", $"{certType} expires soon (NotAfter: {cert.NotAfter:u})");
                    }
                }
            }

            // Validate chain structure and issuer relationships
            if (chain.Count > 1)
            {
                for (int i = 0; i < chain.Count - 1; i++)
                {
                    var subject = chain[i];
                    var issuer = chain[i + 1];

                    // Check if issuer's subject matches subject's issuer
                    if (!subject.Issuer.Equals(issuer.Subject, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Warnings.Add($"IssuerMismatch_{i}", $"Certificate {i} issuer does not match next certificate's subject");
                    }

                    // Verify signature (child certificate signed by parent)
                    try
                    {
                        using (var publicKey = issuer.GetRSAPublicKey() ??
                                              issuer.GetECDsaPublicKey() as AsymmetricAlgorithm)
                        {
                            if (publicKey == null)
                            {
                                result.Warnings.Add($"PublicKeyExtraction_{i}", $"Unable to extract public key from certificate {i + 1} to verify signature");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        result.Warnings.Add($"SignatureValidation_{i}", $"Error validating signature chain at position {i}: {ex.Message}");
                    }
                }

                // Check root certificate is self-signed
                var rootCert = chain[chain.Count - 1];
                if (!rootCert.Subject.Equals(rootCert.Issuer, StringComparison.OrdinalIgnoreCase))
                {
                    result.Warnings.Add("RootNotSelfSigned", "Root certificate is not self-signed (Subject != Issuer)");
                }
            }

            // Use Windows certificate chain validation
            try
            {
                using (var chainValidator = new X509Chain())
                {
                    chainValidator.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Don't check revocation by default
                    chainValidator.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority; // Allow self-signed roots
                    chainValidator.ChainPolicy.ExtraStore.AddRange(chain);

                    bool chainBuilt = chainValidator.Build(endEntityCert);

                    if (!chainBuilt)
                    {
                        int statusIndex = 0;
                        foreach (X509ChainStatus status in chainValidator.ChainStatus)
                        {
                            // Ignore UntrustedRoot for self-signed certificates
                            if (status.Status != X509ChainStatusFlags.UntrustedRoot)
                            {
                                result.Warnings.Add($"ChainStatus_{status.Status}_{statusIndex++}", status.StatusInformation);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add("SystemValidationError", $"Unable to perform system chain validation: {ex.Message}");
            }

            return result;
        }
    }
}
