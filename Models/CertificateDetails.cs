using Azure.Security.KeyVault.Secrets;
using System;
using System.Linq;

namespace keyvault_certsync.Models
{
    public class CertificateDetails
    {
        public Uri Id { get; } 
        public string Version { get; }
        public string SecretName { get; } 
        public DateTimeOffset? NotBefore { get; }
        public DateTimeOffset? ExpiresOn { get; }

        public string CertificateId { get; }
        public string CertificateName { get; }
        public string CertificateState { get; }
        public string SerialNumber { get; }
        public string Thumbprint { get; }

        public CertificateDetails(SecretProperties secret)
        {
            Id = secret.Id;
            Version = Id.ToString().Split('/').Last();
            
            SecretName = secret.Name;
            NotBefore = secret.NotBefore;
            ExpiresOn = secret.ExpiresOn;

            CertificateId = secret.Tags.SingleOrDefault(s => s.Key == "CertificateId").Value;

            if(!string.IsNullOrEmpty(CertificateId) && CertificateId.Contains('/'))
                CertificateName = CertificateId.Split('/').Last();

            CertificateState = secret.Tags.SingleOrDefault(s => s.Key == "CertificateState").Value;
            SerialNumber = secret.Tags.SingleOrDefault(s => s.Key == "SerialNumber").Value;
            Thumbprint = secret.Tags.SingleOrDefault(s => s.Key == "Thumbprint").Value;
        }

        public override string ToString()
        {
            return $"Secret Name: {SecretName}\n" +
                $"\tCertificate Id: {CertificateId}\n" +
                $"\tCertificate Name: {CertificateName}\n" +
                $"\tSerial Number: {SerialNumber}\n" +
                $"\tThumbprint: {Thumbprint}\n" +
                $"\tExpiry Date: {ExpiresOn}\n" +
                $"\tState: {CertificateState}";
        }

        public string ToShortString()
        {
            return $"Secret Name: {SecretName}\n" +
                   $"\tCertificate Id: {CertificateId}\n" +
                   $"\tCertificate Name: {CertificateName}";
        }

        public string ToVersionString()
        {
            return $"\tVersion: {Version}\n" +
                   $"\t\tSerial Number: {SerialNumber}\n" +
                   $"\t\tThumbprint: {Thumbprint}\n" +
                   $"\t\tStart Date: {NotBefore}\n" +
                   $"\t\tExpiry Date: {ExpiresOn}\n" +
                   $"\t\tState: {CertificateState}";
        }
    }
}
