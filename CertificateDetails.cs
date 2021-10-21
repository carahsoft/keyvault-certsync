using Azure.Security.KeyVault.Secrets;
using System;
using System.Linq;

namespace keyvault_certsync
{
    public class CertificateDetails
    {
        public Uri Id { get; } 
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
            
            SecretName = secret.Name;
            NotBefore = secret.NotBefore;
            ExpiresOn = secret.ExpiresOn;

            CertificateId = secret.Tags.SingleOrDefault(s => s.Key == "CertificateId").Value;
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
    }
}
