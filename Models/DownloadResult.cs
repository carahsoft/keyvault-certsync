namespace keyvault_certsync.Models
{
    public class DownloadResult
    {
        public string CertificateName { get; }
        public string Thumbprint { get; }
        public string Path { get; set; }
        public DownloadStatus Status { get; }

        public DownloadResult(DownloadStatus status, CertificateDetails cert = null)
        {
            Status = status;
            CertificateName = cert?.CertificateName;
            Thumbprint = cert?.Thumbprint;
        }
    }
}
