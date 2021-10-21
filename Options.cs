using CommandLine;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync
{
    public class Options
    {
        [Option('q', "quiet", Required = false, HelpText = "Suppress output")]
        public bool Quiet { get; set; }

        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public string KeyVault { get; set; }


        [Option('l', "list", SetName = "list", Required = true, HelpText = "List certificates in Key Vault")]
        public bool ListCertificates { get; set; }


        [Option('d', "download", SetName = "download", Required = true, HelpText = "Download certificates from Key Vault")]
        public bool Download { get; set; }

        [Option('n', "name", SetName = "download", Required = false, HelpText = "Name of certificate")]
        public string Name { get; set; }

        [Option('p', "path", SetName = "download", Required = false, HelpText = "Base directory to store certificates")]
        public string Path { get; set; }

        [Option('s', "store", SetName = "download", Required = false, HelpText = "Windows certificate store (CurrentUser, LocalMachine)")]
        public StoreLocation? Store { get; set; }

        [Option("mark-exportable", SetName = "download", Required = false, HelpText = "Mark Windows certificate key as exportable")]
        public bool MarkExportable { get; set; }
    }
}
