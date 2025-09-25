using CommandLine;
using keyvault_certsync.Models;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace keyvault_certsync.Options
{
    [Verb("download", HelpText = "Download certificates from Key Vault")]
    public class DownloadOptions : BaseOptions
    {
        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public virtual string KeyVault { get; set; }

        [Option('n', "name", Group = "certificates", HelpText = "Name of certificate. Specify multiple by delimiting with commas.")]
        public string Name { get; set; }

        [Option("all", Group = "certificates", HelpText = "Download all certificates")]
        public bool All { get; set; }

        [Option('V',"version", HelpText = "Specific version of the certificate to download (e.g., a1b2c3d4e5f67890123456789abcdef0)")]
        public string Version { get; set; }

        [Option('p', "path", Group = "location", HelpText = "Base directory to store certificates")]
        public string Path { get; set; }

        [Option('t', "file-types", HelpText = "File types to generate (Cert, PrivKey, Chain, FullChain, FullChainPrivKey, Pkcs12)")]
        public FileType? FileTypes { get; set; }

        [Option("password", HelpText = "Password protect PKCS12 keystore")]
        public string Password { get; set; }

        [Option('s', "store", Group = "location", HelpText = "Windows certificate store (CurrentUser, LocalMachine)")]
        public StoreLocation? Store { get; set; }

        [Option("mark-exportable", HelpText = "Mark Windows certificate key as exportable")]
        public bool MarkExportable { get; set; }

        [JsonIgnore]
        [Option('f', "force", HelpText = "Force download even when identical local certificate exists")]
        public bool Force { get; set; }

        [Option("deploy-hook", HelpText = "Run for each certificate downloaded")]
        public string DeployHook { get; set; }

        [Option("post-hook",  HelpText = "Run after downloading all certificates")]
        public string PostHook { get; set; }

        [JsonIgnore]
        [Option('a', "automate", HelpText = "Generate config to run during sync")]
        public bool Automate { get; set; }

        public DownloadOptions ShallowCopy()
        {
            return (DownloadOptions)MemberwiseClone();
        }
    }
}
