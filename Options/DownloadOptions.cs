using CommandLine;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace keyvault_certsync.Options
{
    [Verb("download", HelpText = "Download certificates from Key Vault")]
    public class DownloadOptions : BaseOptions
    {
        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public virtual string KeyVault { get; set; }

        [Option('n', "name", HelpText = "Name of certificate. Specify multiple by delimiting with commas.")]
        public string Name { get; set; }

        [Option('p', "path", Group = "location", HelpText = "Base directory to store certificates")]
        public string Path { get; set; }

        [Option('s', "store", Group = "location", HelpText = "Windows certificate store (CurrentUser, LocalMachine)")]
        public StoreLocation? Store { get; set; }

        [JsonIgnore]
        [Option('f', "force", HelpText = "Force download even when identical local certificate exists")]
        public bool Force { get; set; }

        [Option("mark-exportable", HelpText = "Mark Windows certificate key as exportable")]
        public bool MarkExportable { get; set; }

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
