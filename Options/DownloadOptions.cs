using CommandLine;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync.Options
{
    [Verb("download", HelpText = "Download certificates from Key Vault")]
    public class DownloadOptions : BaseOptions
    {
        [Option('q', "quiet", HelpText = "Suppress output")]
        public bool Quiet { get; set; }

        [Option('n', "name", HelpText = "Name of certificate. Specify multiple by delimiting with commas.")]
        public string Name { get; set; }

        [Option('p', "path", Group = "location", HelpText = "Base directory to store certificates")]
        public string Path { get; set; }

        [Option('s', "store", Group = "location", HelpText = "Windows certificate store (CurrentUser, LocalMachine)")]
        public StoreLocation? Store { get; set; }

        [Option('f', "force", HelpText = "Force download even when identical local certificate exists")]
        public bool Force { get; set; }

        [Option("mark-exportable", HelpText = "Mark Windows certificate key as exportable")]
        public bool MarkExportable { get; set; }

        [Option("post-hook",  HelpText = "Run after downloading certificates")]
        public string PostHook { get; set; }
    }
}
