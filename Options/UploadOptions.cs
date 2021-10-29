using CommandLine;

namespace keyvault_certsync.Options
{
    [Verb("upload", HelpText = "Upload certificate to Key Vault")]
    public class UploadOptions : BaseOptions
    {
        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public virtual string KeyVault { get; set; }

        [Option('n', "name", Required = true, HelpText = "Name of certificate")]
        public string Name { get; set; }

        [Option('c', "cert", Required = true, HelpText = "Path to certificate in PEM format")]
        public string Certificate { get; set; }

        [Option('k', "key", Required = true, HelpText = "Path to private key in PEM format")]
        public string PrivateKey { get; set; }

        [Option("chain", Required = false, HelpText = "Path to CA chain in PEM format")]
        public string Chain { get; set; }

        [Option('f', "force", HelpText = "Force upload even when identical kev vault certificate exists")]
        public bool Force { get; set; }
    }
}
