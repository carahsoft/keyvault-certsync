using CommandLine;

namespace keyvault_certsync.Options
{
    public class BaseOptions
    {
        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public string KeyVault { get; set; }
    }
}
