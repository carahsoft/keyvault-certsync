using CommandLine;

namespace keyvault_certsync.Options
{
    [Verb("list", HelpText = "List certificates in Key Vault")]
    public class ListOptions : BaseOptions
    {
        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public virtual string KeyVault { get; set; }
    }
}
