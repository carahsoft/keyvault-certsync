using CommandLine;

namespace keyvault_certsync.Options
{
    [Verb("list", HelpText = "List certificates in Key Vault")]
    public class ListOptions : BaseOptions
    {
        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public virtual string KeyVault { get; set; }
        
        [Option('n', "name", HelpText = "Name of certificate. Specify multiple by delimiting with commas.")]
        public string Name { get; set; }
    }
}
