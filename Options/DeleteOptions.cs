using CommandLine;

namespace keyvault_certsync.Options
{
    [Verb("delete", HelpText = "Delete certificate from Key Vault")]
    public class DeleteOptions : BaseOptions
    {
        [Option('v', "keyvault", Required = true, HelpText = "Azure Key Vault name")]
        public virtual string KeyVault { get; set; }

        [Option('n', "name", Required = true, HelpText = "Name of certificate")]
        public string Name { get; set; }
    }
}
