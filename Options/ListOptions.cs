using CommandLine;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync.Options
{
    [Verb("list", HelpText = "List certificates in Key Vault")]
    public class ListOptions : BaseOptions
    {

    }
}
