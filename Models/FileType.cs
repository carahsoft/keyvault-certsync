using System;

namespace keyvault_certsync.Models
{
    [Flags]
    public enum FileType
    {
        Cert = 1,
        PrivKey = 2,
        Chain = 4,
        FullChain = 8,
        FullChainPrivKey = 16,
        Pkcs12 = 32,
    }
}
