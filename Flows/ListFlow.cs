﻿using Azure.Core;
using keyvault_certsync.Options;
using System;

namespace keyvault_certsync.Flows
{
    public class ListFlow : BaseFlow
    {
        public ListFlow(ListOptions opts, TokenCredential credential) : base(credential, opts.KeyVault)
        {

        }

        protected override int RunFlow()
        {
            foreach (var cert in client.GetCertificateDetails())
                Console.WriteLine(cert.ToString());

            return 0;
        }
    }
}
