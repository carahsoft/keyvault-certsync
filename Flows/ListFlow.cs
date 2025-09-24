using Azure.Core;
using keyvault_certsync.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using keyvault_certsync.Models;
using Serilog;

namespace keyvault_certsync.Flows
{
    public class ListFlow : BaseFlow
    {
        private readonly ListOptions opts;
        
        public ListFlow(ListOptions opts, TokenCredential credential) : base(credential, opts.KeyVault)
        {
            this.opts = opts;
        }

        protected override int RunFlow()
        {
            IEnumerable<CertificateDetails> certs;
            if (!string.IsNullOrEmpty(opts.Name))
            {
                var names = opts.Name.Split(',').ToList();
                certs = client.GetCertificateDetails(names);

                var missing = names.Except(certs.Select(s => s.CertificateName), StringComparer.CurrentCultureIgnoreCase);

                if (missing.Any())
                {
                    Log.Error("Key vault does not contain certificate with name {Names}", missing);
                    return -1;
                }
            }
            else
            {
                certs = client.GetCertificateDetails();
            }

            
            foreach (var cert in certs)
                Console.WriteLine(cert.ToString());

            return 0;
        }
    }
}
