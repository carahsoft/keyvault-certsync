using Azure.Core;
using keyvault_certsync.Models;
using keyvault_certsync.Options;
using keyvault_certsync.Stores;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace keyvault_certsync.Flows
{
    public class DownloadFlow : BaseFlow
    {
        private readonly DownloadOptions opts;

        public DownloadFlow(DownloadOptions opts, TokenCredential credential) : base(credential, opts.KeyVault)
        {
            this.opts = opts;
        }

        protected override int RunFlow()
        {
            if (!string.IsNullOrEmpty(opts.Path) && !Directory.Exists(opts.Path))
            {
                Log.Error("Directory {Path} does not exist", opts.Path);
                return -1;
            }

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

            bool hookFailed = false;
            var results = new List<DownloadResult>();
            foreach (var cert in certs)
            {
                var result = DownloadCertificate(cert);

                if (result.Status == DownloadStatus.Downloaded && 
                    Hooks.RunDeployHook(opts.DeployHook, result) != 0)
                    hookFailed = true;

                if (opts.Automate && result.Status != DownloadStatus.Error)
                    AddAutomation(cert.CertificateName);

                results.Add(result);
            }

            if (results.Any(w => w.Status == DownloadStatus.Downloaded) && !string.IsNullOrEmpty(opts.PostHook))
                Hooks.AddPostHook(opts.PostHook, results.Where(w => w.Status == DownloadStatus.Downloaded));

            return results.Any(w => w.Status == DownloadStatus.Error) || hookFailed ? -1 : 0;
        }

        private DownloadResult DownloadCertificate(CertificateDetails cert)
        {
            X509Certificate2Collection chain;
            try
            {
                chain = client.GetCertificate(cert.SecretName, !string.IsNullOrEmpty(opts.Path) || opts.MarkExportable);
                Log.Information("Downloaded certificate {Name} from key {Key}", cert.CertificateName, cert.SecretName);
            }
            catch (Azure.RequestFailedException ex)
            {
                Log.Error(ex, "Error downloading certificate {Name} from key {Key}", cert.CertificateName, cert.SecretName);
                return new DownloadResult(DownloadStatus.Error);
            }
            catch (NotSupportedException ex)
            {
                Log.Error(ex, "Key vault certificate {Name} from key {Key} is invalid", cert.CertificateName, cert.SecretName);
                return new DownloadResult(DownloadStatus.Error);
            }

            ICertificateStore store;

            if (!string.IsNullOrEmpty(opts.Path))
            {
                store = new FileCertificateStore(opts.Path);
            }
            else if (opts.Store.HasValue)
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    Log.Error("Certificate store is only supported on Windows");
                    return new DownloadResult(DownloadStatus.Error);
                }

                store = new WindowsCertificateStore(opts.Store.Value);
            }
            else
            {
                Log.Error("Must specify --path or --store option");
                return new DownloadResult(DownloadStatus.Error);
            }

            try
            {
                if (store.Exists(cert))
                {
                    if (!opts.Force)
                    {
                        Log.Information("Local certificate {Name} has identical thumbprint", cert.CertificateName);
                        return new DownloadResult(DownloadStatus.AlreadyExists, cert);
                    }
                    else
                    {
                        Log.Information("Force replacing local certificate {Name}", cert.CertificateName);
                    }
                }

                return store.Save(cert, chain);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error saving local certificate {Name}", cert.CertificateName);
                return new DownloadResult(DownloadStatus.Error);
            }
        }

        private void AddAutomation(string name)
        {
            var config = opts.ShallowCopy();
            config.Name = name;

            string file = Path.Combine(opts.ConfigDirectory, $"download_{name}.json");

            try
            {
                File.WriteAllText(file, JsonSerializer.Serialize(config, new JsonSerializerOptions()
                {
                    WriteIndented = true
                }));

                Log.Information("Added automation config for {Name} to {File}", name, file);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error saving automation config for {Name} to {File}", name, file);
            }
        }
    }
}
