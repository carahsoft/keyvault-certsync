using Azure.Security.KeyVault.Secrets;
using keyvault_certsync.Models;
using keyvault_certsync.Options;
using keyvault_certsync.Stores;
using Serilog;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync.Flows
{
    public class DownloadFlow : BaseFlow
    {
        private readonly DownloadOptions opts;

        public DownloadFlow(DownloadOptions opts) : base(opts)
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
                    Log.Error("Key Vault does not contain certificate with name {Names}", missing);
                    return -1;
                }
            }
            else
            {
                certs = client.GetCertificateDetails();
            }

            List<DownloadResult> results = new List<DownloadResult>();
            foreach (var cert in certs)
            {
                Log.Information("Processing certifiate {Name}", cert.CertificateName);

                if (!opts.Quiet)
                    Console.WriteLine(cert.ToString());

                results.Add(DownloadCertificate(opts, client, cert));
            }

            if (results.Any(w => w.Status == DownloadStatus.Downloaded) && !string.IsNullOrEmpty(opts.PostHook))
                return RunPostHook(opts.PostHook, results.Where(w => w.Status == DownloadStatus.Downloaded));

            return results.Any(w => w.Status == DownloadStatus.Error) ? -1 : 0;
        }

        private DownloadResult DownloadCertificate(DownloadOptions opts, SecretClient client, CertificateDetails cert)
        {
            X509Certificate2Collection chain;
            try
            {
                chain = client.GetCertificate(cert.SecretName, !string.IsNullOrEmpty(opts.Path) || opts.MarkExportable);
            }
            catch (Azure.RequestFailedException ex)
            {
                Log.Error(ex, "Error downloading certificate from Key Vault");
                return new DownloadResult(DownloadStatus.Error);
            }
            catch (NotSupportedException ex)
            {
                Log.Error(ex, "Key Vault certificate is invalid");
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

            if (!opts.Force && store.Exists(cert))
                return new DownloadResult(DownloadStatus.AlreadyExists, cert);

            return store.Save(cert, chain);
        }

        private int RunPostHook(string command, IEnumerable<DownloadResult> results)
        {
            string[] parts = command.Split(new[] { ' ' }, 2);

            ProcessStartInfo startInfo = new ProcessStartInfo(parts[0]);

            startInfo.EnvironmentVariables.Add("CERTIFICATE_NAMES", string.Join(",", results.Select(s => s.CertificateName)));
            startInfo.EnvironmentVariables.Add("CERTIFICATE_THUMBPRINTS", string.Join(",", results.Select(s => s.Thumbprint)));

            if (parts.Length > 1)
                startInfo.Arguments = parts[1];

            int exitCode;
            try
            {
                using var process = Process.Start(startInfo);
                process.WaitForExit();
                exitCode = process.ExitCode;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Unable to start post hook '{Hook}' '{HookArguments}'", startInfo.FileName, startInfo.Arguments);
                return -1;
            }

            if(exitCode == 0)
            {
                Log.Information("Post hook '{Hook}' '{HookArguments}' completed successfully", startInfo.FileName, startInfo.Arguments);
                return 0;
            }

            Log.Warning("Post hook '{Hook}' '{HookArguments}' completed with exit code {ExitCode}", startInfo.FileName, startInfo.Arguments, exitCode);
            return exitCode;
        }
    }
}
