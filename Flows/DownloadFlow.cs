using Azure.Security.KeyVault.Secrets;
using keyvault_certsync.Models;
using keyvault_certsync.Options;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

            bool downloaded = false;
            bool error = false;
            foreach (var cert in certs)
            {
                if (!opts.Quiet)
                {
                    Log.Information("Processing certifiate {Name}", cert.CertificateName);
                    Console.WriteLine(cert.ToString());
                }

                var result = DownloadCertificate(opts, client, cert);

                if (result == DownloadResult.Error)
                    error = true;

                if (result == DownloadResult.Success)
                    downloaded = true;
            }

            if (downloaded)
                return RunPostHook(opts);

            return error ? -1 : 0;
        }

        private bool IdenticalLocalCertificatePath(DownloadOptions opts, CertificateDetails cert)
        {
            if (!File.Exists(cert.GetPath(opts.Path, CERT_PEM)))
                return false;

            X509Certificate2 x509;
            try
            {
                x509 = new X509Certificate2(cert.GetPath(opts.Path, CERT_PEM));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error reading local certificate");
                return false;
            }

            if (string.Equals(cert.Thumbprint, x509.Thumbprint, StringComparison.CurrentCultureIgnoreCase))
            {
                if (!opts.Quiet)
                    Log.Information("Local certificate has identical thumbprint");

                return true;
            }

            return false;
        }

        private bool IdenticalLocalCertificateStore(DownloadOptions opts, CertificateDetails cert)
        {
            using X509Store store = new X509Store(opts.Store.Value);
            store.Open(OpenFlags.ReadOnly);

            var found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);

            if (found.Count > 0 && found[0].HasPrivateKey)
            {
                if (!opts.Quiet)
                    Log.Information("Local certificate has identical thumbprint");

                return true;
            }

            return false;
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
                return DownloadResult.Error;
            }
            catch (NotSupportedException ex)
            {
                Log.Error(ex, "Key Vault certificate is invalid");
                return DownloadResult.Error;
            }

            if (!string.IsNullOrEmpty(opts.Path))
            {
                return DownloadCertificatePath(opts, cert, chain);
            }
            else if (opts.Store.HasValue)
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    Log.Error("Certificate store is only supported on Windows");
                    return DownloadResult.Error;
                }

                return DownloadCertificateStore(opts, cert, chain);
            }

            Log.Error("Must specify --path or --store option");
            return DownloadResult.Error;
        }

        private DownloadResult DownloadCertificatePath(DownloadOptions opts, CertificateDetails cert, X509Certificate2Collection chain)
        {
            if (!Directory.Exists(cert.GetPath(opts.Path)))
                Directory.CreateDirectory(cert.GetPath(opts.Path));

            if (!opts.Force && IdenticalLocalCertificatePath(opts, cert))
                return DownloadResult.AlreadyExists;

            if (!opts.Quiet)
                Log.Information("Downloading certificate to {Path}", cert.GetPath(opts.Path));

            StringBuilder pemFullChain = new StringBuilder();

            if (!opts.Quiet)
                Log.Information("Adding certificate {Subject}", chain[0].Subject);

            string pemCert = chain[0].ToCertificatePEM();
            pemFullChain.AppendLine(pemCert);
            File.WriteAllText(cert.GetPath(opts.Path, CERT_PEM), pemCert);

            StringBuilder pemChain = new StringBuilder();
            for (int i = 1; i < chain.Count; i++)
            {
                if (!opts.Quiet)
                    Log.Information("Adding chain certificate {Subject}", chain[i].Subject);

                pemChain.AppendLine(chain[i].ToCertificatePEM());
                pemFullChain.AppendLine(chain[i].ToCertificatePEM());
            }

            File.WriteAllText(cert.GetPath(opts.Path, CHAIN_PEM), pemChain.ToString());
            File.WriteAllText(cert.GetPath(opts.Path, FULLCHAIN_PEM), pemFullChain.ToString());

            if (chain[0].HasPrivateKey)
            {
                string privKey = chain[0].ToPrivateKeyPEM();

                CreateFileWithUserReadWrite(cert.GetPath(opts.Path, PRIVKEY_PEM));
                File.WriteAllText(cert.GetPath(opts.Path, PRIVKEY_PEM), privKey);

                pemFullChain.AppendLine(privKey);
                CreateFileWithUserReadWrite(cert.GetPath(opts.Path, FULLKEYCHAIN_PEM));
                File.WriteAllText(cert.GetPath(opts.Path, FULLKEYCHAIN_PEM), pemFullChain.ToString());
            }

            return DownloadResult.Success;
        }

        private void CreateFileWithUserReadWrite(string filename)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                File.Create(filename).Dispose();
                new UnixFileInfo(filename).FileAccessPermissions =
                    FileAccessPermissions.UserRead | FileAccessPermissions.UserWrite;
            }
        }

        private DownloadResult DownloadCertificateStore(DownloadOptions opts, CertificateDetails cert, X509Certificate2Collection chain)
        {
            if (!opts.Force && IdenticalLocalCertificateStore(opts, cert))
                return DownloadResult.AlreadyExists;

            using X509Store store = new X509Store(opts.Store.Value);
            store.Open(OpenFlags.ReadWrite);

            if (!opts.Quiet)
                Log.Information("Adding certificate {Subject}", chain[0].Subject);

            chain[0].FriendlyName = cert.CertificateName;
            store.Add(chain[0]);

            using X509Store rootStore = new X509Store(StoreName.Root, opts.Store.Value);
            rootStore.Open(OpenFlags.ReadWrite);

            for (int i = 1; i < chain.Count; i++)
            {
                if (!opts.Quiet)
                    Log.Information("Adding chain certificate {Subject}", chain[i].Subject);

                rootStore.Add(chain[i]);
            }

            return DownloadResult.Success;
        }

        private int RunPostHook(DownloadOptions opts)
        {
            if (string.IsNullOrEmpty(opts.PostHook))
                return 0;

            string[] parts = opts.PostHook.Split(new[] { ' ' }, 2);

            ProcessStartInfo startInfo;

            if (parts.Length > 1)
                startInfo = new ProcessStartInfo()
                {
                    FileName = parts[0],
                    Arguments = parts[1]
                };
            else
                startInfo = new ProcessStartInfo(parts[0]);

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
                if (!opts.Quiet)
                    Log.Information("Post hook '{Hook}' '{HookArguments}' completed successfully", startInfo.FileName, startInfo.Arguments);

                return 0;
            }

            Log.Warning("Post hook '{Hook}' '{HookArguments}' completed with exit code {ExitCode}", startInfo.FileName, startInfo.Arguments, exitCode);
            return exitCode;
        }
    }
}
