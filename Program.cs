using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using CommandLine;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace keyvault_certsync
{
    class Program
    {
        const string CERT_PEM = "cert.pem";
        const string PRIVKEY_PEM = "privkey.pem";
        const string CHAIN_PEM = "chain.pem";
        const string FULLCHAIN_PEM = "fullchain.pem";
        const string FULLKEYCHAIN_PEM = "fullchain.privkey.pem";

        static int Main(string[] args)
        {
            string log_format = "{Level:u3}] {Message:lj}{NewLine}{ExceptionMessage}";

            var log_config = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .Enrich.WithExceptionMessage()
                .WriteTo.Console(outputTemplate: log_format);

            Log.Logger = log_config.CreateLogger();

            int result = Parser.Default.ParseArguments<Options>(args).MapResult(
                (opts) => RunOptionsAsync(opts), errs => HandleParseError(errs));

            return result;
        }

        private static int RunOptionsAsync(Options opts)
        {
            if (!string.IsNullOrEmpty(opts.Path) && !Directory.Exists(opts.Path))
            {
                Log.Error("Directory {Path} does not exist", opts.Path);
                return -1;
            }

            var kvUri = "https://" + opts.KeyVault + ".vault.azure.net";
            var client = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());

            try
            {
                if (opts.ListCertificates)
                {
                    foreach (var cert in client.GetCertificateDetails())
                        Console.WriteLine(cert.ToString());

                    return 0;
                }
                else if (opts.Download && !string.IsNullOrEmpty(opts.Name))
                {
                    var cert = client.GetCertificateDetails(opts.Name);

                    if (cert == null)
                    {
                        Log.Error("Key Vault does not contain certificate with name {Name}", opts.Name);
                        return -1;
                    }

                    if (!opts.Quiet)
                    {
                        Log.Information("Processing certifiate {Name}", cert.CertificateName);
                        Console.WriteLine(cert.ToString());
                    }

                    var result = DownloadCertificate(opts, client, cert);

                    if (result == DownloadResult.Error)
                        return -1;

                    if(result == DownloadResult.Success)
                        return RunPostHook(opts);

                    return 0;
                }
                else if (opts.Download)
                {
                    bool downloaded = false;
                    bool error = false;
                    foreach (var cert in client.GetCertificateDetails())
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

                    if(downloaded)
                        return RunPostHook(opts);

                    return error ? -1 : 0;
                }
            }
            catch (CredentialUnavailableException ex)
            {
                Log.Error(ex, "No Azure credential available");
                return -1;
            }
            catch (Azure.RequestFailedException ex)
            {
                Log.Error(ex, "Error accessing Key Vault");
                return -1;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An unknown error occurred");
                return -1;
            }

            return -1;
        }

        private static bool IdenticalLocalCertificatePath(Options opts, CertificateDetails cert)
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

        private static bool IdenticalLocalCertificateStore(Options opts, CertificateDetails cert)
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

        private static DownloadResult DownloadCertificate(Options opts, SecretClient client, CertificateDetails cert)
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

            return DownloadResult.Success;
        }

        private static DownloadResult DownloadCertificatePath(Options opts, CertificateDetails cert, X509Certificate2Collection chain)
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

        private static void CreateFileWithUserReadWrite(string filename)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                File.Create(filename).Dispose();
                new UnixFileInfo(filename).FileAccessPermissions =
                    FileAccessPermissions.UserRead | FileAccessPermissions.UserWrite;
            }
        }

        private static DownloadResult DownloadCertificateStore(Options opts, CertificateDetails cert, X509Certificate2Collection chain)
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

        private static int RunPostHook(Options opts)
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

            if (!opts.Quiet && exitCode == 0)
                Log.Information("Post hook '{Hook}' '{HookArguments}' completed successfully", startInfo.FileName, startInfo.Arguments);
            else if (!opts.Quiet)
                Log.Warning("Post hook '{Hook}' '{HookArguments}' completed with exit code {ExitCode}", startInfo.FileName, startInfo.Arguments, exitCode);

            return exitCode != 0 ? exitCode : 0;
        }

        private static int HandleParseError(IEnumerable<Error> errs)
        {
            return -1;
        }
    }
}
