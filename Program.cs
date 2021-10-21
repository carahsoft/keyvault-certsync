using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using CommandLine;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
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

                    return DownloadCertificate(opts, client, cert);
                }
                else if (opts.Download)
                { 
                    int result = 0;
                    foreach (var cert in client.GetCertificateDetails())
                        if (DownloadCertificate(opts, client, cert) < 0)
                            result = -1;

                    return result;
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

        private static int DownloadCertificate(Options opts, SecretClient client, CertificateDetails cert)
        {
            X509Certificate2Collection chain;
            try
            {
                chain = client.GetCertificate(cert.SecretName, !string.IsNullOrEmpty(opts.Path) || opts.MarkExportable);
            }
            catch (Azure.RequestFailedException ex)
            {
                Log.Error(ex, "Error downloading certificate from Key Vault");
                return -1;
            }
            catch (NotSupportedException ex)
            {
                Log.Error(ex, "Key Vault certificate is invalid");
                return -1;
            }

            if (!string.IsNullOrEmpty(opts.Path))
            {
                DownloadCertificatePath(opts, cert, chain);
                return 0;
            }
            else if (opts.Store.HasValue)
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    Log.Error("Certificate store is only supported on Windows");
                    return -1;
                }

                DownloadCertificateStore(opts, cert, chain);
                return 0;
            }

            return 0;
        }

        private static void DownloadCertificatePath(Options opts, CertificateDetails cert, X509Certificate2Collection chain)
        {
            if (!Directory.Exists(cert.GetPath(opts.Path)))
                Directory.CreateDirectory(cert.GetPath(opts.Path));
            
            if(!opts.Quiet)
                Log.Information("Downloading certificate to {Path}", cert.GetPath(opts.Path));

            StringBuilder pemFulChain = new StringBuilder();

            string pemCert = chain[0].ToCertificatePEM();
            pemFulChain.AppendLine(pemCert);
            File.WriteAllText(cert.GetPath(opts.Path, CERT_PEM), pemCert);

            StringBuilder pemChain = new StringBuilder();
            for (int i = 1; i < chain.Count; i++)
            {
                pemChain.AppendLine(chain[i].ToCertificatePEM());
                pemFulChain.AppendLine(chain[i].ToCertificatePEM());
            }

            File.WriteAllText(cert.GetPath(opts.Path, CHAIN_PEM), pemChain.ToString());
            File.WriteAllText(cert.GetPath(opts.Path, FULLCHAIN_PEM), pemFulChain.ToString());

            if (chain[0].HasPrivateKey)
            {
                string privKey = chain[0].ToPrivateKeyPEM();

                CreateFileWithUserReadWrite(cert.GetPath(opts.Path, PRIVKEY_PEM));
                File.WriteAllText(cert.GetPath(opts.Path, PRIVKEY_PEM), privKey);

                pemFulChain.AppendLine(privKey);
                CreateFileWithUserReadWrite(cert.GetPath(opts.Path, FULLKEYCHAIN_PEM));
                File.WriteAllText(cert.GetPath(opts.Path, FULLKEYCHAIN_PEM), pemFulChain.ToString());
            }
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

        private static void DownloadCertificateStore(Options opts, CertificateDetails cert, X509Certificate2Collection chain)
        {
            using X509Store store = new X509Store(opts.Store.Value);
            store.Open(OpenFlags.ReadWrite);

            chain[0].FriendlyName = cert.CertificateName;
            store.Add(chain[0]);

            using X509Store rootStore = new X509Store(StoreName.Root, opts.Store.Value);
            rootStore.Open(OpenFlags.ReadWrite);

            for (int i = 1; i < chain.Count; i++)
                rootStore.Add(chain[i]);
        }

        private static int HandleParseError(IEnumerable<Error> errs)
        {
            return -1;
        }
    }
}
