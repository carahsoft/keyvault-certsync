using Azure.Core;
using Azure.Identity;
using CommandLine;
using keyvault_certsync.Flows;
using keyvault_certsync.Options;
using keyvault_certsync.Stores;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace keyvault_certsync
{
    class Program
    {
        static int Main(string[] args)
        {
            string log_format = "{Level:u3}] {Message:lj}{NewLine}{ExceptionMessage}";
            string file_format = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} " + log_format;

            var levelSwitch = new LoggingLevelSwitch
            {
                MinimumLevel = LogEventLevel.Verbose
            };

            string logDir = GetLogDirectory();

            var log_config = new LoggerConfiguration()
                .Enrich.WithExceptionMessage()
                .WriteTo.Console(outputTemplate: log_format, levelSwitch: levelSwitch)
                .WriteTo.File(Path.Combine(logDir, "keyvault-certsync.log"), outputTemplate: file_format,
                    rollingInterval: RollingInterval.Month, retainedFileCountLimit: 6);

            Log.Logger = log_config.CreateLogger();

            TokenCredential credential;
            try
            {
                credential = GetCredential();
            }
            catch (Exception ex)
            {
                Log.Error(ex.Message);
                Log.CloseAndFlush();
                return -1;
            }

            int result = Parser.Default.ParseArguments<ListOptions, DownloadOptions, UploadOptions>(args).MapResult(
                (ListOptions opts) => new ListFlow(opts, credential).Run(),
                (DownloadOptions opts) =>
                {
                    if (opts.Quiet)
                        levelSwitch.MinimumLevel = LogEventLevel.Warning;

                    return new DownloadFlow(opts, credential).Run();
                },
                (UploadOptions opts) =>
                {
                    if (opts.Quiet)
                        levelSwitch.MinimumLevel = LogEventLevel.Warning;

                    return new UploadFlow(opts, credential).Run();
                },
                errs => HandleParseError());

            Log.CloseAndFlush();
            return result;
        }

        private static string GetLogDirectory()
        {
            try
            {
                string logDir = Path.Combine(
                    (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "/var/log/" :
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
                    "keyvault-certsync");
                Directory.CreateDirectory(logDir);
                return logDir;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error creating log directory. Defaulting to working directory. {ex.Message}");
                return string.Empty;
            }
        }

        private static TokenCredential GetCredential()
        {
            var thumbprint = Environment.GetEnvironmentVariable("AZURE_CLIENT_CERTIFICATE_THUMBPRINT");

            if (thumbprint != null)
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    throw new NotSupportedException("AZURE_CLIENT_CERTIFICATE_THUMBPRINT is only supported on Windows");

                var store = new WindowsCertificateStore(StoreLocation.LocalMachine);
                var x509 = store.Get(thumbprint);

                if (x509 == null)
                {
                    store = new WindowsCertificateStore(StoreLocation.CurrentUser);
                    x509 = store.Get(thumbprint);

                    if (x509 == null)
                        throw new CredentialUnavailableException("Unable to find certificate for authentication");
                }

                return new ClientCertificateCredential(
                    Environment.GetEnvironmentVariable("AZURE_TENANT_ID"),
                    Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"),
                    x509);
            }

            return new DefaultAzureCredential();
        }

        private static int HandleParseError()
        {
            return -1;
        }
    }
}
