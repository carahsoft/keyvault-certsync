using Azure.Core;
using Azure.Identity;
using CommandLine;
using keyvault_certsync.Flows;
using keyvault_certsync.Models;
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
        protected const string CONFIG_FILE = "config.json";

        static int Main(string[] args)
        {
            string log_format = "{Level:u3}] {Message:lj}{NewLine}{ExceptionMessage}";
            string file_format = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} " + log_format;

            var levelSwitch = new LoggingLevelSwitch
            {
                MinimumLevel = LogEventLevel.Information
            };

            var consoleLevelSwitch = new LoggingLevelSwitch
            {
                MinimumLevel = LogEventLevel.Verbose
            };

            string logDir = GetLogDirectory();

            var log_config = new LoggerConfiguration()
                .MinimumLevel.ControlledBy(levelSwitch)
                .Enrich.WithExceptionMessage()
                .WriteTo.Console(outputTemplate: log_format, levelSwitch: consoleLevelSwitch)
                .WriteTo.File(Path.Combine(logDir, "keyvault-certsync.log"), outputTemplate: file_format,
                    rollingInterval: RollingInterval.Month, retainedFileCountLimit: 6);

            Log.Logger = log_config.CreateLogger();

            var parserResult = Parser.Default.ParseArguments<ListOptions, DownloadOptions, SyncOptions, UploadOptions, DeleteOptions>(args);

            BaseOptions opts = null;
            parserResult.WithParsed((BaseOptions o) => opts = o );

            if (opts == null)
            {
                Log.CloseAndFlush();
                return -1;
            }

            if (opts.Debug)
                levelSwitch.MinimumLevel = LogEventLevel.Verbose;

            if (opts.Quiet)
                consoleLevelSwitch.MinimumLevel = LogEventLevel.Warning;

            if (string.IsNullOrEmpty(opts.ConfigDirectory))
                opts.ConfigDirectory = GetConfigDirectory();

            var config_file = Path.Combine(opts.ConfigDirectory, CONFIG_FILE);
            var config = Config.LoadConfig(config_file) ?? new Config();

            config.SetEnvironment();

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

            int ret = parserResult.MapResult(
                (ListOptions opts) => new ListFlow(opts, credential).Run(),
                (DownloadOptions opts) => new DownloadFlow(opts, credential).Run(),
                (SyncOptions opts) => new SyncFlow(opts, credential).Run(),
                (UploadOptions opts) => new UploadFlow(opts, credential).Run(),
                (DeleteOptions opts) =>new DeleteFlow(opts, credential).Run(),
                errors => -1);

            if (Hooks.RunPostHooks() != 0)
                ret = -1;

            if (ret == 0)
            {
                if(config.GetEnvironment())
                    config.SaveConfig(config_file);
            }

            Log.CloseAndFlush();
            return ret;
        }

        private static string GetLogDirectory()
        {
            try
            {
                string dir =
                    RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ?
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "keyvault-certsync", "logs") :
                        Path.Combine("/var/log/keyvault-certsync");
                Directory.CreateDirectory(dir);
                return dir;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error creating log directory. Defaulting to working directory. {ex.Message}");
                return string.Empty;
            }
        }

        private static string GetConfigDirectory()
        {
            try
            {
                string dir =
                    RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ?
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "keyvault-certsync", "config") :
                        Path.Combine("/etc/keyvault-certsync");
                Directory.CreateDirectory(dir);
                return dir;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error creating config directory. Defaulting to working directory.");
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
    }
}
