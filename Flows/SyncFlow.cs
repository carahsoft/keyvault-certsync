using Azure.Core;
using keyvault_certsync.Options;
using Serilog;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace keyvault_certsync.Flows
{
    public class SyncFlow : BaseFlow
    {
        private readonly SyncOptions opts;
        private readonly TokenCredential credential;

        public SyncFlow(SyncOptions opts, TokenCredential credential) : base()
        {
            this.opts = opts;
            this.credential = credential;
        }

        protected override int RunFlow()
        {
            string[] files;
            try
            {
                files = Directory.GetFiles(Path.Combine(opts.ConfigDirectory), "download_*.json");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error enumerating config files in directory {Path}", opts.ConfigDirectory);
                return -1;
            }
            
            if (files.Length == 0)
            {
                Log.Information("No automation configs found in {Path}", opts.ConfigDirectory);
                return 0;
            }

            Log.Information("Found {Count} automation config(s) in {Path}", files.Length, opts.ConfigDirectory);

            int ret = 0;
            foreach(var file in files)
            {
                DownloadOptions config;
                try
                {
                    config = JsonSerializer.Deserialize<DownloadOptions>(File.ReadAllText(file), new JsonSerializerOptions()
                    {
                        Converters = {
                            new JsonStringEnumConverter()
                        }
                    });
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error loading config {File}", file);
                    ret = -1;
                    continue;
                }

                // Ensure backwards compatibility before --all
                if (string.IsNullOrEmpty(config.Name))
                    config.All = true;
                
                DisplayAutomation(file, config);

                if (opts.Force)
                    config.Force = true;

                if (!opts.DryRun)
                {
                    var flow = new DownloadFlow(config, credential);

                    if (flow.Run() != 0)
                        ret = -1;
                }
            }

            return ret;
        }

        private void DisplayAutomation(string fileName, DownloadOptions config)
        {
            Log.Information("Automation {FileName}", fileName);
            Log.Debug("  Key Vault: {KeyVault}", config.KeyVault);

            // Display certificate selection
            if (config.All)
            {
                Log.Debug("  Certificates: All");
            }
            else if (!string.IsNullOrEmpty(config.Name))
            {
                var names = config.Name.Split(',');
                if (names.Length == 1)
                {
                    Log.Debug("  Certificate: {Name}", config.Name);
                }
                else
                {
                    Log.Debug("  Certificates: {Count} certificate(s)", names.Length);
                    foreach (var name in names)
                    {
                        Log.Debug("    - {Name}", name.Trim());
                    }
                }
            }

            // Display version if specified
            if (!string.IsNullOrEmpty(config.Version))
            {
                Log.Debug("  Version: {Version}", config.Version);
            }

            // Display download location
            if (!string.IsNullOrEmpty(config.Path))
            {
                Log.Debug("  Path: {Path}", config.Path);
            }

            if (config.Store.HasValue)
            {
                Log.Debug("  Store: {Store}", config.Store.Value);
                if (config.MarkExportable)
                {
                    Log.Debug("  Mark Exportable: Yes");
                }
            }

            // Display file types if specified
            if (config.FileTypes.HasValue && !string.IsNullOrEmpty(config.Path))
            {
                Log.Debug("  File Types: {FileTypes}", config.FileTypes.Value);
            }

            // Display PKCS12 password protection
            if (!string.IsNullOrEmpty(config.Password))
            {
                Log.Debug("  PKCS12 Password: (protected)");
            }

            // Display validation setting
            if (config.SkipValidation)
            {
                Log.Debug("  Skip Validation: Yes");
            }

            // Display force flag
            if (config.Force)
            {
                Log.Debug("  Force: Yes");
            }

            // Display hooks
            foreach (var hook in config.DeployHook ?? Array.Empty<string>())
            {
                Log.Debug("  Deploy Hook: {Hook}", hook);
            }

            foreach (var hook in config.PostHook ?? Array.Empty<string>())
            {
                Log.Debug("  Post Hook: {Hook}", hook);
            }

            if (!(config.DeployHook?.Any() ?? false) && !(config.PostHook?.Any() ?? false))
            {
                Log.Debug("  Hooks: None");
            }
        }
    }
}
