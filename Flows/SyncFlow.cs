using Azure.Core;
using keyvault_certsync.Options;
using Serilog;
using System;
using System.IO;
using System.Text.Json;

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

            int ret = 0;
            foreach(var file in files)
            {
                DownloadOptions config;
                try
                {
                    config = JsonSerializer.Deserialize<DownloadOptions>(File.ReadAllText(file));
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error loading config {File}", file);
                    ret = -1;
                    continue;
                }

                if (opts.Force)
                    config.Force = true;

                var flow = new DownloadFlow(config, credential);

                if (flow.Run() != 0)
                    ret = -1;
            }

            return ret;
        }
    }
}
