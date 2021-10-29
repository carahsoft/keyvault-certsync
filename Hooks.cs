using keyvault_certsync.Models;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace keyvault_certsync
{
    public static class Hooks
    {
        private static readonly Dictionary<string, List<DownloadResult>> postHooks = new();

        public static void AddPostHook(string command, IEnumerable<DownloadResult> results)
        {
            if (!postHooks.ContainsKey(command))
                postHooks.Add(command, new List<DownloadResult>());

            postHooks[command].AddRange(results);
        }

        public static int RunPostHooks()
        {
            bool hookFailed = false;
            foreach(var entry in postHooks)
            {
                if (RunPostHook(entry.Key, entry.Value) != 0)
                    hookFailed = true;
            }

            return hookFailed ? -1 : 0;
        }

        public static int RunDeployHook(string command, DownloadResult result)
        {
            string[] parts = command.Split(new[] { ' ' }, 2);

            var startInfo = new ProcessStartInfo(parts[0]);

            startInfo.EnvironmentVariables.Add("CERTIFICATE_NAME", result.CertificateName);
            startInfo.EnvironmentVariables.Add("CERTIFICATE_THUMBPRINT", result.Thumbprint);

            if (!string.IsNullOrEmpty(result.Path))
                startInfo.EnvironmentVariables.Add("CERTIFICATE_PATH", result.Path);

            if (parts.Length > 1)
                startInfo.Arguments = parts[1];

            return RunHook(startInfo, "Deploy");
        }

        private static int RunPostHook(string command, IEnumerable<DownloadResult> results)
        {
            string[] parts = command.Split(new[] { ' ' }, 2);

            var startInfo = new ProcessStartInfo(parts[0]);

            startInfo.EnvironmentVariables.Add("CERTIFICATE_NAMES", string.Join(",", results.Select(s => s.CertificateName)));
            startInfo.EnvironmentVariables.Add("CERTIFICATE_THUMBPRINTS", string.Join(",", results.Select(s => s.Thumbprint)));

            if (parts.Length > 1)
                startInfo.Arguments = parts[1];

            return RunHook(startInfo, "Post");
        }

        private static int RunHook(ProcessStartInfo startInfo, string type)
        {
            int exitCode;
            try
            {
                using var process = Process.Start(startInfo);
                process.WaitForExit();
                exitCode = process.ExitCode;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{HookType} hook '{Hook}' '{HookArguments}' failed to run",
                    type, startInfo.FileName, startInfo.Arguments);
                return -1;
            }

            if (exitCode == 0)
            {
                Log.Information("{HookType} hook '{Hook}' '{HookArguments}' completed successfully",
                    type, startInfo.FileName, startInfo.Arguments);
                return 0;
            }

            Log.Warning("{HookType} hook '{Hook}' '{HookArguments}' completed with exit code {ExitCode}",
                type, startInfo.FileName, startInfo.Arguments, exitCode);
            return exitCode;
        }
    }
}
