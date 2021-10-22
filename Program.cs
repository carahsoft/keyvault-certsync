using Azure.Identity;
using CommandLine;
using keyvault_certsync.Flows;
using keyvault_certsync.Options;
using Serilog;
using System;
using System.Collections.Generic;

namespace keyvault_certsync
{
    class Program
    {
        static int Main(string[] args)
        {
            string log_format = "{Level:u3}] {Message:lj}{NewLine}{ExceptionMessage}";

            var log_config = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .Enrich.WithExceptionMessage()
                .WriteTo.Console(outputTemplate: log_format);

            Log.Logger = log_config.CreateLogger();

            int result = Parser.Default.ParseArguments<ListOptions, DownloadOptions, UploadOptions>(args).MapResult(
                (ListOptions opts) => new ListFlow(opts).Run(),
                (DownloadOptions opts) => new DownloadFlow(opts).Run(),
                (UploadOptions opts) => new UploadFlow(opts).Run(),
                errs => HandleParseError(errs));

            return result;
        }

        private static int HandleParseError(IEnumerable<Error> errs)
        {
            return -1;
        }
    }
}
