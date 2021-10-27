using CommandLine;
using keyvault_certsync.Flows;
using keyvault_certsync.Options;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using System.Collections.Generic;

namespace keyvault_certsync
{
    class Program
    {
        static int Main(string[] args)
        {
            string log_format = "{Level:u3}] {Message:lj}{NewLine}{ExceptionMessage}";

            var levelSwitch = new LoggingLevelSwitch();
            levelSwitch.MinimumLevel = LogEventLevel.Verbose;

            var log_config = new LoggerConfiguration()
                .MinimumLevel.ControlledBy(levelSwitch)
                .Enrich.WithExceptionMessage()
                .WriteTo.Console(outputTemplate: log_format);

            Log.Logger = log_config.CreateLogger();

            int result = Parser.Default.ParseArguments<ListOptions, DownloadOptions, UploadOptions>(args).MapResult(
                (ListOptions opts) => new ListFlow(opts).Run(),
                (DownloadOptions opts) =>
                {
                    if (opts.Quiet)
                        levelSwitch.MinimumLevel = LogEventLevel.Warning;

                    return new DownloadFlow(opts).Run();
                },
                (UploadOptions opts) =>
                {
                    if (opts.Quiet)
                        levelSwitch.MinimumLevel = LogEventLevel.Warning;

                    return new UploadFlow(opts).Run();
                },
                errs => HandleParseError(errs));

            return result;
        }

        private static int HandleParseError(IEnumerable<Error> errs)
        {
            return -1;
        }
    }
}
