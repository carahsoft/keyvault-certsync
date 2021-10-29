using CommandLine;

namespace keyvault_certsync.Options
{
    [Verb("sync", HelpText = "Sync certificates using automation config")]
    public class SyncOptions : BaseOptions
    {
        [Option('f', "force", HelpText = "Force even when identical certificate exists")]
        public bool Force { get; set; }
    }
}
