using CommandLine;
using System.Text.Json.Serialization;

namespace keyvault_certsync.Options
{
    public class BaseOptions
    {
        [JsonIgnore]
        [Option('q', "quiet", HelpText = "Suppress output")]
        public bool Quiet { get; set; }

        [JsonIgnore]
        [Option("debug", HelpText = "Enable debug output")]
        public bool Debug { get; set; }

        [JsonIgnore]
        [Option("config", HelpText = "Override directory for config files")]
        public string ConfigDirectory { get; set; }
    }
}
