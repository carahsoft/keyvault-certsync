using Serilog;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace keyvault_certsync.Models
{
    public class Config
    {
        public Dictionary<string, string> Environment { get; set; } = new Dictionary<string, string>();

        public void SetEnvironment()
        {
            foreach (KeyValuePair<string, string> env in Environment)
                System.Environment.SetEnvironmentVariable(env.Key, env.Value);
        }

        public bool GetEnvironment()
        {
            bool changed = false;
            foreach (DictionaryEntry env in System.Environment.GetEnvironmentVariables())
                if (env.Key.ToString().StartsWith("AZURE_", StringComparison.CurrentCultureIgnoreCase))
                {
                    if (!Environment.ContainsKey(env.Key.ToString()) || Environment[env.Key.ToString()] != env.Value.ToString())
                    {
                        Environment.Add(env.Key.ToString(), env.Value.ToString());
                        changed = true;
                    }    
                }

            return changed;
        }

        public static Config LoadConfig(string file)
        {
            if (!File.Exists(file))
                return null;

            try
            {
                var config = JsonSerializer.Deserialize<Config>(File.ReadAllText(file));

                Log.Debug("Loaded config from {File}", file);
                return config;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error loading config from {File}, using defaults", file);
                return null;
            }
        }

        public bool SaveConfig(string file)
        {
            try
            {
                File.WriteAllText(file, JsonSerializer.Serialize(this, new JsonSerializerOptions()
                {
                    WriteIndented = true
                }));

                Log.Debug("Saved config to {File}", file);
                return true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error saving config to {File}", file);
                return false;
            }
        }
    }
}
