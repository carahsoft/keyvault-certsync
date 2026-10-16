using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace keyvault_certsync.Models
{
    /// <summary>
    /// Reads either a single JSON string or an array of strings; always writes an array.
    /// </summary>
    public class StringOrArrayConverter : JsonConverter<IEnumerable<string>>
    {
        public override IEnumerable<string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.Null:
                    return null;
                case JsonTokenType.String:
                    return new[] { reader.GetString() };
                case JsonTokenType.StartArray:
                    var list = new List<string>();
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        if (reader.TokenType != JsonTokenType.String)
                            throw new JsonException("Expected a string in array");
                        list.Add(reader.GetString());
                    }
                    return list.ToArray();
                default:
                    throw new JsonException("Expected a string or array of strings");
            }
        }

        public override void Write(Utf8JsonWriter writer, IEnumerable<string> value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();
            foreach (var item in value)
                writer.WriteStringValue(item);
            writer.WriteEndArray();
        }
    }
}
