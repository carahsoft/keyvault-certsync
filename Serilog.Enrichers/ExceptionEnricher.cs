using Serilog.Core;
using Serilog.Events;

namespace Serilog.Enrichers
{
    /// <summary>
    /// Enriches log events with a ExceptionMessage property
    /// </summary>
    public class ExceptionMessageEnricher : ILogEventEnricher
    {
        /// <summary>
        /// The property name added to enriched log events.
        /// </summary>
        public const string ExceptionMessagePropertyName = "ExceptionMessage";

        /// <summary>
        /// Enrich the log event.
        /// </summary>
        /// <param name="logEvent">The log event to enrich.</param>
        /// <param name="propertyFactory">Factory for creating new properties to add to the event.</param>
        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
        {
            if (logEvent.Exception == null)
                return;

            var message = new LogEventProperty(ExceptionMessagePropertyName, new ScalarValue($"{logEvent.Exception.Message}\n"));
            logEvent.AddPropertyIfAbsent(message);
        }
    }
}