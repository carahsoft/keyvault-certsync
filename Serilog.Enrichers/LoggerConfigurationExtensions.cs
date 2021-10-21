using Serilog.Configuration;
using Serilog.Enrichers;
using System;

namespace Serilog
{
    public static class ThreadLoggerConfigurationExtensions
    {
        public static LoggerConfiguration WithExceptionMessage(
            this LoggerEnrichmentConfiguration enrichmentConfiguration)
        {
            if (enrichmentConfiguration == null) 
                throw new ArgumentNullException(nameof(enrichmentConfiguration));

            return enrichmentConfiguration.With<ExceptionMessageEnricher>();
        }
    }
}
