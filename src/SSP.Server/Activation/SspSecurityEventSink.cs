// File: src/SSP.Server/Activation/SspSecurityEventSink.cs
//
// SSP-native production security event sink. The activation library ships
// only Null/InMemory sinks; SSP supplies the real one. It writes structured,
// secret-free events to an operator-supplied log file (the composition root
// passes a directory resolved with the same conventions as
// ServiceDiagnostics) and to the Windows Application event log on Windows.
// Implementation never throws - a logging failure must never take down
// licensing validation or the service.

using System.Text;
using SSP.Activation;

namespace SSP.Server.Activation;

/// <summary>
/// Persistent licensing security event sink. Emits one line per event to a
/// local log file inside the supplied directory (when provided), optionally
/// mirrors the same line to stdout for foreground/operator runs, and writes a
/// best-effort entry to the Windows Application event log.
/// </summary>
public sealed class SspSecurityEventSink : ISecurityEventSink
{
    /// <summary>Log file name used inside the configured log directory.</summary>
    public const string LogFileName = "ssp-activation-security.log";

    private const string EventSource = "SSP.Server";
    private const int MaxMessageLength = 30_000;

    private readonly string? _logDirectory;
    private readonly bool _writeToConsole;
    private readonly object _gate = new();

    /// <summary>
    /// Creates the sink.
    /// </summary>
    /// <param name="logDirectory">
    /// Directory that receives <see cref="LogFileName"/>, or null to disable
    /// file logging. The directory is created on first write.
    /// </param>
    /// <param name="writeToConsole">
    /// When true the formatted event is also written to stdout. Defaults to
    /// true so foreground setup/operator runs surface activation events;
    /// Windows services have no console and simply discard this output.
    /// </param>
    public SspSecurityEventSink(string? logDirectory = null, bool writeToConsole = true)
    {
        _logDirectory = string.IsNullOrWhiteSpace(logDirectory) ? null : logDirectory;
        _writeToConsole = writeToConsole;
    }

    /// <summary>The directory the sink writes <see cref="LogFileName"/> into, or null.</summary>
    public string? LogDirectory => _logDirectory;

    /// <inheritdoc />
    public void Report(LicenseSecurityEvent securityEvent)
    {
        if (securityEvent is null)
        {
            return;
        }

        try
        {
            var line = BuildMessage(securityEvent);
            lock (_gate)
            {
                if (_writeToConsole)
                {
                    Console.Out.WriteLine(line);
                }

                TryWriteFile(line);
                TryWriteWindowsEventLog(line);
            }
        }
        catch
        {
            // The sink contract is to never throw. A logging failure must not
            // fail licensing validation or the protected service.
        }
    }

    /// <summary>
    /// Formats a licensing security event as a single safe log line. Events
    /// carry only identifiers, reason codes, state and detail text - never
    /// keys, signatures or credentials (the reference library guarantees this
    /// before the event reaches the sink).
    /// </summary>
    internal static string BuildMessage(LicenseSecurityEvent securityEvent)
    {
        var builder = new StringBuilder();
        builder.Append("ssp-activation event=").Append(securityEvent.EventType);
        builder.Append(" state=").Append(securityEvent.State);
        builder.Append(" at=").Append(securityEvent.OccurredAtUtc.ToString("o"));

        if (securityEvent.LicenseId is Guid licenseId)
        {
            builder.Append(" licenseId=").Append(licenseId.ToString("D"));
        }

        if (!string.IsNullOrWhiteSpace(securityEvent.ReasonCode))
        {
            builder.Append(" reason=").Append(Sanitize(securityEvent.ReasonCode));
        }

        if (!string.IsNullOrWhiteSpace(securityEvent.Detail))
        {
            builder.Append(" detail=").Append(Sanitize(securityEvent.Detail));
        }

        var line = builder.ToString();
        return line.Length <= MaxMessageLength
            ? line
            : line[..MaxMessageLength] + " [truncated]";
    }

    private static string Sanitize(string value)
    {
        return value
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ');
    }

    private void TryWriteFile(string line)
    {
        if (_logDirectory is null)
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(_logDirectory);
            var path = Path.Combine(_logDirectory, LogFileName);
            File.AppendAllText(
                path,
                DateTime.UtcNow.ToString("o") + " " + line + Environment.NewLine);
        }
        catch
        {
            // Best effort only.
        }
    }

    private static void TryWriteWindowsEventLog(string line)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            if (!System.Diagnostics.EventLog.SourceExists(EventSource))
            {
                System.Diagnostics.EventLog.CreateEventSource(EventSource, "Application");
            }

            System.Diagnostics.EventLog.WriteEntry(EventSource, line, System.Diagnostics.EventLogEntryType.Information);
        }
        catch
        {
            // Best effort only; never throw from a security event sink.
        }
    }
}
