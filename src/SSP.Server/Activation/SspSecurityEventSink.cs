// File: src/SSP.Server/Activation/SspSecurityEventSink.cs
//
// SSP-native production security event sink. The activation library ships
// only Null/InMemory sinks; SSP supplies the real one. It writes structured,
// secret-free events to an operator-supplied log file (the composition root
// passes a directory resolved with the same conventions as
// ServiceDiagnostics) and to the Windows Application event log on Windows.
// Implementation never throws - a logging failure must never take down
// licensing validation or the service.

using System.Runtime.Versioning;
using System.Text;
using SSP.Activation;

namespace SSP.Server.Activation;

/// <summary>
/// Persistent licensing security event sink. Emits one line per event to a
/// local log file inside the supplied directory (when provided), optionally
/// mirrors the same line to stdout for foreground/operator runs, and writes a
/// best-effort entry to the Windows Application event log under the stable
/// taxonomy in <see cref="LicensingEventLogTaxonomy"/>.
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
                TryWriteWindowsEventLog(securityEvent, line);
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

    private static void TryWriteWindowsEventLog(LicenseSecurityEvent securityEvent, string line)
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

            System.Diagnostics.EventLog.WriteEntry(
                EventSource,
                line,
                LicensingEventLogTaxonomy.EntryTypeFor(securityEvent.EventType),
                LicensingEventLogTaxonomy.EventIdFor(securityEvent.EventType));
        }
        catch
        {
            // Best effort only; never throw from a security event sink.
        }
    }
}

/// <summary>
/// Windows Application event-log taxonomy for SSP licensing security events.
///
/// P5 hardening (event-log taxonomy review): every
/// <see cref="LicenseSecurityEventType"/> maps to a STABLE event id and an
/// operator-meaningful entry type, so licensing denials can be filtered and
/// alerted on in the event log instead of all arriving as plain Information
/// entries with no id (the pre-review behaviour).
///
/// The mapping is part of the operational contract:
///   * ids are never renumbered and severity is never raised or lowered for an
///     existing event type - operators may bind alerting to these ids;
///   * the library appends enum members only. The taxonomy tests pin the full
///     vocabulary and require an explicit severity for each defined type;
///     the fallback below is defensive for undefined numeric enum values.
///
/// Event ids: <see cref="EventIdBase"/> + the enum value, i.e.
/// LicenseLoaded = 4601 ... TimeIntegrityUnavailable = 4617. The base sits
/// outside the system-defined range so SSP licensing events can never collide
/// with SCM / ServiceBase / .NET runtime entries. The source name is
/// "SSP.Server", the same Application-log source ServiceDiagnostics writes
/// startup failures under, so one source name covers the whole server.
///
/// Severity classes:
///   Information - normal lifecycle transitions: license loaded, validated,
///     lockdown cleared, a newer artifact superseding an older one.
///   Warning     - every operator-actionable denial state: validation failure,
///     invalid signature, expiry, installation binding failure, revocation,
///     lockdown activation, state/time integrity failure and protected-operation denial.
///   Error       - deliberately never used. The sink contract is best-effort
///     and a licensing denial is an operational state, not a crash; Error-level
///     service failures (including SspActivationException at startup) are
///     surfaced separately by ServiceDiagnostics with its own contract.
///
/// The file/console line format is a second, equally stable taxonomy
/// ("ssp-activation event=... state=... reason=...", see
/// <see cref="SspSecurityEventSink.BuildMessage"/>); this mapping governs only
/// the Windows event-log presentation of the same events.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class LicensingEventLogTaxonomy
{
    /// <summary>Base of the SSP licensing event-id range in the Windows Application log.</summary>
    public const int EventIdBase = 4600;

    /// <summary>
    /// Stable, documented event id for a licensing security event type.
    /// Never renumber an existing mapping.
    /// </summary>
    public static int EventIdFor(LicenseSecurityEventType eventType) => EventIdBase + (int)eventType;

    /// <summary>
    /// Operator-meaningful Windows event-log entry type for a licensing
    /// security event type. The taxonomy tests require an explicit reviewed
    /// severity for every member of <see cref="LicenseSecurityEventType"/>;
    /// unknown numeric values default to Warning.
    /// </summary>
    public static System.Diagnostics.EventLogEntryType EntryTypeFor(LicenseSecurityEventType eventType) => eventType switch
    {
        LicenseSecurityEventType.LicenseLoaded => System.Diagnostics.EventLogEntryType.Information,
        LicenseSecurityEventType.LicenseValidated => System.Diagnostics.EventLogEntryType.Information,
        LicenseSecurityEventType.LicenseValidationFailed => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.InvalidSignature => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.LicenseExpired => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.LicenseBindingFailed => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.LicenseRevoked => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.LicenseLockdownActivated => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.LicenseLockdownCleared => System.Diagnostics.EventLogEntryType.Information,
        LicenseSecurityEventType.LicenseSuperseded => System.Diagnostics.EventLogEntryType.Information,
        LicenseSecurityEventType.ProtectedOperationDenied => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.ActivationRequired => System.Diagnostics.EventLogEntryType.Information,
        LicenseSecurityEventType.LicenseActivated => System.Diagnostics.EventLogEntryType.Information,
        LicenseSecurityEventType.LicenseStateRollbackDetected => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.LicenseStateDeletionRecovered => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.ClockRollbackDetected => System.Diagnostics.EventLogEntryType.Warning,
        LicenseSecurityEventType.TimeIntegrityUnavailable => System.Diagnostics.EventLogEntryType.Warning,
        _ => System.Diagnostics.EventLogEntryType.Warning,
    };
}
