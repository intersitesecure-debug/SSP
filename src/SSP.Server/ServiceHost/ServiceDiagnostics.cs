// File: src/SSP.Server/ServiceHost/ServiceDiagnostics.cs
//
// Best-effort diagnostic logging for the Windows Service start path.
//
// A failure that happens before ServiceBase.Run connects to the SCM is
// otherwise completely invisible: ServiceBase.AutoLog only starts writing
// to the Application event log after the dispatcher has connected, and the
// process has no console under LocalSystem. Every such failure therefore
// surfaces to the operator as an opaque ERROR 1053 ("service did not respond
// to the start or control request in a timely fashion") with no hint of the
// underlying cause.
//
// Failures that happen inside OnStart are not much better: ServiceBase
// reports ERROR 1064 (ERROR_EXCEPTION_IN_SERVICE) and writes the exception
// to the Application log under the *service name* as the event source, but
// SspWindowsService surfaces listener failures through Task completion, so
// what reaches that log entry is the AggregateException wrapper whose
// Message is the useless "One or more errors occurred."
//
// This helper records the real exception - type, message, full stack trace
// and every inner exception - to the Application event log and to a local
// log file, so the cause is always discoverable. All writes are best-effort:
// a logging failure must never mask or replace the original exception.

using System.Text;

namespace SSP.Server.ServiceHost;

internal static class ServiceDiagnostics
{
    private const string EventSource = "SSP.Server";
    private const string LogFileName = "ssp-service-startup.log";

    /// <summary>Classic event-log message payload limit; keep a margin.</summary>
    private const int MaxMessageLength = 30_000;

    /// <summary>
    /// Record a fatal startup failure. Never throws.
    /// </summary>
    public static void WriteStartupFailure(string serviceDir, Exception ex)
        => Write("failed to start", serviceDir, null, ex);

    /// <summary>
    /// Record a gateway failure that happened after the service was already
    /// reported RUNNING. The accept loop exiting without a cancellation means
    /// the listener socket is gone while the SCM still shows the service as
    /// healthy, so this must never be silent either. Never throws.
    /// </summary>
    public static void WriteGatewayFailure(string serviceDir, int gatewayPort, Exception ex)
        => Write("gateway failed while running", serviceDir, gatewayPort, ex);

    private static void Write(string phase, string serviceDir, int? gatewayPort, Exception ex)
    {
        var message = BuildMessage(phase, serviceDir, gatewayPort, ex);
        TryWriteEventLog(message);
        TryWriteLogFile(serviceDir, message);
    }

    /// <summary>
    /// Full diagnostic payload: what failed, where, under which account and
    /// working directory, and the exception in its entirety.
    /// AggregateException is flattened so a cause wrapped by Task.Wait is
    /// visible directly rather than behind "One or more errors occurred."
    /// </summary>
    internal static string BuildMessage(string phase, string serviceDir, int? gatewayPort, Exception ex)
    {
        var builder = new StringBuilder();

        builder.Append("SSP service ").Append(phase).Append('.');
        builder.Append(" ServiceDirectory='").Append(serviceDir).Append('\'');
        if (gatewayPort is int port)
            builder.Append(" GatewayPort=").Append(port);
        builder.Append(" Process='").Append(SafeValue(static () => Environment.ProcessPath)).Append('\'');
        builder.Append(" ProcessId=").Append(Environment.ProcessId);
        builder.Append(" WorkingDirectory='").Append(SafeValue(static () => Directory.GetCurrentDirectory())).Append('\'');
        builder.Append(" User='").Append(SafeValue(static () => $"{Environment.UserDomainName}\\{Environment.UserName}")).Append('\'');
        builder.Append(" OS='").Append(SafeValue(static () => Environment.OSVersion.ToString())).Append('\'');
        builder.Append(Environment.NewLine);

        foreach (var single in Flatten(ex))
        {
            builder.Append("--- ").Append(single.GetType().FullName).Append(" ---");
            builder.Append(Environment.NewLine);
            // Exception.ToString() is type + message + stack trace.
            builder.Append(single);
            builder.Append(Environment.NewLine);
        }

        var message = builder.ToString();
        return message.Length <= MaxMessageLength
            ? message
            : message[..MaxMessageLength] + Environment.NewLine + "[truncated]";
    }

    /// <summary>
    /// Walk the exception graph breadth-first, expanding
    /// <see cref="AggregateException"/> into its inner exceptions so the
    /// actual cause is always present in the diagnostic.
    /// </summary>
    private static List<Exception> Flatten(Exception ex)
    {
        var result = new List<Exception>();
        var seen = new HashSet<Exception>(ReferenceEqualityComparer.Instance);
        var pending = new Queue<Exception>();
        pending.Enqueue(ex);

        while (pending.Count > 0)
        {
            var current = pending.Dequeue();
            if (!seen.Add(current))
                continue;

            result.Add(current);

            if (current is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions)
                    pending.Enqueue(inner);
            }
            else if (current.InnerException is not null)
            {
                pending.Enqueue(current.InnerException);
            }
        }

        return result;
    }

    private static string SafeValue(Func<string?> read)
    {
        try
        {
            return read() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Resolve a log file location that the service account can actually
    /// write to. Prefer the service directory (LocalSystem already reads
    /// .cache.dat there), then the executable directory, then the
    /// system temp directory.
    /// </summary>
    internal static string ResolveLogFilePath(string serviceDir)
    {
        if (!string.IsNullOrWhiteSpace(serviceDir))
        {
            try
            {
                if (Directory.Exists(serviceDir))
                    return Path.Combine(serviceDir, LogFileName);
            }
            catch
            {
                // fall through
            }
        }

        try
        {
            var exeDir = Path.GetDirectoryName(Environment.ProcessPath);
            if (!string.IsNullOrWhiteSpace(exeDir) && Directory.Exists(exeDir))
                return Path.Combine(exeDir, LogFileName);
        }
        catch
        {
            // fall through
        }

        return Path.Combine(Path.GetTempPath(), LogFileName);
    }

    private static void TryWriteEventLog(string message)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            if (!System.Diagnostics.EventLog.SourceExists(EventSource))
                System.Diagnostics.EventLog.CreateEventSource(EventSource, "Application");
            System.Diagnostics.EventLog.WriteEntry(EventSource, message,
                System.Diagnostics.EventLogEntryType.Error);
        }
        catch
        {
            // Best effort only; never mask the original failure.
        }
    }

    private static void TryWriteLogFile(string serviceDir, string message)
    {
        try
        {
            File.AppendAllText(
                ResolveLogFilePath(serviceDir),
                DateTime.UtcNow.ToString("o") + " " + message + Environment.NewLine);
        }
        catch
        {
            // Best effort only.
        }
    }
}
