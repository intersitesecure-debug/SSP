// File: tests/SSP.Tests/Activation/ClockLockProbe.cs
//
// Standalone entry point of the SSP.Tests assembly, used only by
// ClockRollbackStateTests.FileLease_IsExclusiveAcrossProcesses.
//
// The code under test is the real cross-process lease in
// SSP.Server.Activation.SspLicenseStateFileLock, reached through the public
// ILicenseTimeStateLock seam of SspLicenseStateStore. The lease is reentrant
// per thread and its acquisition map is thread-local, so a second thread of
// the test process cannot stand in for a holder in another process: the probe
// therefore runs as a genuine child process.
//
// The parent starts the probe with `dotnet exec <this assembly>`. The
// assembly entry point begins executing immediately - there is no VSTest
// adapter discovery and no test enumeration to wait through - so the probe
// holds the lease a moment after launch instead of after a full child
// testhost boot. (The previous filtered `dotnet vstest` child was the reason
// the test could exceed its Fact timeout on a loaded machine.)
//
// The probe never reads or writes license state: it only acquires the lease
// file and speaks the pipe handshake.

using System.IO.Pipes;
using System.Text;
using SSP.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

internal static class ClockLockProbe
{
    /// <summary>First argument that selects the lock-probe mode.</summary>
    internal const string Command = "--clock-lock-probe";

    internal static int Main(string[] args)
    {
        if (args.Length != 3 || !string.Equals(args[0], Command, StringComparison.Ordinal))
        {
            Console.Error.WriteLine(
                $"Usage: dotnet exec {typeof(ClockLockProbe).Assembly.GetName().Name}.dll {Command} <pipeName> <statePath>");
            return 2;
        }

        try
        {
            Run(args[1], args[2]);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Clock-lock probe failed: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Acquires the time-state lease in this process, signals the parent and
    /// holds it until the parent releases the probe. The lease is disposed on
    /// the same thread it was acquired on (the ILicenseTimeStateLock contract).
    /// The release read is bounded so a dead parent cannot leave the probe
    /// holding the lease forever.
    /// </summary>
    private static void Run(string pipeName, string statePath)
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
        pipe.Connect(60_000);
        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        using var writer = new StreamWriter(pipe, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
        // Synchronous lease: acquire and dispose on the same thread, no await.
        using var lease = ((ILicenseTimeStateLock)new SspLicenseStateStore(statePath)).AcquireTimeStateLock();
        writer.WriteLine("locked");
        var release = reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(120)).GetAwaiter().GetResult();
        if (!string.Equals(release, "release", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Unexpected control message: {release ?? "<null>"}");
        }
    }
}
