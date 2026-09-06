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
// The parent starts the probe by launching this assembly's apphost (the Exe
// produced because OutputType=Exe), falling back to `dotnet exec -- <dll>`.
// It must never launch testhost via DOTNET_HOST_PATH: testhost waits for a
// VSTest runner that never connects, which is what used to push the test
// past its Fact timeout. The assembly entry point begins executing
// immediately - there is no VSTest adapter discovery and no test enumeration
// to wait through.
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

    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    internal static int Main(string[] args)
    {
        var filtered = args.Where(argument => argument != "--").ToArray();
        if (filtered.Length != 3 || !string.Equals(filtered[0], Command, StringComparison.Ordinal))
        {
            Console.Error.WriteLine(
                $"Usage: {typeof(ClockLockProbe).Assembly.GetName().Name} {Command} <pipeName> <statePath>");
            return 2;
        }

        try
        {
            Run(filtered[1], filtered[2]);
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
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        pipe.Connect(60_000);
        using var reader = new StreamReader(pipe, Utf8NoBom, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
        using var writer = new StreamWriter(pipe, Utf8NoBom, bufferSize: 1024, leaveOpen: true) { AutoFlush = true };
        // Synchronous lease: acquire and dispose on the same thread, no await.
        using var lease = ((ILicenseTimeStateLock)new SspLicenseStateStore(statePath)).AcquireTimeStateLock();
        writer.WriteLine("locked");
        writer.Flush();
        using var releaseTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var release = reader.ReadLineAsync(releaseTimeout.Token).AsTask().GetAwaiter().GetResult();
        if (!string.Equals(release, "release", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Unexpected control message: {release ?? "<null>"}");
        }
    }
}
