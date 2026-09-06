using System.Diagnostics;

namespace SSP.Server.Activation;

/// <summary>
/// Phase 6: synchronous, reentrant, cross-process lock for the existing license
/// state. A checkpoint holds it across read/merge/primary/witness writes. Load and
/// Save also take it, so a time-only update cannot erase concurrent activation or
/// renewal state. Like ServiceConfigFileLock, this uses a local exclusive file;
/// unlike that async API, its bounded wait uses elapsed time, never wall-clock UTC.
///
/// The acquisition bound (default thirty seconds) is a security decision, not a
/// performance hint: an enforcement that cannot obtain the lease denies instead of
/// hanging, so a stuck holder can never block every admission forever. The bound
/// is deliberately much larger than any legitimate hold (one read/sample/merge/
/// save/readback transaction, including its bounded atomic-write retries), so
/// bursts of legitimate concurrent checkpoints serialize through the lease and
/// succeed instead of failing closed. Only after the bound expires does a waiter
/// conclude that the state is unavailable.
/// </summary>
internal static class SspLicenseStateFileLock
{
    /// <summary>Default acquisition bound, in elapsed time (never wall-clock UTC).</summary>
    internal static readonly TimeSpan DefaultAcquisitionTimeout = TimeSpan.FromSeconds(30);

    private static readonly ThreadLocal<Dictionary<string, HeldLock>> Held = new(() =>
        new Dictionary<string, HeldLock>(OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal));

    internal static IDisposable Acquire(string statePath, TimeSpan? timeout = null)
    {
        var path = Path.GetFullPath(statePath) + ".lock";
        var locks = Held.Value!;
        if (locks.TryGetValue(path, out var held))
        {
            held.Depth++;
            return new Lease(path, held, locks);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var wait = timeout ?? DefaultAcquisitionTimeout;
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            try
            {
                var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite,
                    FileShare.None, bufferSize: 1, FileOptions.None);
                held = new HeldLock(stream);
                locks.Add(path, held);
                return new Lease(path, held, locks);
            }
            catch (IOException) when (elapsed.Elapsed < wait)
            {
                // A short poll interval keeps handoff latency low while a
                // legitimate holder finishes; an attempt is only a file open.
                Thread.Sleep(10);
            }
        }
    }

    /// <summary>
    /// Unlike File.Exists, this does not turn access errors or a directory in the
    /// file slot into "fresh installation". Only actual absence permits bootstrap.
    /// </summary>
    internal static bool FileExists(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.Directory) != 0)
                throw new InvalidDataException("A directory occupies a required license state file path.");
            return true;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private sealed class HeldLock
    {
        internal HeldLock(FileStream stream) => Stream = stream;
        internal FileStream Stream { get; }
        internal int Depth { get; set; } = 1;
    }

    private sealed class Lease : IDisposable
    {
        private readonly string _path;
        private readonly HeldLock _held;
        private readonly Dictionary<string, HeldLock> _locks;
        private bool _disposed;

        internal Lease(string path, HeldLock held, Dictionary<string, HeldLock> locks)
        {
            _path = path;
            _held = held;
            _locks = locks;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (--_held.Depth != 0) return;
            _locks.Remove(_path);
            _held.Stream.Dispose();
            // Never delete the lock file: another process may already hold a
            // handle to it. A stale empty file itself does not hold a lock.
        }
    }
}
