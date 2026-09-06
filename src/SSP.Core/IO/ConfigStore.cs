// File: src/SSP.Core/IO/ConfigStore.cs
//
// Helpers for loading and persisting the JSON files that live in a
// service directory:
//   - .cache.dat
//   - .index.dat
// Callers work with UTF-8 JSON; the protected service files are encrypted
// on disk by ProtectedFileStore.

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SSP.Core.Models;

namespace SSP.Core.IO;

/// <summary>
/// Centralized JSON serializer options used by every config file. The
/// options are immutable; reuse the static instance to avoid the per-call
/// compilation cost of the source generator.
/// </summary>
public static class JsonOptions
{
    public static readonly JsonSerializerOptions Default = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true
    };
}

/// <summary>
/// Atomic file writer: writes to a temp file in the same directory then
/// renames it into place. Survives a crash mid-write without leaving a
/// truncated file behind.
///
/// The commit phase (create the temp file, then <c>File.Replace</c> /
/// <c>File.Move</c> it over the target) retries a bounded number of times on
/// <see cref="IOException"/>. Every retried attempt rewrites the temp file
/// from scratch, so the operation stays atomic and idempotent. On Windows a
/// real-time scanner (antivirus, search indexer) can briefly hold either the
/// freshly written <c>.tmp</c> file or the target open without delete
/// sharing; that makes the rename fail with a transient sharing violation
/// even though the caller did nothing wrong. Deterministic failures (a
/// directory occupying the path, access denied, a full disk, an invalid
/// path) are never retried away: each attempt rethrows and the final attempt
/// surfaces the error to the caller, which is what the fail-closed callers
/// (for example the license state store's mandatory time checkpoints) rely
/// on.
/// </summary>
public static class AtomicFile
{
    /// <summary>
    /// Number of commit attempts. With the doubling delay below this bounds
    /// a transient collision to roughly 1.3 seconds before the final error
    /// propagates.
    /// </summary>
    private const int MaxCommitAttempts = 8;

    public static Task WriteTextAsync(string path, string content, CancellationToken ct = default)
        => WriteBytesAsync(path, Encoding.UTF8.GetBytes(content), ct);

    public static async Task WriteBytesAsync(string path, byte[] content, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        var retryDelay = TimeSpan.FromMilliseconds(10);
        for (var attempt = 1; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                await using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await fs.WriteAsync(content.AsMemory(0, content.Length), ct).ConfigureAwait(false);
                }

                Commit(tmp, path);
                return;
            }
            catch (IOException) when (attempt < MaxCommitAttempts)
            {
                // A transient sharing violation (see the class remarks), not
                // a data-loss failure: the previous attempt never committed
                // a partial file, so waiting briefly and rewriting is safe.
                await Task.Delay(retryDelay, ct).ConfigureAwait(false);
                retryDelay += retryDelay;
            }
        }
    }

    private static void Commit(string tmp, string path)
    {
        if (File.Exists(path))
            File.Replace(tmp, path, null);
        else
            File.Move(tmp, path);
    }

    public static Task<string> ReadTextAsync(string path, CancellationToken ct = default)
    {
        return File.ReadAllTextAsync(path, ct);
    }

    public static string ReadText(string path)
    {
        return File.ReadAllText(path);
    }
}


/// <summary>
/// Cross-process advisory lock for service-directory configuration updates.
/// Every process that mutates .cache.dat takes this lock so a running
/// gateway enrollment and an additional-client provisioning process cannot
/// overwrite each other's PendingOneTimeTokens changes.
/// </summary>
public static class ServiceConfigFileLock
{
    public static async Task<FileStream> AcquireAsync(string serviceDir, CancellationToken ct = default)
    {
        Directory.CreateDirectory(serviceDir);
        var lockPath = Path.Combine(serviceDir, ".cache.dat.lock");

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.Asynchronous);
            }
            catch (IOException)
            {
                await Task.Delay(50, ct).ConfigureAwait(false);
            }
        }
    }
}

/// <summary>
/// Load / save .cache.dat.
/// </summary>
public static class ServiceConfigStore
{
    public static async Task<ServiceConfig> LoadAsync(string path, CancellationToken ct = default)
    {
        var read = await ProtectedFileStore.ReadTextAsync(path, ct).ConfigureAwait(false);
        var cfg = JsonSerializer.Deserialize<ServiceConfig>(read.Text, JsonOptions.Default)
                  ?? throw new InvalidDataException($"Failed to deserialize {path}.");

        await ProtectedFileStore.MigratePlaintextAsync(path, read, ct).ConfigureAwait(false);

        cfg.PendingOneTimeTokens ??= new List<PendingOneTimeToken>();

        // Backward compatibility: old files have only ActiveOneTimeTokenHash.
        // Migrate it into PendingOneTimeTokens as a "Legacy" entry if needed,
        // so that both old and new server code can handle it.
        if (!string.IsNullOrEmpty(cfg.ActiveOneTimeTokenHash) && cfg.PendingOneTimeTokens.Count == 0)
        {
            cfg.PendingOneTimeTokens.Add(new PendingOneTimeToken
            {
                ClientName = "Legacy",
                OneTimeTokenHash = cfg.ActiveOneTimeTokenHash!,
                CreatedAtUtc = cfg.CreatedAtUtc,
                FailedAuthenticationCodeAttempts = cfg.ActiveOneTimeTokenFailedAuthenticationCodeAttempts,
                AuthenticationCodeRetryNotBeforeUtc = cfg.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc,
            });
        }

        return cfg;
    }

    public static Task SaveAsync(string path, ServiceConfig config, CancellationToken ct = default)
    {
        config.PendingOneTimeTokens ??= new List<PendingOneTimeToken>();
        var json = JsonSerializer.Serialize(config, JsonOptions.Default);
        return ProtectedFileStore.WriteTextAsync(path, json, ct);
    }
}

/// <summary>
/// Load / save .index.dat.
/// </summary>
public static class AuthorisedUsersStore
{
    public static async Task<AuthorisedUsersFile> LoadAsync(string path, CancellationToken ct = default)
    {
        if (!File.Exists(path))
            return new AuthorisedUsersFile();

        var read = await ProtectedFileStore.ReadTextAsync(path, ct).ConfigureAwait(false);
        var users = JsonSerializer.Deserialize<AuthorisedUsersFile>(read.Text, JsonOptions.Default)
                    ?? new AuthorisedUsersFile();

        await ProtectedFileStore.MigratePlaintextAsync(path, read, ct).ConfigureAwait(false);
        return users;
    }

    public static Task SaveAsync(string path, AuthorisedUsersFile file, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(file, JsonOptions.Default);
        return ProtectedFileStore.WriteTextAsync(path, json, ct);
    }
}
