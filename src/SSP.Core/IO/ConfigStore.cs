// File: src/SSP.Core/IO/ConfigStore.cs
//
// Helpers for loading and persisting the JSON files that live in a
// service directory:
//   - .cache.dat
//   - .index.dat
// Callers work with UTF-8 JSON; the protected service files are encrypted
// on disk by ProtectedFileStore.

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
/// </summary>
public static class AtomicFile
{
    public static async Task WriteTextAsync(string path, string content, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        await using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await using var sw = new StreamWriter(fs);
            await sw.WriteAsync(content.AsMemory(), ct).ConfigureAwait(false);
        }

        if (File.Exists(path))
            File.Replace(tmp, path, null);
        else
            File.Move(tmp, path);
    }

    public static async Task WriteBytesAsync(string path, byte[] content, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        await using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await fs.WriteAsync(content.AsMemory(0, content.Length), ct).ConfigureAwait(false);
        }

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
