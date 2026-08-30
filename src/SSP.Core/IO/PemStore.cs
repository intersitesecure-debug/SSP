// File: src/SSP.Core/IO/PemStore.cs
//
// Load / save RSA PEM keys for both server and client. The service
// key filenames (.sysdata.bin and .runtime.dat) are encrypted at rest;
// other PEM files keep their existing format. Private-key files are also
// written with restrictive permissions on Unix (chmod 600).

namespace SSP.Core.IO;

public static class PemStore
{
    public static async Task SavePrivateKeyAsync(string path, string pem, CancellationToken ct = default)
    {
        if (ProtectedFileStore.IsProtectedPath(path))
            await ProtectedFileStore.WriteTextAsync(path, pem, ct).ConfigureAwait(false);
        else
            await AtomicFile.WriteTextAsync(path, pem, ct).ConfigureAwait(false);

        TryRestrictFilePermissions(path);
    }

    public static async Task SavePublicKeyAsync(string path, string pem, CancellationToken ct = default)
    {
        if (ProtectedFileStore.IsProtectedPath(path))
            await ProtectedFileStore.WriteTextAsync(path, pem, ct).ConfigureAwait(false);
        else
            await AtomicFile.WriteTextAsync(path, pem, ct).ConfigureAwait(false);
    }

    public static async Task<string> LoadPrivateKeyAsync(string path, CancellationToken ct = default)
    {
        if (!ProtectedFileStore.IsProtectedPath(path))
            return await AtomicFile.ReadTextAsync(path, ct).ConfigureAwait(false);

        var read = await ProtectedFileStore.ReadTextAsync(path, ct).ConfigureAwait(false);
        await ProtectedFileStore.MigratePlaintextAsync(path, read, ct).ConfigureAwait(false);
        if (read.WasPlaintextProtectedFile)
            TryRestrictFilePermissions(path);
        return read.Text;
    }

    public static async Task<string> LoadPublicKeyAsync(string path, CancellationToken ct = default)
    {
        if (!ProtectedFileStore.IsProtectedPath(path))
            return await AtomicFile.ReadTextAsync(path, ct).ConfigureAwait(false);

        var read = await ProtectedFileStore.ReadTextAsync(path, ct).ConfigureAwait(false);
        await ProtectedFileStore.MigratePlaintextAsync(path, read, ct).ConfigureAwait(false);
        return read.Text;
    }

    /// <summary>
    /// On Unix, set chmod 600 on the private key file. On Windows this
    /// is a no-op (the directory ACL governs access). Failures are
    /// swallowed because the file already exists and is usable.
    /// </summary>
    private static void TryRestrictFilePermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { /* best effort */ }
        }
    }
}
