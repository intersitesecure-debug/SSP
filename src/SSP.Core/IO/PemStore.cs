// File: src/SSP.Core/IO/PemStore.cs
//
// Load / save RSA PEM keys for both server and client. The service
// key filenames (.sysdata.bin and .runtime.dat) are encrypted at rest;
// other PEM files keep their existing format. Private-key files are also
// written with restrictive permissions on Unix (chmod 600).
//
// Protection scope (Phase 3 / M-2 of the Security Correction roadmap):
//   * SERVER-side key files default to DPAPI LocalMachine scope: setup
//     mode writes them elevated and the gateway Windows Service
//     (LocalSystem) must read them back at runtime.
//   * CLIENT-side connection key files (connections/{ConnectionId}/) are
//     written and read with DataProtectionScope.CurrentUser
//     (ClientInstallPaths.ClientConnectionProtectionScope): the client is
//     a desktop app, the same interactive user both creates the identity
//     and reads it back, and no other account may recover the private
//     key even though C:\Program Files files are readable by every local
//     user. See ProtectedFileStore for the scope semantics.

using System.Security.Cryptography;

// CA1416 suppression (build-clean, platform-safe)
// ------------------------------------------------
// System.Security.Cryptography.DataProtectionScope is annotated
// [SupportedOSPlatform("windows")], so ANY reference to the type - even a
// pure enum member used as a scope MARKER in cross-platform code - is
// reported by the platform-compatibility analyzer as CA1416. The actual
// Windows-only APIs (ProtectedData.Protect / Unprotect) are never invoked
// off Windows: every call site is guarded by OperatingSystem.IsWindows()
// (see ProtectedFileStore.Protect / UnprotectWithWindowsDpapi, which throws
// PlatformNotSupportedException otherwise) and non-Windows hosts take the
// AES-GCM fallback. The enum reference itself carries no runtime dependency,
// so the diagnostic is a false positive here and is suppressed deliberately
// and locally rather than globally in the project file.
#pragma warning disable CA1416


namespace SSP.Core.IO;

public static class PemStore
{
    public static async Task SavePrivateKeyAsync(
        string path, string pem,
        DataProtectionScope scope = DataProtectionScope.LocalMachine,
        CancellationToken ct = default)
    {
        if (ProtectedFileStore.IsProtectedPath(path))
            await ProtectedFileStore.WriteTextAsync(path, pem, scope, ct).ConfigureAwait(false);
        else
            await AtomicFile.WriteTextAsync(path, pem, ct).ConfigureAwait(false);

        TryRestrictFilePermissions(path);
    }

    public static async Task SavePublicKeyAsync(
        string path, string pem,
        DataProtectionScope scope = DataProtectionScope.LocalMachine,
        CancellationToken ct = default)
    {
        if (ProtectedFileStore.IsProtectedPath(path))
            await ProtectedFileStore.WriteTextAsync(path, pem, scope, ct).ConfigureAwait(false);
        else
            await AtomicFile.WriteTextAsync(path, pem, ct).ConfigureAwait(false);
    }

    public static async Task<string> LoadPrivateKeyAsync(
        string path,
        DataProtectionScope scope = DataProtectionScope.LocalMachine,
        CancellationToken ct = default)
    {
        if (!ProtectedFileStore.IsProtectedPath(path))
            return await AtomicFile.ReadTextAsync(path, ct).ConfigureAwait(false);

        var read = await ProtectedFileStore.ReadTextAsync(path, scope, ct).ConfigureAwait(false);
        await ProtectedFileStore.MigratePlaintextAsync(path, read, scope, ct).ConfigureAwait(false);
        if (read.WasPlaintextProtectedFile)
            TryRestrictFilePermissions(path);
        return read.Text;
    }

    public static async Task<string> LoadPublicKeyAsync(
        string path,
        DataProtectionScope scope = DataProtectionScope.LocalMachine,
        CancellationToken ct = default)
    {
        if (!ProtectedFileStore.IsProtectedPath(path))
            return await AtomicFile.ReadTextAsync(path, ct).ConfigureAwait(false);

        var read = await ProtectedFileStore.ReadTextAsync(path, scope, ct).ConfigureAwait(false);
        await ProtectedFileStore.MigratePlaintextAsync(path, read, scope, ct).ConfigureAwait(false);
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
#pragma warning restore CA1416
