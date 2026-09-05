// File: src/SSP.Core/IO/ProtectedFileStore.cs
//
// Encryption-at-rest for SSP state files:
//   - .cache.dat
//   - .sysdata.bin
//   - .runtime.dat
//   - .index.dat
//   - .license-state.dat   (activation anti-rollback state; see SspLicenseStateStore)
//
// Production Windows builds use DPAPI (ProtectedData). The protection SCOPE
// is a per-caller decision recorded inside the envelope:
//
//   * LocalMachine scope (envelope algorithm bytes 1 / 2) - SERVER-side
//     service files. Setup mode runs elevated and the gateway Windows
//     Service (LocalSystem) must be able to read what setup wrote, so the
//     files must be decryptable across user contexts on the same machine.
//
//   * CurrentUser scope (envelope algorithm bytes 3 / 4) - CLIENT-side
//     connection files (connections/{ConnectionId}/). The client is a
//     desktop application: the same interactive user both generates the
//     client identity key pair and later reads it back, and no other
//     identity ever needs to read those files. CurrentUser scope therefore
//     binds decryption to the user's own DPAPI master key: ANY other local
//     account (administrator or not) can read the file bytes but cannot
//     decrypt them. LocalMachine scope would have let any logged-in user on
//     the machine recover the client private key (MS-CryptProtectData:
//     "any user on the computer ... can use CryptUnprotectData to decrypt
//     the data"), which is exactly the local impersonation path Phase 3
//     (M-2) of the Security Correction roadmap closes.
//
// The decryption scope is ALWAYS the one recorded in the envelope
// (authoritative), never the caller's requested scope; the requested scope
// only decides which scope a newly written (or migrated / re-wrapped)
// file gets. Existing LocalMachine envelopes written by earlier builds are
// still decrypted, and client files found in a LocalMachine envelope are
// re-wrapped into CurrentUser scope on first read (best effort), so
// pre-existing client installations are upgraded in place without
// re-enrollment.
//
// The encryption key is managed by Windows and is never written to the
// service directory, the protected files, or the repository.

using System.Security.Cryptography;
using System.Text;

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

/// <summary>
/// Low-level storage wrapper for the SSP files that must be encrypted at
/// rest. Callers still work with the exact same logical UTF-8 text they used
/// before; only the bytes persisted on disk are protected.
/// </summary>
public static class ProtectedFileStore
{
    private static readonly byte[] Magic = "SSP-EAR1"u8.ToArray();

    // Envelope algorithm bytes. Bytes 1/3 select the Windows DPAPI envelope
    // (machine vs current-user scope); bytes 2/4 select the non-Windows
    // AES-GCM fallback (test/development hosts) with the corresponding
    // scope marker, so the recorded scope is deterministic on every
    // platform.
    private const byte DpapiLocalMachineAlgorithm = 1;
    private const byte NonWindowsAesGcmAlgorithm = 2;
    private const byte DpapiCurrentUserAlgorithm = 3;
    private const byte NonWindowsAesGcmCurrentUserAlgorithm = 4;

    private const int AesKeySizeBytes = 32;
    private const int AesNonceSizeBytes = 12;
    private const int AesTagSizeBytes = 16;

    // DPAPI optional entropy is a purpose string, not a secret key. Keeping
    // it in code prevents accidental cross-use with unrelated ProtectedData.
    // The SAME entropy is used for both scopes: the scope recorded in the
    // envelope is the differentiator, and reusing the string keeps the
    // re-wrap migration of legacy LocalMachine client envelopes
    // deterministic (no entropy guessing on the read path).
    private static readonly byte[] DpapiOptionalEntropy =
        Encoding.UTF8.GetBytes("SSP encrypted-at-rest service storage v1");

    private static readonly string[] ProtectedFileNames =
    {
        ".cache.dat",
        ".sysdata.bin",
        ".runtime.dat",
        ".index.dat",
        ".license-state.dat",
    };

    private static readonly object NonWindowsKeyLock = new();
    private static byte[]? _cachedNonWindowsKey;

    public readonly record struct ReadTextResult(
        string Text,
        bool WasEncrypted,
        bool WasPlaintextProtectedFile,
        DataProtectionScope? EnvelopeScope = null);

    /// <summary>
    /// True only for the SSP state files covered by the encrypted-at-rest
    /// requirement. Other SSP files keep their existing storage format.
    /// </summary>
    public static bool IsProtectedPath(string path)
    {
        var fileName = Path.GetFileName(path);
        return ProtectedFileNames.Any(name =>
            string.Equals(name, fileName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Test/diagnostic helper: identifies files already written in the SSP
    /// encrypted-at-rest envelope without decrypting them.
    /// </summary>
    public static bool HasEncryptedEnvelope(byte[] bytes)
    {
        return bytes.Length > Magic.Length && bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic);
    }

    /// <summary>
    /// Test/diagnostic helper: returns the protection scope recorded in an
    /// existing envelope (LocalMachine for bytes 1/2, CurrentUser for
    /// bytes 3/4), or null when the bytes are not an SSP envelope.
    /// Throws <see cref="CryptographicException"/> for an unknown
    /// algorithm byte so tests can fail loudly instead of guessing.
    /// </summary>
    public static DataProtectionScope? GetEnvelopeScope(byte[] bytes)
    {
        if (!HasEncryptedEnvelope(bytes))
            return null;

        return bytes[Magic.Length] switch
        {
            DpapiLocalMachineAlgorithm => DataProtectionScope.LocalMachine,
            NonWindowsAesGcmAlgorithm => DataProtectionScope.LocalMachine,
            DpapiCurrentUserAlgorithm => DataProtectionScope.CurrentUser,
            NonWindowsAesGcmCurrentUserAlgorithm => DataProtectionScope.CurrentUser,
            _ => throw new CryptographicException(
                $"Unsupported SSP encrypted-at-rest file format version/algorithm: {bytes[Magic.Length]}.")
        };
    }

    /// <summary>
    /// Diagnostics only: Windows uses DPAPI and therefore has no SSP key file.
    /// Non-Windows test/development hosts keep their fallback key outside the
    /// repository and outside service directories.
    /// </summary>
    public static string? ExternalKeyPathForDiagnostics =>
        OperatingSystem.IsWindows() ? null : ResolveNonWindowsKeyPath();

    /// <summary>
    /// Reads a protected file. The decryption uses the scope RECORDED IN THE
    /// ENVELOVE (not <paramref name="scope"/>); <paramref name="scope"/> is
    /// the scope that <see cref="MigratePlaintextAsync"/> migrates to when
    /// the file is plaintext or written with a different scope. The
    /// LocalMachine default keeps every pre-Phase-3 server-side call site
    /// byte- and behavior-identical.
    /// </summary>
    public static Task<ReadTextResult> ReadTextAsync(string path, CancellationToken ct = default)
        => ReadTextAsync(path, DataProtectionScope.LocalMachine, ct);

    public static async Task<ReadTextResult> ReadTextAsync(
        string path, DataProtectionScope scope, CancellationToken ct = default)
    {
        var bytes = await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
        var protectedPath = IsProtectedPath(path);
        if (protectedPath && TryUnprotect(bytes, out var plaintext))
        {
            return new ReadTextResult(
                DecodeUtf8Text(plaintext),
                WasEncrypted: true,
                WasPlaintextProtectedFile: false,
                EnvelopeScope: GetEnvelopeScope(bytes));
        }

        return new ReadTextResult(
            DecodeUtf8Text(bytes),
            WasEncrypted: false,
            WasPlaintextProtectedFile: protectedPath);
    }

    /// <summary>
    /// Writes a protected file in the given scope (LocalMachine by default -
    /// the server-side contract; client-side callers pass CurrentUser).
    /// </summary>
    public static Task WriteTextAsync(string path, string content, CancellationToken ct = default)
        => WriteTextAsync(path, content, DataProtectionScope.LocalMachine, ct);

    public static Task WriteTextAsync(
        string path, string content, DataProtectionScope scope, CancellationToken ct = default)
    {
        if (!IsProtectedPath(path))
            return AtomicFile.WriteTextAsync(path, content, ct);

        var plaintext = Encoding.UTF8.GetBytes(content);
        var protectedBytes = Protect(plaintext, scope);
        CryptographicOperations.ZeroMemory(plaintext);
        return AtomicFile.WriteBytesAsync(path, protectedBytes, ct);
    }

    /// <summary>
    /// Rewrites an existing plaintext protected file into the encrypted
    /// envelope after the higher-level store has successfully validated it
    /// (legacy behavior; a failed migration still propagates, exactly as
    /// before Phase 3).
    /// </summary>
    public static Task MigratePlaintextAsync(string path, ReadTextResult read, CancellationToken ct = default)
        => MigratePlaintextAsync(path, read, DataProtectionScope.LocalMachine, ct);

    /// <summary>
    /// Two side-effect upgrades, both applied only AFTER a successful read:
    ///
    /// 1. Legacy plaintext protected files are rewritten into the encrypted
    ///    envelope in <paramref name="scope"/> (a failed write propagates,
    ///    preserving the pre-Phase-3 contract).
    ///
    /// 2. An already-encrypted file whose envelope records a DIFFERENT scope
    ///    than requested (e.g. a pre-Phase-3 client identity envelope still
    ///    protected LocalMachine) is re-wrapped into <paramref name="scope"/>.
    ///    This re-wrap is best effort: the logical content was already read
    ///    successfully, so a write failure must never mask the read and
    ///    break an otherwise working client - the next successful write will
    ///    land in the requested scope anyway.
    /// </summary>
    public static Task MigratePlaintextAsync(
        string path, ReadTextResult read, DataProtectionScope scope, CancellationToken ct = default)
    {
        if (read.WasPlaintextProtectedFile)
            return WriteTextAsync(path, read.Text, scope, ct);

        if (read.WasEncrypted && read.EnvelopeScope is { } envelopeScope && envelopeScope != scope)
        {
            try
            {
                return WriteTextAsync(path, read.Text, scope, ct);
            }
            catch
            {
                // Best effort only (see remarks); the validated content is
                // already available to the caller in memory.
            }
        }

        return Task.CompletedTask;
    }

    private static string DecodeUtf8Text(byte[] bytes)
    {
        var text = Encoding.UTF8.GetString(bytes);
        return text.Length > 0 && text[0] == '\uFEFF' ? text[1..] : text;
    }

    private static byte[] Protect(byte[] plaintext, DataProtectionScope scope)
    {
        if (OperatingSystem.IsWindows())
        {
            var algorithm = scope == DataProtectionScope.CurrentUser
                ? DpapiCurrentUserAlgorithm
                : DpapiLocalMachineAlgorithm;
            var protectedPayload = ProtectedData.Protect(
                plaintext,
                DpapiOptionalEntropy,
                scope);

            return BuildEnvelope(algorithm, protectedPayload);
        }

        var nonWindowsAlgorithm = scope == DataProtectionScope.CurrentUser
            ? NonWindowsAesGcmCurrentUserAlgorithm
            : NonWindowsAesGcmAlgorithm;
        var payload = AesGcmEncrypt(plaintext);
        return BuildEnvelope(nonWindowsAlgorithm, payload);
    }

    private static bool TryUnprotect(byte[] bytes, out byte[] plaintext)
    {
        plaintext = Array.Empty<byte>();

        if (!HasEncryptedEnvelope(bytes))
            return false;

        var algorithm = bytes[Magic.Length];
        var payload = bytes.AsSpan(Magic.Length + 1);

        // The scope recorded in the envelope is authoritative for
        // decryption; a caller requesting a different scope can never
        // change WHICH key material Windows applies to the payload.
        var scope = algorithm switch
        {
            DpapiLocalMachineAlgorithm or NonWindowsAesGcmAlgorithm => DataProtectionScope.LocalMachine,
            DpapiCurrentUserAlgorithm or NonWindowsAesGcmCurrentUserAlgorithm => DataProtectionScope.CurrentUser,
            _ => throw new CryptographicException(
                $"Unsupported SSP encrypted-at-rest file format version/algorithm: {algorithm}.")
        };

        plaintext = algorithm switch
        {
            DpapiLocalMachineAlgorithm or DpapiCurrentUserAlgorithm =>
                UnprotectWithWindowsDpapi(payload, scope),
            NonWindowsAesGcmAlgorithm or NonWindowsAesGcmCurrentUserAlgorithm =>
                UnprotectWithNonWindowsAesGcm(payload),
            _ => throw new CryptographicException(
                $"Unsupported SSP encrypted-at-rest file format version/algorithm: {algorithm}.")
        };

        return true;
    }

    private static byte[] BuildEnvelope(byte algorithm, byte[] protectedPayload)
    {
        var envelope = new byte[Magic.Length + 1 + protectedPayload.Length];
        Magic.CopyTo(envelope, 0);
        envelope[Magic.Length] = algorithm;
        protectedPayload.CopyTo(envelope, Magic.Length + 1);
        return envelope;
    }

    private static byte[] UnprotectWithWindowsDpapi(ReadOnlySpan<byte> payload, DataProtectionScope scope)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("DPAPI-protected SSP files can only be decrypted on Windows.");

        return ProtectedData.Unprotect(
            payload.ToArray(),
            DpapiOptionalEntropy,
            scope);
    }

    /// <summary>
    /// Portable fallback for non-Windows test/development hosts. Windows
    /// production never uses this path; it exists so the cross-platform test
    /// suite can exercise encrypted-at-rest semantics without DPAPI. The
    /// generated key is outside the repository and outside every service
    /// directory, protected by user-only filesystem permissions where the
    /// platform supports them. Both scope markers (bytes 2 and 4) use the
    /// same fallback key: on these hosts the scope is a recorded marker for
    /// deterministic tests, not a separate key hierarchy.
    /// </summary>
    private static byte[] AesGcmEncrypt(byte[] plaintext)
    {
        var key = GetOrCreateNonWindowsKey();
        var nonce = RandomNumberGenerator.GetBytes(AesNonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesTagSizeBytes];

        using (var aes = new AesGcm(key, AesTagSizeBytes))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var payload = new byte[AesNonceSizeBytes + AesTagSizeBytes + ciphertext.Length];
        nonce.CopyTo(payload, 0);
        tag.CopyTo(payload, AesNonceSizeBytes);
        ciphertext.CopyTo(payload, AesNonceSizeBytes + AesTagSizeBytes);
        return payload;
    }

    private static byte[] UnprotectWithNonWindowsAesGcm(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < AesNonceSizeBytes + AesTagSizeBytes)
            throw new CryptographicException("SSP encrypted-at-rest payload is truncated.");

        var key = GetOrCreateNonWindowsKey();
        var nonce = payload[..AesNonceSizeBytes];
        // The tag occupies AesTagSizeBytes bytes starting right after the
        // nonce (payload layout: nonce | tag | ciphertext). The length
        // argument of Span.Slice is a LENGTH, not an end offset.
        var tag = payload.Slice(AesNonceSizeBytes, AesTagSizeBytes);
        var ciphertext = payload[(AesNonceSizeBytes + AesTagSizeBytes)..];
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, AesTagSizeBytes);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    private static byte[] GetOrCreateNonWindowsKey()
    {
        lock (NonWindowsKeyLock)
        {
            if (_cachedNonWindowsKey != null)
                return _cachedNonWindowsKey;

            var keyPath = ResolveNonWindowsKeyPath();
            var keyDir = Path.GetDirectoryName(keyPath)!;
            Directory.CreateDirectory(keyDir);
            TryRestrictDirectoryPermissions(keyDir);

            if (File.Exists(keyPath))
            {
                TryRestrictFilePermissions(keyPath);
                var existing = File.ReadAllBytes(keyPath);
                if (existing.Length != AesKeySizeBytes)
                    throw new CryptographicException($"Invalid SSP encrypted-at-rest key material at {keyPath}.");

                _cachedNonWindowsKey = existing;
                return _cachedNonWindowsKey;
            }

            var generated = RandomNumberGenerator.GetBytes(AesKeySizeBytes);
            try
            {
                using var fs = new FileStream(keyPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                fs.Write(generated, 0, generated.Length);
                TryRestrictFilePermissions(keyPath);
                _cachedNonWindowsKey = generated;
                return _cachedNonWindowsKey;
            }
            catch (IOException) when (File.Exists(keyPath))
            {
                CryptographicOperations.ZeroMemory(generated);
                TryRestrictFilePermissions(keyPath);
                var existing = File.ReadAllBytes(keyPath);
                if (existing.Length != AesKeySizeBytes)
                    throw new CryptographicException($"Invalid SSP encrypted-at-rest key material at {keyPath}.");

                _cachedNonWindowsKey = existing;
                return _cachedNonWindowsKey;
            }
        }
    }

    private static string ResolveNonWindowsKeyPath()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root))
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            root = string.IsNullOrWhiteSpace(home)
                ? Path.Combine(Path.GetTempPath(), "ssp")
                : Path.Combine(home, ".local", "share");
        }

        return Path.Combine(root, "SSP", "protected-storage", "encrypted-at-rest.key");
    }

    private static void TryRestrictDirectoryPermissions(string path)
    {
        if (OperatingSystem.IsWindows())
            return;

        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
        catch { /* best effort */ }
    }

    private static void TryRestrictFilePermissions(string path)
    {
        if (OperatingSystem.IsWindows())
            return;

        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        catch { /* best effort */ }
    }
}
#pragma warning restore CA1416
