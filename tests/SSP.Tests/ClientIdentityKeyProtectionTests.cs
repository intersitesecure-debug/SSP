// File: tests/SSP.Tests/ClientIdentityKeyProtectionTests.cs
//
// Phase 3 (M-2) of the Security Correction roadmap: client identity
// private key protection.
//
// The client is a desktop application: the same interactive user both
// creates the client identity key pair and reads it back on every later
// start, and NO other identity (no Windows Service, no setup-mode
// elevation) ever reads the client connection files. The files must
// therefore be protected with DPAPI CurrentUser scope (the envelope
// records the scope; on the non-Windows test host the scope is the
// AES-GCM fallback's scope marker) so that:
//
//   * every other local account on the machine can read the file bytes
//     (C:\Program Files is world-readable) but CANNOT decrypt them, so
//     the client private key cannot be recovered and the enrolled
//     client identity cannot be impersonated;
//   * server-side service files KEEP the LocalMachine scope the
//     gateway Windows Service (LocalSystem) requires;
//   * pre-Phase-3 client files (legacy plaintext or LocalMachine
//     envelopes) stay readable by their owner and are upgraded in place
//     on first load, without re-enrollment;
//   * foreign/undecryptable key material fails closed: the load throws,
//     the files are left byte-identical, and no replacement identity is
//     silently generated (spec §19).

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSP.Activation;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Client.Runtime;
using SSP.Server.Activation;

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


namespace SSP.Tests;

public class ClientIdentityKeyProtectionTests
{
    // ────────────────────────────────────────────────────────────────
    // 1. New client connection files use the CurrentUser scope
    // ────────────────────────────────────────────────────────────────

    [Fact(Timeout = 30000)]
    public async Task ClientConnectionFiles_AreProtectedWithCurrentUserScope()
    {
        var dir = CreateTempDir();
        try
        {
            var cfg = TestConfig("Phase3CurrentUserApp");
            var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.False(runtime.IsEnrolled);

            var cachePath = Path.Combine(dir, ".cache.dat");
            var indexPath = Path.Combine(dir, ".index.dat");
            var runtimePath = Path.Combine(dir, ".runtime.dat");

            // The security property: the envelope records CurrentUser
            // scope for the CLIENT identity files (DPAPI CurrentUser on
            // Windows, scope marker on the non-Windows fallback).
            AssertCurrentUserScope(cachePath, "client private key");
            AssertCurrentUserScope(indexPath, "client public key");
            AssertCurrentUserScope(runtimePath, "connection profile");

            // Still encrypted at rest, no plaintext markers, no sidecars.
            AssertEncryptedAtRest(cachePath, "-----BEGIN PRIVATE KEY-----",
                runtime.ClientPublicKeyFingerprint);
            AssertEncryptedAtRest(indexPath, "-----BEGIN PUBLIC KEY-----");
            AssertNoSidecarFilesInConnectionDirectory(dir);

            // Logical data round-trips and the decrypted key is usable.
            using var loadedPrivate = RsaCrypto.ImportPrivateKeyPem(
                await PemStore.LoadPrivateKeyAsync(
                    cachePath, ClientInstallPaths.ClientConnectionProtectionScope));
            Assert.Equal(runtime.ClientPublicKeyFingerprint,
                RsaCrypto.ComputePublicKeyFingerprint(loadedPrivate));

            // Restart: same identity, scope unchanged.
            var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.Equal(runtime.ClientPublicKeyFingerprint,
                runtime2.ClientPublicKeyFingerprint);
            Assert.Equal(runtime.ClientPublicKeyPem, runtime2.ClientPublicKeyPem);
            AssertCurrentUserScope(cachePath, "client private key after restart");
            AssertCurrentUserScope(indexPath, "client public key after restart");
            AssertCurrentUserScope(runtimePath, "connection profile after restart");
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 2. Server-side service files keep the LocalMachine scope
    // ────────────────────────────────────────────────────────────────

    [Fact(Timeout = 30000)]
    public async Task ServerSideServiceFiles_RemainProtectedWithLocalMachineScope()
    {
        var dir = CreateTempDir();
        try
        {
            var configPath = Path.Combine(dir, ".cache.dat");
            var keyPath = Path.Combine(dir, ".sysdata.bin");
            var pubPath = Path.Combine(dir, ".runtime.dat");
            var usersPath = Path.Combine(dir, ".index.dat");
            var statePath = Path.Combine(dir, ".license-state.dat");

            using var rsa = RsaCrypto.GenerateKeyPair();
            var privatePem = RsaCrypto.ExportPrivateKeyPem(rsa);
            var publicPem = RsaCrypto.ExportPublicKeyPem(rsa);

            // All server-side stores keep their pre-Phase-3 defaults:
            // LocalMachine scope, so the gateway Windows Service
            // (LocalSystem) can still read what setup wrote.
            await ServiceConfigStore.SaveAsync(configPath, new ServiceConfig
            {
                ApplicationName = "Phase3ServerScopeApp",
                GatewayPublicIpAddress = "198.51.100.77",
                GatewayPort = 4443,
                LocalApplicationPort = 3389,
                ClientTunnelPort = 13389,
                CreatedAtUtc = "2026-09-05T00:00:00.0000000Z",
                WindowsServiceName = "SSP Phase3ServerScopeApp 4443",
            });
            await PemStore.SavePrivateKeyAsync(keyPath, privatePem);
            await PemStore.SavePublicKeyAsync(pubPath, publicPem);
            await AuthorisedUsersStore.SaveAsync(usersPath, new AuthorisedUsersFile());

            var stateStore = new SspLicenseStateStore(statePath);
            stateStore.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = 1,
            });

            AssertLocalMachineScope(configPath, "server service config");
            AssertLocalMachineScope(keyPath, "server private key");
            AssertLocalMachineScope(pubPath, "server public key");
            AssertLocalMachineScope(usersPath, "authorized users");
            AssertLocalMachineScope(statePath, "license anti-rollback state");

            // Round-trip still intact (server contract unchanged).
            var loadedConfig = await ServiceConfigStore.LoadAsync(configPath);
            Assert.Equal("Phase3ServerScopeApp", loadedConfig.ApplicationName);
            Assert.Equal(privatePem, await PemStore.LoadPrivateKeyAsync(keyPath));

            // Reads with the LOCALMACHINE scope must not rewrite the
            // files (no unnecessary re-wrap on the server path).
            var configBytesBefore = File.ReadAllBytes(configPath);
            await ServiceConfigStore.LoadAsync(configPath);
            Assert.Equal(configBytesBefore, File.ReadAllBytes(configPath));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 3. Pre-Phase-3 client files (LocalMachine envelope) are readable
    //    by their owner and re-wrapped to CurrentUser on first load
    // ────────────────────────────────────────────────────────────────

    [Fact(Timeout = 30000)]
    public async Task LegacyLocalMachineClientFiles_AreRewrappedToCurrentUserScope_OnFirstLoad()
    {
        var dir = CreateTempDir();
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            var privPem = RsaCrypto.ExportPrivateKeyPem(seedRsa);
            var pubPem = RsaCrypto.ExportPublicKeyPem(seedRsa);
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(seedRsa);
            var cfg = TestConfig("Phase3RewrapApp");

            // Seed a pre-Phase-3 layout: the SAME files, but protected
            // with the old LocalMachine scope (the envelope any
            // installation created before this fix holds).
            await ProtectedFileStore.WriteTextAsync(
                Path.Combine(dir, ".cache.dat"), privPem, DataProtectionScope.LocalMachine);
            await ProtectedFileStore.WriteTextAsync(
                Path.Combine(dir, ".index.dat"), pubPem, DataProtectionScope.LocalMachine);

            var legacyState = ClientConnectionState.FromConfig(cfg);
            legacyState.ClientPublicKeyFingerprint = fingerprint;
            legacyState.IsEnrolled = true;
            legacyState.IsAuthorized = true;
            legacyState.EnrolledAtUtc = "2026-08-01T00:00:00.0000000Z";
            await ProtectedFileStore.WriteTextAsync(
                Path.Combine(dir, ".runtime.dat"),
                JsonSerializer.Serialize(legacyState, JsonOptions.Default),
                DataProtectionScope.LocalMachine);

            AssertLocalMachineScope(Path.Combine(dir, ".cache.dat"), "seeded legacy cache");
            AssertLocalMachineScope(Path.Combine(dir, ".index.dat"), "seeded legacy index");
            AssertLocalMachineScope(Path.Combine(dir, ".runtime.dat"), "seeded legacy profile");

            // First load after the upgrade: the owner still recovers the
            // EXACT same identity and enrollment state (no re-enrollment)
            var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime.IsEnrolled);
            Assert.Equal(fingerprint, runtime.ClientPublicKeyFingerprint);

            var migratedState = ClientConnectionState.TryLoad(dir);
            Assert.NotNull(migratedState);
            Assert.True(migratedState.IsEnrolled);
            Assert.True(migratedState.IsAuthorized);
            Assert.Equal(fingerprint, migratedState.ClientPublicKeyFingerprint);
            Assert.Equal("2026-08-01T00:00:00.0000000Z", migratedState.EnrolledAtUtc);

            // ... and every client file on disk now carries the
            // CurrentUser envelope (the pre-Phase-3 LocalMachine
            // protection of this installation is gone).
            AssertCurrentUserScope(Path.Combine(dir, ".cache.dat"), "rewrapped private key");
            AssertCurrentUserScope(Path.Combine(dir, ".index.dat"), "rewrapped public key");
            AssertCurrentUserScope(Path.Combine(dir, ".runtime.dat"), "rewrapped profile");

            // The decrypted logical data is intact after the re-wrap.
            Assert.Equal(pubPem, await PemStore.LoadPublicKeyAsync(
                Path.Combine(dir, ".index.dat"),
                ClientInstallPaths.ClientConnectionProtectionScope));

            // Restart over the upgraded directory keeps identity and
            // scope stable.
            var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime2.IsEnrolled);
            Assert.Equal(fingerprint, runtime2.ClientPublicKeyFingerprint);
            AssertCurrentUserScope(Path.Combine(dir, ".cache.dat"), "private key after restart");
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 4. Legacy plaintext client keys migrate DIRECTLY into the
    //    CurrentUser envelope (never via a LocalMachine intermediate)
    // ────────────────────────────────────────────────────────────────

    [Fact(Timeout = 30000)]
    public async Task LegacyPlaintextClientKeys_MigrateDirectlyToCurrentUserScope()
    {
        var dir = CreateTempDir();
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            var privPem = RsaCrypto.ExportPrivateKeyPem(seedRsa);
            var pubPem = RsaCrypto.ExportPublicKeyPem(seedRsa);
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(seedRsa);
            var cfg = TestConfig("Phase3PlaintextApp");

            await File.WriteAllTextAsync(Path.Combine(dir, ".cache.dat"), privPem);
            await File.WriteAllTextAsync(Path.Combine(dir, ".index.dat"), pubPem);

            var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime.IsEnrolled); // legacy keys-present == enrolled
            Assert.Equal(fingerprint, runtime.ClientPublicKeyFingerprint);

            // The migration lands straight in the CurrentUser envelope.
            AssertCurrentUserScope(Path.Combine(dir, ".cache.dat"), "migrated private key");
            AssertCurrentUserScope(Path.Combine(dir, ".index.dat"), "migrated public key");

            var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime2.IsEnrolled);
            Assert.Equal(fingerprint, runtime2.ClientPublicKeyFingerprint);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 5. Foreign key material (another user's / another machine's
    //    envelope) fails closed: the load throws, the files are left
    //    byte-identical and no replacement identity is generated
    // ────────────────────────────────────────────────────────────────

    [Fact(Timeout = 30000)]
    public async Task ForeignKeyMaterial_FailsClosed_WithoutRegeneratingIdentity()
    {
        var dir = CreateTempDir();
        try
        {
            var cfg = TestConfig("Phase3ForeignApp");

            // A .cache.dat envelope that CANNOT be decrypted with this
            // machine/user's key material: same SSP-EAR1 layout, but the
            // AES-GCM payload was produced with a random foreign key.
            // (On Windows production the equivalent case is an envelope
            // from another user/machine; the read path is the same.)
            var foreignCachePath = Path.Combine(dir, ".cache.dat");
            var foreignBytes = BuildForeignKeyEnvelope(
                "-----BEGIN PRIVATE KEY-----\nFOREIGN\n-----END PRIVATE KEY-----\n");
            await File.WriteAllBytesAsync(foreignCachePath, foreignBytes);

            // A valid companion public-key file so the runtime reaches
            // the private-key load (both files present -> load path).
            using var companionRsa = RsaCrypto.GenerateKeyPair();
            await PemStore.SavePublicKeyAsync(
                Path.Combine(dir, ".index.dat"),
                RsaCrypto.ExportPublicKeyPem(companionRsa),
                ClientInstallPaths.ClientConnectionProtectionScope);

            var cacheBytesBefore = File.ReadAllBytes(foreignCachePath);
            var indexPath = Path.Combine(dir, ".index.dat");
            var indexBytesBefore = File.ReadAllBytes(indexPath);

            // Fail closed: the load throws (the caller surfaces "local
            // identity credential unavailable"), and ...
            await Assert.ThrowsAsync<CryptographicException>(
                () => ClientRuntime.LoadOrCreateAsync(dir, cfg));

            // ... the surviving credential files are untouched (no
            // silent regeneration over them, spec §19).
            Assert.Equal(cacheBytesBefore, File.ReadAllBytes(foreignCachePath));
            Assert.Equal(indexBytesBefore, File.ReadAllBytes(indexPath));
            Assert.DoesNotContain(
                Directory.EnumerateFiles(dir),
                p => Path.GetFileName(p) is ".tmp" or ".lock");
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 6. The envelope scope is authoritative for decryption; a read
    //    requesting a different scope re-wraps, a same-scope read does
    //    not rewrite the file
    // ────────────────────────────────────────────────────────────────

    [Fact(Timeout = 30000)]
    public async Task CrossScopeRead_UsesEnvelopeRecordedScope_AndRewrapsToRequestedScope()
    {
        var dir = CreateTempDir();
        try
        {
            var cachePath = Path.Combine(dir, ".cache.dat");
            using var rsa = RsaCrypto.GenerateKeyPair();
            var privatePem = RsaCrypto.ExportPrivateKeyPem(rsa);

            // Written with the legacy server-side scope ...
            await PemStore.SavePrivateKeyAsync(
                cachePath, privatePem, DataProtectionScope.LocalMachine);
            AssertLocalMachineScope(cachePath, "locally-scoped seed");

            // ... must still decrypt (the envelope records its own
            // scope), and the read with the client scope re-wraps the
            // file into the CurrentUser envelope in place.
            var loaded = await PemStore.LoadPrivateKeyAsync(
                cachePath, DataProtectionScope.CurrentUser);
            Assert.Equal(privatePem, loaded);
            AssertCurrentUserScope(cachePath, "after cross-scope read");

            // The re-wrapped file round-trips under the client scope.
            Assert.Equal(privatePem, await PemStore.LoadPrivateKeyAsync(
                cachePath, DataProtectionScope.CurrentUser));

            // A same-scope read must NOT rewrite the file (no needless
            // re-encryption churn on every client start).
            var bytesBefore = File.ReadAllBytes(cachePath);
            await PemStore.LoadPrivateKeyAsync(
                cachePath, DataProtectionScope.CurrentUser);
            Assert.Equal(bytesBefore, File.ReadAllBytes(cachePath));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    private static void AssertCurrentUserScope(string path, string what)
        => AssertEnvelopeScope(DataProtectionScope.CurrentUser, path, what);

    private static void AssertLocalMachineScope(string path, string what)
        => AssertEnvelopeScope(DataProtectionScope.LocalMachine, path, what);

    /// <summary>
    /// Asserts the scope RECORDED IN THE ENVELOPE of <paramref name="path"/>.
    ///
    /// The pinned xUnit in this repository (xunit 2.5.3, see BUILD.md §2 and
    /// its "do not bump these versions on an offline machine" rule) has no
    /// <c>Assert.Equal</c> overload that takes a user message: the third
    /// argument is a COMPARER (<c>IEqualityComparer&lt;T&gt;</c> or
    /// <c>Func&lt;T, T, bool&gt;</c>), which is exactly why
    /// <c>Assert.Equal(expected, actual, $"...")</c> failed to bind with
    /// CS1503 (cannot convert from 'string' to
    /// 'Func&lt;DataProtectionScope?, DataProtectionScope?, bool&gt;').
    /// Passing the message through <c>Assert.True</c> instead keeps the
    /// diagnostic value: a mismatch still names the file, what it holds, the
    /// required scope and the scope the envelope actually carries.
    /// </summary>
    private static void AssertEnvelopeScope(DataProtectionScope expected, string path, string what)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes),
            $"{what} at {path} is not in the encrypted-at-rest envelope.");

        var actual = ProtectedFileStore.GetEnvelopeScope(bytes);
        var recorded = actual is { } scope ? scope.ToString() : "no scope";
        Assert.True(actual == expected,
            $"{what} at {path} must be protected with {expected} scope (envelope records {recorded}).");
    }

    private static void AssertEncryptedAtRest(string path, params string[] plaintextMarkers)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes),
            $"{path} is not in the encrypted-at-rest envelope.");

        var directText = Encoding.UTF8.GetString(bytes);
        foreach (var marker in plaintextMarkers.Where(m => !string.IsNullOrEmpty(m)))
            Assert.DoesNotContain(marker, directText);
    }

    private static void AssertNoSidecarFilesInConnectionDirectory(string connectionDir)
    {
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".cache.dat", ".index.dat", ".runtime.dat",
        };

        var unexpected = Directory.EnumerateFiles(connectionDir)
            .Select(Path.GetFileName)
            .Where(name => !expected.Contains(name!))
            .ToList();
        Assert.Empty(unexpected);
    }

    /// <summary>
    /// Builds a syntactically valid SSP-EAR1 envelope (magic + the
    /// non-Windows AES-GCM algorithm byte + nonce + tag + ciphertext)
    /// whose payload was encrypted with a RANDOM key that is not this
    /// host's fallback key. Decrypting it must fail with
    /// CryptographicException - the cross-platform stand-in for "an
    /// envelope produced by another user / another machine".
    /// </summary>
    private static byte[] BuildForeignKeyEnvelope(string plaintext)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];

        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }
        CryptographicOperations.ZeroMemory(key);

        var payload = new byte[12 + 16 + ciphertext.Length];
        nonce.CopyTo(payload, 0);
        tag.CopyTo(payload, 12);
        ciphertext.CopyTo(payload, 28);

        // Envelope layout of ProtectedFileStore: magic | algorithm byte |
        // payload. "SSP-EAR1"u8 is a ReadOnlySpan<byte>, whose CopyTo takes
        // the destination span only (no start offset), so the magic is
        // written into the leading slice - the same shape as
        // ProtectedFileStore.BuildEnvelope, which copies a byte[].
        var magic = "SSP-EAR1"u8;
        var envelope = new byte[magic.Length + 1 + payload.Length];
        magic.CopyTo(envelope.AsSpan(0, magic.Length));
        envelope[magic.Length] = 2; // non-Windows AES-GCM algorithm byte
        payload.CopyTo(envelope, magic.Length + 1);
        return envelope;
    }

    private static ClientConfig TestConfig(string appName)
    {
        using var serverRsa = RsaCrypto.GenerateKeyPair();
        return new ClientConfig
        {
            ApplicationName        = appName,
            ServerPublicKeyPem     = RsaCrypto.ExportPublicKeyPem(serverRsa),
            GatewayPublicIpAddress = "203.0.113.77",
            GatewayPort            = 4443,
            LocalApplicationPort   = 3389,
            ClientTunnelPort       = 13389,
            ClientName             = "ClientMarker",
        };
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-client-key-protection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
#pragma warning restore CA1416
