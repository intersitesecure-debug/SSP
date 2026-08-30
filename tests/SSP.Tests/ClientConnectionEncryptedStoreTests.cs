// File: tests/SSP.Tests/ClientConnectionEncryptedStoreTests.cs
//
// Focused tests for encrypted-at-rest storage of the per-connection
// client files (connections/{ConnectionId}/):
//   - .cache.dat   (client private key PEM)
//   - .index.dat   (client public key PEM)
//   - .runtime.dat (per-connection enrollment / authorization profile)
//
// The files must use the SAME ProtectedFileStore mechanism as the
// server-side service files: encrypted envelope on disk, transparent
// decryption on read, and migration of legacy plaintext files that
// replaces the plaintext in place.

using System.Text;
using System.Text.Json;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Client.Runtime;
using SSP.Tests.Helpers;

namespace SSP.Tests;

public class ClientConnectionEncryptedStoreTests
{
    /// <summary>
    /// A brand-new connection directory must hold all three files in
    /// the encrypted-at-rest envelope, the logical data must round-trip
    /// (keys importable, profile readable) and a restart (second
    /// LoadOrCreateAsync) must recover the exact same identity and
    /// state with the files still encrypted.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task NewConnection_ThreeFilesEncryptedAtRest_RoundTripOnRestart()
    {
        var dir = CreateTempDir();
        try
        {
            var cfg = TestConfig("EncryptedNewApp");
            var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.False(runtime.IsEnrolled);

            var cachePath = Path.Combine(dir, ".cache.dat");
            var indexPath = Path.Combine(dir, ".index.dat");
            var runtimePath = Path.Combine(dir, ".runtime.dat");

            Assert.True(File.Exists(cachePath));
            Assert.True(File.Exists(indexPath));
            Assert.True(File.Exists(runtimePath));

            AssertEncryptedAtRest(cachePath,
                "-----BEGIN PRIVATE KEY-----",
                runtime.ClientPublicKeyFingerprint);
            AssertEncryptedAtRest(indexPath,
                "-----BEGIN PUBLIC KEY-----");
            AssertEncryptedAtRest(runtimePath,
                cfg.GatewayPublicIpAddress,
                ConnectionIdentity.ConnectionId(cfg));
            AssertNoSidecarFilesInConnectionDirectory(dir);

            // Logical data still fully usable after the transparent
            // decrypt: same key pair, same profile.
            using var loadedPrivate = RsaCrypto.ImportPrivateKeyPem(
                await PemStore.LoadPrivateKeyAsync(cachePath));
            Assert.Equal(runtime.ClientPublicKeyFingerprint,
                RsaCrypto.ComputePublicKeyFingerprint(loadedPrivate));

            var state = ClientConnectionState.TryLoad(dir);
            Assert.NotNull(state);
            Assert.Equal(ConnectionIdentity.ConnectionId(cfg), state.ConnectionId);
            Assert.False(state.IsEnrolled);
            Assert.False(state.IsAuthorized);

            // Restart: second process over the same directory recovers
            // the SAME identity (no re-generation) and the files are
            // still protected.
            var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.False(runtime2.IsEnrolled);
            Assert.Equal(runtime.ClientPublicKeyFingerprint,
                runtime2.ClientPublicKeyFingerprint);
            Assert.Equal(runtime.ClientPublicKeyPem, runtime2.ClientPublicKeyPem);

            AssertEncryptedAtRest(cachePath,
                "-----BEGIN PRIVATE KEY-----",
                runtime.ClientPublicKeyFingerprint);
            AssertEncryptedAtRest(indexPath, "-----BEGIN PUBLIC KEY-----");
            AssertEncryptedAtRest(runtimePath,
                cfg.GatewayPublicIpAddress,
                ConnectionIdentity.ConnectionId(cfg));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>
    /// Legacy installation with plaintext .cache.dat / .index.dat /
    /// .runtime.dat (pre-encryption layout): the first load must
    /// migrate all three files into the encrypted envelope in place
    /// (plaintext deleted from disk), keep the same identity, keep the
    /// enrollment state, and a subsequent restart must recover it
    /// unchanged.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task LegacyPlaintextConnectionFiles_MigratedOnLoad_AndRestartRecoversSameIdentityAndState()
    {
        var dir = CreateTempDir();
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            var privPem = RsaCrypto.ExportPrivateKeyPem(seedRsa);
            var pubPem = RsaCrypto.ExportPublicKeyPem(seedRsa);
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(seedRsa);
            var cfg = TestConfig("LegacyMigrateApp");

            // Seed the legacy plaintext layout.
            await File.WriteAllTextAsync(Path.Combine(dir, ".cache.dat"), privPem);
            await File.WriteAllTextAsync(Path.Combine(dir, ".index.dat"), pubPem);

            var legacyState = ClientConnectionState.FromConfig(cfg);
            legacyState.ClientPublicKeyFingerprint = fingerprint;
            legacyState.IsEnrolled = true;
            legacyState.IsAuthorized = true;
            legacyState.EnrolledAtUtc = "2026-08-01T00:00:00.0000000Z";
            await File.WriteAllTextAsync(
                Path.Combine(dir, ".runtime.dat"),
                JsonSerializer.Serialize(legacyState, JsonOptions.Default));

            AssertPlaintextOnDisk(Path.Combine(dir, ".cache.dat"), "-----BEGIN PRIVATE KEY-----");
            AssertPlaintextOnDisk(Path.Combine(dir, ".index.dat"), "-----BEGIN PUBLIC KEY-----");
            AssertPlaintextOnDisk(Path.Combine(dir, ".runtime.dat"), "LegacyMigrateApp");

            // First load: identity + state must be recovered AND the
            // plaintext must be replaced by the encrypted envelope.
            var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime.IsEnrolled);
            Assert.Equal(fingerprint, runtime.ClientPublicKeyFingerprint);

            var cachePath = Path.Combine(dir, ".cache.dat");
            var indexPath = Path.Combine(dir, ".index.dat");
            var runtimePath = Path.Combine(dir, ".runtime.dat");
            AssertEncryptedAtRest(cachePath,
                "-----BEGIN PRIVATE KEY-----", fingerprint);
            AssertEncryptedAtRest(indexPath, "-----BEGIN PUBLIC KEY-----", fingerprint);
            AssertEncryptedAtRest(runtimePath, "LegacyMigrateApp", fingerprint);
            AssertNoSidecarFilesInConnectionDirectory(dir);

            // The decrypted logical data is intact.
            var migratedState = ClientConnectionState.TryLoad(dir);
            Assert.NotNull(migratedState);
            Assert.True(migratedState.IsEnrolled);
            Assert.True(migratedState.IsAuthorized);
            Assert.Equal(fingerprint, migratedState.ClientPublicKeyFingerprint);
            Assert.Equal("2026-08-01T00:00:00.0000000Z", migratedState.EnrolledAtUtc);

            // Restart over the migrated (encrypted) directory.
            var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime2.IsEnrolled);
            Assert.Equal(fingerprint, runtime2.ClientPublicKeyFingerprint);
            AssertEncryptedAtRest(cachePath, "-----BEGIN PRIVATE KEY-----", fingerprint);
            AssertEncryptedAtRest(indexPath, "-----BEGIN PUBLIC KEY-----");
            AssertEncryptedAtRest(runtimePath, "LegacyMigrateApp", fingerprint);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>
    /// Legacy keys-only layout (plaintext .cache.dat / .index.dat, no
    /// .runtime.dat): the pre-profile semantics "keys present ==
    /// enrolled" must be preserved, and both key files must be migrated
    /// into the encrypted envelope on load.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task LegacyPlaintextKeys_WithoutProfile_KeepLegacyEnrolledSemantics_AndAreMigrated()
    {
        var dir = CreateTempDir();
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            await File.WriteAllTextAsync(
                Path.Combine(dir, ".cache.dat"), RsaCrypto.ExportPrivateKeyPem(seedRsa));
            await File.WriteAllTextAsync(
                Path.Combine(dir, ".index.dat"), RsaCrypto.ExportPublicKeyPem(seedRsa));
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(seedRsa);
            var cfg = TestConfig("LegacyKeysApp");

            var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);

            Assert.True(runtime.IsEnrolled);
            Assert.Equal(fingerprint, runtime.ClientPublicKeyFingerprint);

            // No .runtime.dat existed and the connection is already
            // enrolled: the profile must not be created (same behavior
            // as before encryption-at-rest).
            Assert.False(File.Exists(Path.Combine(dir, ".runtime.dat")));

            // Both key files migrated in place.
            AssertEncryptedAtRest(Path.Combine(dir, ".cache.dat"),
                "-----BEGIN PRIVATE KEY-----", fingerprint);
            AssertEncryptedAtRest(Path.Combine(dir, ".index.dat"),
                "-----BEGIN PUBLIC KEY-----", fingerprint);
            AssertNoSidecarFilesInConnectionDirectory(dir);

            // Restart keeps the same identity and enrollment.
            var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime2.IsEnrolled);
            Assert.Equal(fingerprint, runtime2.ClientPublicKeyFingerprint);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>
    /// Legacy .pem-layout migration (spec §18): client_private_key.pem /
    /// client_public_key.pem next to the executable are copied into the
    /// connection directory as .cache.dat / .index.dat. The destination
    /// pair must be created DIRECTLY in the encrypted envelope (the
    /// legacy plaintext PEM never lands inside the connection directory)
    /// and must decrypt back to the exact legacy key material.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task PrepareIdentityDirectory_LegacyPemFiles_MigratedToEncryptedConnectionFiles()
    {
        // The connection directory now lives under the canonical product
        // root, so give this test its own root (cleaned up on dispose).
        using var clientRoot = new ClientConnectionRootScope();
        var exeDir = CreateTempDir();
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            var privPem = RsaCrypto.ExportPrivateKeyPem(seedRsa);
            var pubPem = RsaCrypto.ExportPublicKeyPem(seedRsa);
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(seedRsa);

            File.WriteAllText(Path.Combine(exeDir, "client_private_key.pem"), privPem);
            File.WriteAllText(Path.Combine(exeDir, "client_public_key.pem"), pubPem);

            var cfg = TestConfig("LegacyPemApp");
            var dest = ClientServiceBundle.PrepareIdentityDirectory(exeDir, cfg, 1, cfg);
            Assert.StartsWith(clientRoot.ProductRoot, Path.GetFullPath(dest));

            var cachePath = Path.Combine(dest, ".cache.dat");
            var indexPath = Path.Combine(dest, ".index.dat");
            Assert.True(File.Exists(cachePath));
            Assert.True(File.Exists(indexPath));

            // Encrypted at rest from the moment of creation.
            AssertEncryptedAtRest(cachePath, "-----BEGIN PRIVATE KEY-----", fingerprint);
            AssertEncryptedAtRest(indexPath, "-----BEGIN PUBLIC KEY-----", fingerprint);

            // Decryption yields the exact legacy key material.
            Assert.Equal(privPem, await PemStore.LoadPrivateKeyAsync(cachePath));
            Assert.Equal(pubPem, await PemStore.LoadPublicKeyAsync(indexPath));

            // The client can load the migrated identity (legacy
            // keys-present == enrolled) with the same key pair.
            var runtime = await ClientRuntime.LoadOrCreateAsync(dest, cfg);
            Assert.True(runtime.IsEnrolled);
            Assert.Equal(fingerprint, runtime.ClientPublicKeyFingerprint);
        }
        finally
        {
            TryDelete(exeDir);
        }
    }

    /// <summary>
    /// After enrollment completes (ReloadKeysAsync), the profile is
    /// rewritten as an encrypted envelope carrying the enrolled state.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task ReloadKeysAfterEnrollment_PersistsEncryptedProfile()
    {
        var dir = CreateTempDir();
        try
        {
            var cfg = TestConfig("EnrolledProfileApp");
            var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.False(runtime.IsEnrolled);

            await runtime.ReloadKeysAsync();
            Assert.True(runtime.IsEnrolled);

            var runtimePath = Path.Combine(dir, ".runtime.dat");
            AssertEncryptedAtRest(runtimePath,
                cfg.GatewayPublicIpAddress,
                ConnectionIdentity.ConnectionId(cfg),
                runtime.ClientPublicKeyFingerprint);
            AssertNoSidecarFilesInConnectionDirectory(dir);

            var state = ClientConnectionState.TryLoad(dir);
            Assert.NotNull(state);
            Assert.True(state.IsEnrolled);
            Assert.True(state.IsAuthorized);
            Assert.Equal(runtime.ClientPublicKeyFingerprint, state.ClientPublicKeyFingerprint);

            // Restart recovers the enrolled state.
            var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
            Assert.True(runtime2.IsEnrolled);
            Assert.Equal(runtime.ClientPublicKeyFingerprint,
                runtime2.ClientPublicKeyFingerprint);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

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

    private static void AssertEncryptedAtRest(string path, params string[] plaintextMarkers)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes),
            $"{path} is not in the encrypted-at-rest envelope.");

        var directText = Encoding.UTF8.GetString(bytes);
        foreach (var marker in plaintextMarkers.Where(m => !string.IsNullOrEmpty(m)))
            Assert.DoesNotContain(marker, directText);
    }

    private static void AssertPlaintextOnDisk(string path, string marker)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.False(ProtectedFileStore.HasEncryptedEnvelope(bytes),
            $"{path} should start as legacy plaintext for this migration test.");
        Assert.Contains(marker, Encoding.UTF8.GetString(bytes));
    }

    /// <summary>
    /// The connection directory must contain nothing but the three
    /// state files - in particular no encryption key sidecar.
    /// </summary>
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

        var externalKeyPath = ProtectedFileStore.ExternalKeyPathForDiagnostics;
        if (externalKeyPath != null)
        {
            Assert.False(IsUnderDirectory(externalKeyPath, connectionDir),
                $"Encryption key must not be stored in the connection directory: {externalKeyPath}");
        }
    }

    private static bool IsUnderDirectory(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var fullDirectory = Path.GetFullPath(directory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(fullDirectory, StringComparison.OrdinalIgnoreCase);
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-conn-protected-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
