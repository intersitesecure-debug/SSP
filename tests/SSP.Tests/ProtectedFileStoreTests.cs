// File: tests/SSP.Tests/ProtectedFileStoreTests.cs
//
// Focused tests for encrypted-at-rest storage of SSP service files.

using System.Text;
using System.Text.Json;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;

namespace SSP.Tests;

public class ProtectedFileStoreTests
{
    [Fact]
    public async Task ProtectedServiceFiles_AreEncryptedAtRest_AndRoundTripLogicalData()
    {
        var dir = CreateTempDir();
        try
        {
            var paths = ProtectedPaths(dir);
            using var rsa = RsaCrypto.GenerateKeyPair();
            var privatePem = RsaCrypto.ExportPrivateKeyPem(rsa);
            var publicPem = RsaCrypto.ExportPublicKeyPem(rsa);
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(publicPem);

            var config = new ServiceConfig
            {
                ApplicationName = "ProtectedAppMarker",
                GatewayPublicIpAddress = "198.51.100.44",
                GatewayPort = 4443,
                LocalApplicationPort = 3389,
                ClientTunnelPort = 13389,
                ActiveOneTimeTokenHash = "logical-token-hash-marker",
                PendingOneTimeTokens = new List<PendingOneTimeToken>
                {
                    new()
                    {
                        ClientName = "ClientMarker01",
                        OneTimeTokenHash = "pending-token-hash-marker",
                        CreatedAtUtc = "2026-08-26T00:00:00.0000000Z",
                    }
                },
                CreatedAtUtc = "2026-08-26T00:00:00.0000000Z",
                WindowsServiceName = "SSP ProtectedAppMarker 4443",
            };
            var users = new AuthorisedUsersFile
            {
                Users = new List<AuthorisedUser>
                {
                    new()
                    {
                        ClientPublicKeyFingerprint = fingerprint,
                        ClientPublicKeyPem = publicPem,
                        IsAuthorized = true,
                        EnrolledAtUtc = "2026-08-26T00:01:00.0000000Z",
                        Label = "AuthorisedUserMarker",
                    }
                }
            };

            await ServiceConfigStore.SaveAsync(paths.Cache, config);
            await PemStore.SavePrivateKeyAsync(paths.SysData, privatePem);
            await PemStore.SavePublicKeyAsync(paths.Runtime, publicPem);
            await AuthorisedUsersStore.SaveAsync(paths.Index, users);

            AssertProtectedOnDisk(paths.Cache, "ProtectedAppMarker", "198.51.100.44", "logical-token-hash-marker");
            AssertProtectedOnDisk(paths.SysData, "-----BEGIN PRIVATE KEY-----", privatePem.Split('\n')[1]);
            AssertProtectedOnDisk(paths.Runtime, "-----BEGIN PUBLIC KEY-----", publicPem.Split('\n')[1]);
            AssertProtectedOnDisk(paths.Index, "AuthorisedUserMarker", fingerprint, "-----BEGIN PUBLIC KEY-----");
            AssertNoLocalKeyStoredWithProtectedFiles(dir, paths.All);

            var loadedConfig = await ServiceConfigStore.LoadAsync(paths.Cache);
            var loadedPrivatePem = await PemStore.LoadPrivateKeyAsync(paths.SysData);
            var loadedPublicPem = await PemStore.LoadPublicKeyAsync(paths.Runtime);
            var loadedUsers = await AuthorisedUsersStore.LoadAsync(paths.Index);

            Assert.Equal(Serialize(config), Serialize(loadedConfig));
            Assert.Equal(privatePem, loadedPrivatePem);
            Assert.Equal(publicPem, loadedPublicPem);
            Assert.Equal(Serialize(users), Serialize(loadedUsers));

            // Runtime usability: decrypted key material is still the same PEM
            // SSP expects, and can be imported/used by the existing RSA layer.
            using var loadedPrivate = RsaCrypto.ImportPrivateKeyPem(loadedPrivatePem);
            using var loadedPublic = RsaCrypto.ImportPublicKeyPem(loadedPublicPem);
            var message = Encoding.UTF8.GetBytes("ssp encrypted-at-rest runtime use marker");
            var signature = RsaCrypto.Sign(loadedPrivate, message);
            Assert.True(RsaCrypto.Verify(loadedPublic, message, signature));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public async Task PlaintextProtectedFiles_AreMigratedToEncryptedEnvelope_WithoutChangingLogicalData()
    {
        var dir = CreateTempDir();
        try
        {
            var paths = ProtectedPaths(dir);
            using var rsa = RsaCrypto.GenerateKeyPair();
            var privatePem = RsaCrypto.ExportPrivateKeyPem(rsa);
            var publicPem = RsaCrypto.ExportPublicKeyPem(rsa);
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(publicPem);

            var config = new ServiceConfig
            {
                ApplicationName = "LegacyPlaintextAppMarker",
                GatewayPublicIpAddress = "203.0.113.9",
                GatewayPort = 5443,
                LocalApplicationPort = 5432,
                ClientTunnelPort = 15432,
                ActiveOneTimeTokenHash = "legacy-token-hash-marker",
                PendingOneTimeTokens = new List<PendingOneTimeToken>(),
                CreatedAtUtc = "2026-08-26T00:02:00.0000000Z",
                WindowsServiceName = "SSP LegacyPlaintextAppMarker 5443",
            };
            var users = new AuthorisedUsersFile
            {
                Users = new List<AuthorisedUser>
                {
                    new()
                    {
                        ClientPublicKeyFingerprint = fingerprint,
                        ClientPublicKeyPem = publicPem,
                        IsAuthorized = true,
                        EnrolledAtUtc = "2026-08-26T00:03:00.0000000Z",
                        Label = "LegacyAuthorisedUserMarker",
                    }
                }
            };

            await File.WriteAllTextAsync(paths.Cache, Serialize(config));
            await File.WriteAllTextAsync(paths.SysData, privatePem);
            await File.WriteAllTextAsync(paths.Runtime, publicPem);
            await File.WriteAllTextAsync(paths.Index, Serialize(users));

            AssertPlaintextOnDisk(paths.Cache, "LegacyPlaintextAppMarker");
            AssertPlaintextOnDisk(paths.SysData, "-----BEGIN PRIVATE KEY-----");
            AssertPlaintextOnDisk(paths.Runtime, "-----BEGIN PUBLIC KEY-----");
            AssertPlaintextOnDisk(paths.Index, "LegacyAuthorisedUserMarker");

            var loadedConfig = await ServiceConfigStore.LoadAsync(paths.Cache);
            var loadedPrivatePem = await PemStore.LoadPrivateKeyAsync(paths.SysData);
            var loadedPublicPem = await PemStore.LoadPublicKeyAsync(paths.Runtime);
            var loadedUsers = await AuthorisedUsersStore.LoadAsync(paths.Index);

            Assert.Equal(config.ApplicationName, loadedConfig.ApplicationName);
            Assert.Equal(config.GatewayPublicIpAddress, loadedConfig.GatewayPublicIpAddress);
            Assert.Equal(config.ActiveOneTimeTokenHash, loadedConfig.ActiveOneTimeTokenHash);
            Assert.Equal(privatePem, loadedPrivatePem);
            Assert.Equal(publicPem, loadedPublicPem);
            Assert.Equal(Serialize(users), Serialize(loadedUsers));

            AssertProtectedOnDisk(paths.Cache, "LegacyPlaintextAppMarker", "203.0.113.9", "legacy-token-hash-marker");
            AssertProtectedOnDisk(paths.SysData, "-----BEGIN PRIVATE KEY-----", privatePem.Split('\n')[1]);
            AssertProtectedOnDisk(paths.Runtime, "-----BEGIN PUBLIC KEY-----", publicPem.Split('\n')[1]);
            AssertProtectedOnDisk(paths.Index, "LegacyAuthorisedUserMarker", fingerprint, "-----BEGIN PUBLIC KEY-----");
            AssertNoLocalKeyStoredWithProtectedFiles(dir, paths.All);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    private static (string Cache, string SysData, string Runtime, string Index, string[] All) ProtectedPaths(string dir)
    {
        var cache = Path.Combine(dir, ".cache.dat");
        var sysData = Path.Combine(dir, ".sysdata.bin");
        var runtime = Path.Combine(dir, ".runtime.dat");
        var index = Path.Combine(dir, ".index.dat");
        return (cache, sysData, runtime, index, new[] { cache, sysData, runtime, index });
    }

    private static void AssertProtectedOnDisk(string path, params string[] plaintextMarkers)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes), $"{path} is not in the encrypted-at-rest envelope.");

        var directText = Encoding.UTF8.GetString(bytes);
        foreach (var marker in plaintextMarkers.Where(m => !string.IsNullOrEmpty(m)))
            Assert.DoesNotContain(marker, directText);
    }

    private static void AssertPlaintextOnDisk(string path, string marker)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.False(ProtectedFileStore.HasEncryptedEnvelope(bytes), $"{path} should start as legacy plaintext for this migration test.");
        Assert.Contains(marker, Encoding.UTF8.GetString(bytes));
    }

    private static void AssertNoLocalKeyStoredWithProtectedFiles(string serviceDir, string[] protectedPaths)
    {
        var protectedFullPaths = protectedPaths
            .Select(Path.GetFullPath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var unexpectedSidecars = Directory.EnumerateFiles(serviceDir, "*", SearchOption.TopDirectoryOnly)
            .Where(path => !protectedFullPaths.Contains(Path.GetFullPath(path)))
            .ToArray();
        Assert.Empty(unexpectedSidecars);

        var externalKeyPath = ProtectedFileStore.ExternalKeyPathForDiagnostics;
        if (externalKeyPath != null)
        {
            Assert.False(IsUnderDirectory(externalKeyPath, serviceDir),
                $"Encryption key must not be stored in the service directory: {externalKeyPath}");

            var repoRoot = FindRepositoryRoot();
            if (repoRoot != null)
            {
                Assert.False(IsUnderDirectory(externalKeyPath, repoRoot),
                    $"Encryption key must not be stored in the repository: {externalKeyPath}");
            }

            if (File.Exists(externalKeyPath))
            {
                var keyBytes = File.ReadAllBytes(externalKeyPath);
                foreach (var protectedPath in protectedPaths)
                {
                    Assert.False(ContainsSubsequence(File.ReadAllBytes(protectedPath), keyBytes),
                        $"Encryption key material must not be embedded in {protectedPath}.");
                }
            }
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

    private static bool ContainsSubsequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || needle.Length > haystack.Length)
            return false;

        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var found = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] == needle[j])
                    continue;

                found = false;
                break;
            }

            if (found)
                return true;
        }

        return false;
    }

    private static string? FindRepositoryRoot()
    {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "SSP.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return null;
    }

    private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, JsonOptions.Default);

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-protected-store-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
