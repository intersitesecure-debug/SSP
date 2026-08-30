// File: tests/SSP.Tests/ClientConnectionRootTests.cs
//
// Canonical client connection location:
//
//   C:\Program Files\SSP\connections\{ConnectionId}\
//
//   * the connection directory is resolved under the canonical product
//     root (C:\Program Files\SSP), NOT next to the launched executable,
//   * the ConnectionId structure, the file names
//     (.cache.dat / .index.dat / .runtime.dat) and the encrypted-at-rest
//     format are UNCHANGED,
//   * pre-canonical (per-exe) connection state is moved into the
//     canonical root on first run, so an already enrolled installation
//     does not have to re-enroll.
//
// Tests run with the root redirected to a temporary directory through
// ClientConnectionRootScope (the production value is C:\Program Files\SSP).

using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Tests.Helpers;

namespace SSP.Tests;

public sealed class ClientConnectionRootTests
{
    /// <summary>
    /// The connection directory must live under the canonical product
    /// root for ANY exe folder, and two different exe folders of the
    /// same connection must resolve to the SAME directory.
    /// </summary>
    [Fact]
    public void ConnectionDirectory_UnderCanonicalRoot_NotExeDirectory()
    {
        using var scope = new ClientConnectionRootScope();
        var cfg = MakeConfig("ROOTAPP");
        var id = ConnectionIdentity.ConnectionId(cfg);

        var dir = ClientServiceBundle.ConnectionDirectory("/some/exe/dir", cfg);

        Assert.Equal(
            Path.GetFullPath(Path.Combine(scope.ProductRoot, "connections", id)),
            Path.GetFullPath(dir));
        Assert.DoesNotContain("/some/exe/dir", dir);

        // Any other exe folder (any machine location) resolves to the
        // exact same directory: one machine == one state per connection.
        Assert.Equal(
            Path.GetFullPath(dir),
            Path.GetFullPath(ClientServiceBundle.ConnectionDirectory(@"C:\Elsewhere\Other", cfg)));
    }

    /// <summary>
    /// The structure under the canonical root is unchanged:
    /// {ProductRoot}\connections\{ConnectionId}\ with the same three
    /// state file names, encrypted at rest.
    /// </summary>
    [Fact]
    public async Task ConnectionDirectory_KeepsConnectionIdStructure_AndFileNames()
    {
        using var scope = new ClientConnectionRootScope();
        var cfg = MakeConfig("STRUCT");
        var id = ConnectionIdentity.ConnectionId(cfg);

        var dir = ClientServiceBundle.ConnectionDirectory("unused", cfg);
        Assert.Equal(id, Path.GetFileName(Path.GetFullPath(dir)));
        Assert.Equal(
            Path.GetFullPath(Path.Combine(scope.ProductRoot, "connections")),
            Path.GetFullPath(Path.GetDirectoryName(Path.GetFullPath(dir))!));

        var runtime = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
        Assert.False(runtime.IsEnrolled);

        // Same file names as before the canonical location.
        var names = Directory.EnumerateFiles(dir)
            .Select(Path.GetFileName)
            .Select(n => n!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var expectedNames = new[] { ".cache.dat", ".index.dat", ".runtime.dat" };
        Assert.Equal(expectedNames.Length, names.Count);
        Assert.All(expectedNames, n => Assert.Contains(n, names));

        // Still protected at rest.
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(
            File.ReadAllBytes(Path.Combine(dir, ".cache.dat"))));
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(
            File.ReadAllBytes(Path.Combine(dir, ".runtime.dat"))));

        // Restart over the canonical directory recovers the SAME identity.
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(dir, cfg);
        Assert.Equal(runtime.ClientPublicKeyFingerprint, runtime2.ClientPublicKeyFingerprint);
    }

    /// <summary>
    /// Pre-canonical installation: the connection state lives next to
    /// the executable in {exeDir}\connections\{ConnectionId}\ (the
    /// layout before the canonical location). The first run through
    /// PrepareIdentityDirectory must move it into the canonical root,
    /// byte for byte (the encryption is never re-wrapped), keep the
    /// source in place, and the client must stay enrolled - no
    /// re-enrollment, no burned One-Time Token.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task PrepareIdentityDirectory_MovesPreviousPerExeState_ToCanonicalRoot()
    {
        using var scope = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-prev-exe-");
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            var privPem = RsaCrypto.ExportPrivateKeyPem(seedRsa);
            var pubPem = RsaCrypto.ExportPublicKeyPem(seedRsa);
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(seedRsa);
            var cfg = MakeConfig("PREVCANON");
            var id = ConnectionIdentity.ConnectionId(cfg);

            // Seed the pre-canonical per-exe layout (already enrolled).
            var previousDir = Path.Combine(exeDir, "connections", id);
            Directory.CreateDirectory(previousDir);
            await PemStore.SavePrivateKeyAsync(Path.Combine(previousDir, ".cache.dat"), privPem);
            await PemStore.SavePublicKeyAsync(Path.Combine(previousDir, ".index.dat"), pubPem);

            var state = ClientConnectionState.FromConfig(cfg);
            state.ClientPublicKeyFingerprint = fingerprint;
            state.IsEnrolled = true;
            state.IsAuthorized = true;
            state.EnrolledAtUtc = "2026-08-01T00:00:00.0000000Z";
            await ClientConnectionState.SaveAsync(previousDir, state);

            var cacheBefore = File.ReadAllBytes(Path.Combine(previousDir, ".cache.dat"));
            var indexBefore = File.ReadAllBytes(Path.Combine(previousDir, ".index.dat"));
            var runtimeBefore = File.ReadAllBytes(Path.Combine(previousDir, ".runtime.dat"));

            var dest = ClientServiceBundle.PrepareIdentityDirectory(exeDir, cfg, 1, cfg);

            // The prepared directory IS the canonical one.
            Assert.Equal(
                Path.GetFullPath(Path.Combine(scope.ProductRoot, "connections", id)),
                Path.GetFullPath(dest));

            // The state was moved byte for byte: same encrypted envelope,
            // same names, source left in place.
            Assert.Equal(cacheBefore, File.ReadAllBytes(Path.Combine(dest, ".cache.dat")));
            Assert.Equal(indexBefore, File.ReadAllBytes(Path.Combine(dest, ".index.dat")));
            Assert.Equal(runtimeBefore, File.ReadAllBytes(Path.Combine(dest, ".runtime.dat")));
            Assert.True(File.Exists(Path.Combine(previousDir, ".cache.dat")));

            // The client loads the moved state: same identity, still
            // enrolled (no re-enrollment).
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
    /// A HALF identity in the pre-canonical location (private key
    /// without public key) must never be migrated: the canonical
    /// directory stays empty and the client starts fresh instead of
    /// inheriting an incomplete credential.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task PrepareIdentityDirectory_PartialPreviousPair_NotMigrated()
    {
        using var scope = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-partial-");
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            var cfg = MakeConfig("PARTIAL");
            var id = ConnectionIdentity.ConnectionId(cfg);

            var previousDir = Path.Combine(exeDir, "connections", id);
            Directory.CreateDirectory(previousDir);
            await PemStore.SavePrivateKeyAsync(
                Path.Combine(previousDir, ".cache.dat"),
                RsaCrypto.ExportPrivateKeyPem(seedRsa));
            // NO .index.dat: an incomplete pair.

            var dest = ClientServiceBundle.PrepareIdentityDirectory(exeDir, cfg, 1, cfg);
            Assert.Empty(Directory.EnumerateFiles(dest));

            // Fresh identity generated in the canonical root.
            var runtime = await ClientRuntime.LoadOrCreateAsync(dest, cfg);
            Assert.False(runtime.IsEnrolled);
            Assert.True(File.Exists(Path.Combine(dest, ".cache.dat")));
            Assert.True(File.Exists(Path.Combine(dest, ".index.dat")));
        }
        finally
        {
            TryDelete(exeDir);
        }
    }

    /// <summary>
    /// The pre-canonical state of ANOTHER connection (different
    /// Server + Service) must never be adopted: preparing connection B
    /// with connection A's old state sitting next to the exe leaves B's
    /// canonical directory empty.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task PrepareIdentityDirectory_DoesNotAdoptOtherConnectionPreviousState()
    {
        using var scope = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-other-conn-");
        try
        {
            using var seedRsa = RsaCrypto.GenerateKeyPair();
            var otherCfg = MakeConfig("OTHERCONN");
            var ownCfg = MakeConfig("OWNCONN");
            var otherId = ConnectionIdentity.ConnectionId(otherCfg);

            // The folder holds the pre-canonical state of the OTHER
            // connection only.
            var otherDir = Path.Combine(exeDir, "connections", otherId);
            Directory.CreateDirectory(otherDir);
            await PemStore.SavePrivateKeyAsync(
                Path.Combine(otherDir, ".cache.dat"),
                RsaCrypto.ExportPrivateKeyPem(seedRsa));
            await PemStore.SavePublicKeyAsync(
                Path.Combine(otherDir, ".index.dat"),
                RsaCrypto.ExportPublicKeyPem(seedRsa));

            var dest = ClientServiceBundle.PrepareIdentityDirectory(exeDir, ownCfg, 1, ownCfg);
            Assert.Empty(Directory.EnumerateFiles(dest));
            Assert.NotEqual(
                Path.GetFullPath(Path.Combine(dest)),
                Path.GetFullPath(otherDir));
        }
        finally
        {
            TryDelete(exeDir);
        }
    }

    /// <summary>
    /// The default product root is C:\Program Files\SSP (resolved
    /// through .NET), the connections root is its connections subfolder,
    /// and the environment override wins over both.
    /// </summary>
    [Fact]
    public void ClientInstallPaths_DefaultRoot_IsProgramFilesSSP_AndOverrideWins()
    {
        // SetEnvironmentVariable returns void, so the previous value has to
        // be read explicitly in order to restore it afterwards.
        var previous = Environment.GetEnvironmentVariable(
            ClientInstallPaths.EnvironmentRootOverrideVariable);
        Environment.SetEnvironmentVariable(
            ClientInstallPaths.EnvironmentRootOverrideVariable, null);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                Assert.Equal(
                    Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                        "SSP"),
                    ClientInstallPaths.GetProductRoot());
            }

            var custom = Path.GetTempPath();
            Environment.SetEnvironmentVariable(
                ClientInstallPaths.EnvironmentRootOverrideVariable, custom);
            Assert.Equal(custom, ClientInstallPaths.GetProductRoot());
            Assert.Equal(
                Path.Combine(custom, "connections"),
                ClientInstallPaths.GetConnectionsRoot());
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                ClientInstallPaths.EnvironmentRootOverrideVariable, previous);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    private static ClientConfig MakeConfig(string appName)
    {
        using var serverRsa = RsaCrypto.GenerateKeyPair();
        var pubPem = RsaCrypto.ExportPublicKeyPem(serverRsa);
        return new ClientConfig
        {
            ApplicationName        = appName,
            ServerPublicKeyPem     = pubPem,
            ServerFingerprint      = RsaCrypto.ComputePublicKeyFingerprintFromPem(pubPem),
            GatewayPublicIpAddress = "198.51.100.23",
            GatewayPort            = 4433,
            LocalApplicationPort   = 3389,
            ClientTunnelPort       = 13389,
            ClientName             = "Client01",
        };
    }

    private static string NewTempDir(string prefix)
    {
        var dir = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
