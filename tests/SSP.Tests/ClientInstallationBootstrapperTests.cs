// File: tests/SSP.Tests/ClientInstallationBootstrapperTests.cs
//
// Unit coverage of the Windows launch gate that runs before the
// client's existing startup path:
//
//   * SSP.Client.*.exe launched OUTSIDE C:\Program Files\SSP requires
//     the install handoff (copy + Desktop shortcut + relaunch),
//   * the SAME executable launched FROM C:\Program Files\SSP passes
//     through: no copy, no shortcut,
//   * the shortcut name is derived from the client's own name,
//   * the handoff moves the launched connection's state from the
//     pre-canonical per-exe location to the canonical root - and only
//     that connection's state.
//
// The gate, the name derivation and the state move are pure file/logic
// operations, so they are verified on every platform.

using SSP.Client.Runtime;
using SSP.Client.Setup;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Server.Setup;
using SSP.Tests.Helpers;

namespace SSP.Tests;

public sealed class ClientInstallationBootstrapperTests
{
    private const string CanonicalDir = @"C:\Program Files\SSP";

    // ────────────────────────────────────────────────────────────────
    // The launch gate
    // ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(@"C:\Program Files\SSP\SSP.Client.RDP.Client01.exe", false)]
    [InlineData(@"c:\program files\ssp\SSP.Client.RDP.Client01.exe", false)]
    [InlineData(@"C:\Program Files\SSP\\SSP.Client.WEB.Client02.exe", false)]
    [InlineData(@"C:\Program Files\SSP\SSP.Client.exe", false)]
    [InlineData(@"C:\Users\Operator\Downloads\SSP.Client.RDP.Client01.exe", true)]
    [InlineData(@"D:\Deployment\SSP.Client.WEB.Client02.exe", true)]
    [InlineData(@"C:\Tools\SSP\SSP.Client.SQL.Client03.exe", true)]
    [InlineData(@"C:\Program Files\SSP\nested\SSP.Client.RDP.Client01.exe", true)]
    public void RequiresInstallation_OnlyForClientExecutableOutsideCanonicalDir(
        string launchedPath,
        bool expected)
    {
        Assert.Equal(expected,
            ClientInstallationBootstrapper.RequiresInstallation(launchedPath, CanonicalDir));
    }

    [Theory]
    [InlineData(@"C:\Users\Operator\Downloads\dotnet.exe")]
    [InlineData(@"C:\Users\Operator\Downloads\SSP.Client.RDP.Client01.dll")]
    [InlineData(@"C:\Users\Operator\Downloads\SSP.Client.RDP.Client01.deps.json")]
    [InlineData(@"C:\Users\Operator\Downloads\SSP.Server.exe")]
    [InlineData(@"C:\Users\Operator\Downloads\SSP")]
    [InlineData(@"")]
    [InlineData(null)]
    public void RequiresInstallation_RejectsNonClientProcesses(string? launchedPath)
    {
        Assert.False(
            ClientInstallationBootstrapper.RequiresInstallation(launchedPath, CanonicalDir));
    }

    // ────────────────────────────────────────────────────────────────
    // The shortcut name
    // ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(@"SSP.Client.RDP.Client01.exe", "SSP Client - RDP - Client01")]
    [InlineData(@"SSP.Client.WEB.Client02.exe", "SSP Client - WEB - Client02")]
    [InlineData(@"C:\Users\Operator\Downloads\SSP.Client.SQL.Client03.exe", "SSP Client - SQL - Client03")]
    [InlineData(@"SSP.Client.exe", "SSP Client")]
    public void DeriveShortcutName_BasedOnTheClientName(string fileName, string expected)
    {
        Assert.Equal(expected, ClientInstallationBootstrapper.DeriveShortcutName(fileName));
    }

    [Theory]
    [InlineData(@"SSP.Client.RDP.Client01.exe", true)]
    [InlineData(@"SSP.Client.exe", true)]
    [InlineData(@"ssp.client.rdp.client01.EXE", true)]
    [InlineData(@"SSP.Client.RDP.Client01.dll", false)]
    [InlineData(@"MyApp.exe", false)]
    [InlineData(@"SSPClient.exe", false)]
    public void IsClientExecutableName_MatchesSSPClientExesOnly(string fileName, bool expected)
    {
        Assert.Equal(expected, ClientInstallationBootstrapper.IsClientExecutableName(fileName));
    }

    // ────────────────────────────────────────────────────────────────
    // The canonical root
    // ────────────────────────────────────────────────────────────────

    [Fact]
    public void CanonicalDirectory_IsTheClientProductRoot()
    {
        // Without the override the product root is the .NET-resolved
        // Program Files folder + SSP (C:\Program Files\SSP on Windows).
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
                        ClientInstallPaths.ProductDirectoryName),
                    ClientInstallPaths.GetProductRoot());
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                ClientInstallPaths.EnvironmentRootOverrideVariable, previous);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // The state move that happens before the canonical relaunch
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The handoff moves the LAUNCHED connection's state from the
    /// pre-canonical per-exe location to the canonical root, byte for
    /// byte, and leaves every OTHER connection's state in place.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task MigrateConnectionState_MovesOnlyLaunchedConnection_ToCanonicalRoot()
    {
        using var scope = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-mig-exe-");
        try
        {
            using var serverRsa = RsaCrypto.GenerateKeyPair();
            var pubPem = RsaCrypto.ExportPublicKeyPem(serverRsa);
            var cfg = new ClientConfig
            {
                ApplicationName        = "RDP",
                ServerPublicKeyPem     = pubPem,
                ServerFingerprint      = RsaCrypto.ComputePublicKeyFingerprintFromPem(pubPem),
                GatewayPublicIpAddress = "198.51.100.7",
                GatewayPort            = 4433,
                LocalApplicationPort   = 3389,
                ClientTunnelPort       = 13389,
                OneTimeToken           = "mig-ott",
                ClientName             = "Client01",
            };
            var ownId = ConnectionIdentity.ConnectionId(cfg);

            // A real patched client binary (the handoff reads its patch
            // slot to learn which connection belongs to the launched exe).
            var exePath = Path.Combine(exeDir, "SSP.Client.RDP.Client01.exe");
            await SetupEngine.BuildPatchedClientAsync(exePath, cfg);

            // Pre-canonical state of the launched connection (enrolled).
            using var clientRsa = RsaCrypto.GenerateKeyPair();
            var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(clientRsa);
            var ownDir = Path.Combine(exeDir, ClientInstallPaths.ConnectionsDirectoryName, ownId);
            Directory.CreateDirectory(ownDir);
            await PemStore.SavePrivateKeyAsync(
                Path.Combine(ownDir, ".cache.dat"), RsaCrypto.ExportPrivateKeyPem(clientRsa));
            await PemStore.SavePublicKeyAsync(
                Path.Combine(ownDir, ".index.dat"), RsaCrypto.ExportPublicKeyPem(clientRsa));
            var state = ClientConnectionState.FromConfig(cfg);
            state.ClientPublicKeyFingerprint = fingerprint;
            state.IsEnrolled = true;
            state.IsAuthorized = true;
            await ClientConnectionState.SaveAsync(ownDir, state);
            var cacheBefore = File.ReadAllBytes(Path.Combine(ownDir, ".cache.dat"));
            var indexBefore = File.ReadAllBytes(Path.Combine(ownDir, ".index.dat"));
            var runtimeBefore = File.ReadAllBytes(Path.Combine(ownDir, ".runtime.dat"));

            // Pre-canonical state of ANOTHER connection: must stay put.
            var otherDir = Path.Combine(exeDir, ClientInstallPaths.ConnectionsDirectoryName, "OTHER-CONNECTION");
            Directory.CreateDirectory(otherDir);
            File.WriteAllText(Path.Combine(otherDir, ".cache.dat"), "other");

            ClientInstallationBootstrapper.MigrateConnectionState(exePath, scope.ProductRoot);

            // The launched connection's state now exists under the
            // canonical root, byte for byte (encryption untouched).
            var canonicalOwn = Path.Combine(scope.ProductRoot, ClientInstallPaths.ConnectionsDirectoryName, ownId);
            Assert.Equal(cacheBefore, File.ReadAllBytes(Path.Combine(canonicalOwn, ".cache.dat")));
            Assert.Equal(indexBefore, File.ReadAllBytes(Path.Combine(canonicalOwn, ".index.dat")));
            Assert.Equal(runtimeBefore, File.ReadAllBytes(Path.Combine(canonicalOwn, ".runtime.dat")));

            // The source stayed in place (non-destructive move).
            Assert.True(File.Exists(Path.Combine(ownDir, ".cache.dat")));

            // The other connection was NOT moved.
            Assert.False(Directory.Exists(
                Path.Combine(scope.ProductRoot, ClientInstallPaths.ConnectionsDirectoryName, "OTHER-CONNECTION")));
            Assert.True(File.Exists(Path.Combine(otherDir, ".cache.dat")));

            // The canonical copy recovers the moved, enrolled identity.
            var runtime = await ClientRuntime.LoadOrCreateAsync(canonicalOwn, cfg);
            Assert.True(runtime.IsEnrolled);
            Assert.Equal(fingerprint, runtime.ClientPublicKeyFingerprint);
        }
        finally
        {
            TryDelete(exeDir);
        }
    }

    /// <summary>
    /// A binary without a readable patch slot (raw template host) moves
    /// EVERY connection sub-directory of the pre-canonical location.
    /// </summary>
    [Fact(Timeout = 30000)]
    public void MigrateConnectionState_UnpatchedBinary_MovesAllConnections()
    {
        using var scope = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-mig-host-");
        try
        {
            // Not a real client binary: the patch slot read fails, so
            // the handoff falls back to moving every sub-directory.
            var exePath = Path.Combine(exeDir, "SSP.Client.exe");
            File.WriteAllBytes(exePath, new byte[] { 1, 2, 3, 4 });

            var first = Path.Combine(exeDir, ClientInstallPaths.ConnectionsDirectoryName, "A-1");
            var second = Path.Combine(exeDir, ClientInstallPaths.ConnectionsDirectoryName, "B-2");
            Directory.CreateDirectory(first);
            Directory.CreateDirectory(second);
            File.WriteAllText(Path.Combine(first, ".cache.dat"), "a");
            File.WriteAllText(Path.Combine(second, ".index.dat"), "b");

            ClientInstallationBootstrapper.MigrateConnectionState(exePath, scope.ProductRoot);

            Assert.True(File.Exists(
                Path.Combine(scope.ProductRoot, ClientInstallPaths.ConnectionsDirectoryName, "A-1", ".cache.dat")));
            Assert.True(File.Exists(
                Path.Combine(scope.ProductRoot, ClientInstallPaths.ConnectionsDirectoryName, "B-2", ".index.dat")));
        }
        finally
        {
            TryDelete(exeDir);
        }
    }

    /// <summary>
    /// No pre-canonical state (or the exe already in the canonical
    /// directory) is a clean no-op: nothing is created or thrown.
    /// </summary>
    [Fact]
    public void MigrateConnectionState_NothingToMove_IsNoOp()
    {
        using var scope = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-mig-noop-");
        try
        {
            var exePath = Path.Combine(exeDir, "SSP.Client.RDP.Client01.exe");
            File.WriteAllBytes(exePath, new byte[] { 1, 2, 3, 4 });

            // 1. No connections folder next to the exe.
            ClientInstallationBootstrapper.MigrateConnectionState(exePath, scope.ProductRoot);
            Assert.False(Directory.Exists(
                Path.Combine(scope.ProductRoot, ClientInstallPaths.ConnectionsDirectoryName)));

            // 2. The exe already lives in the canonical directory.
            Directory.CreateDirectory(
                Path.Combine(scope.ProductRoot, ClientInstallPaths.ConnectionsDirectoryName, "A-1"));
            ClientInstallationBootstrapper.MigrateConnectionState(
                Path.Combine(scope.ProductRoot, "SSP.Client.RDP.Client01.exe"), scope.ProductRoot);
        }
        finally
        {
            TryDelete(exeDir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

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
