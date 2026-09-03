// File: tests/SSP.Tests/MultiServerMultiServiceTests.cs
//
// Per-Server + per-Service enrollment isolation.
//
// The logical identity of an SSP connection is
//
//     ConnectionIdentity = Server + Service/Application
//
// so ServerA/RDP, ServerA/WEB, ServerB/RDP and ServerB/WEB are four
// different SSP identities even when the client is called "Client01"
// in all four cases.
//
// This file covers the required matrix:
//   Case 1  ServerA/RDP  Client01                 enrolls
//   Case 2  ServerA/RDP  Client02                 enrolls
//   Case 3  ServerA/WEB  Client01                 enrolls (RDP does not satisfy it)
//   Case 4  ServerB/WEB  Client01                 enrolls (neither A/RDP nor A/WEB satisfies it)
//   Case 5  one client, three connections, all independently enrolled
//   Case 6  service restart: all three profiles stay valid
//   Case 7  a new client on ServerA/RDP leaves the other connections untouched
// plus the mandatory negative security tests.

using System.Net;
using System.Net.Sockets;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Util;
using SSP.Server.Setup;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class MultiServerMultiServiceTests
{
    // ────────────────────────────────────────────────────────────────
    // Connection identity (unit level)
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The connection id must distinguish Server AND Service, and must
    /// NOT depend on the client name.
    /// </summary>
    [Fact]
    public void ConnectionId_IsServerPlusService_AndIgnoresClientName()
    {
        using var serverA = RsaCrypto.GenerateKeyPair();
        using var serverB = RsaCrypto.GenerateKeyPair();
        var pemA = RsaCrypto.ExportPublicKeyPem(serverA);
        var pemB = RsaCrypto.ExportPublicKeyPem(serverB);

        var aRdp = Cfg("RDP", pemA, 4433, "Client01");
        var aWeb = Cfg("WEB", pemA, 4480, "Client01");
        var bRdp = Cfg("RDP", pemB, 4433, "Client01");
        var bWeb = Cfg("WEB", pemB, 4480, "Client01");

        var ids = new[] { aRdp, aWeb, bRdp, bWeb }
            .Select(ConnectionIdentity.ConnectionId)
            .ToArray();

        Assert.Equal(4, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());

        // Same Server + Service, different client name => same connection.
        var aRdpOtherName = Cfg("RDP", pemA, 4433, "C1");
        Assert.Equal(ids[0], ConnectionIdentity.ConnectionId(aRdpOtherName));
        Assert.True(ConnectionIdentity.SameConnection(aRdp, aRdpOtherName));

        // The server part is the key fingerprint, not the IP address.
        Assert.Equal(
            RsaCrypto.ComputePublicKeyFingerprintFromPem(pemA),
            ConnectionIdentity.ResolveServerFingerprint(aRdp));

        // Filesystem safe.
        Assert.DoesNotContain(Path.GetInvalidFileNameChars(), c => ids[0].Contains(c));
    }

    /// <summary>
    /// The same ApplicationName hosted by two different servers must be
    /// two entries in the bundle, not one overwriting the other.
    /// </summary>
    [Fact]
    public async Task Bundle_SameApplicationOnTwoServers_StaysIndependent()
    {
        using var serverA = RsaCrypto.GenerateKeyPair();
        using var serverB = RsaCrypto.GenerateKeyPair();
        var webA = Cfg("WEB", RsaCrypto.ExportPublicKeyPem(serverA), 4480, "Client01");
        var webB = Cfg("WEB", RsaCrypto.ExportPublicKeyPem(serverB), 4480, "Client01");
        webA.ClientTunnelPort = 8181;
        webB.ClientTunnelPort = 8281;

        var services = new List<ClientConfig>();
        ClientServiceBundle.Upsert(services, webA);
        ClientServiceBundle.Upsert(services, webB);
        Assert.Equal(2, services.Count);

        var dir = NewTempDir("ssp-bundle-2servers-");
        try
        {
            // The bundle is embedded in the client executable, so the
            // folder needs one for the merged list to live in.
            var exePath = Path.Combine(dir, "SSP.Client.WEB.Client01.exe");
            await SetupEngine.BuildPatchedClientAsync(exePath, webA);
            await SetupEngine.WriteClientServiceBundleAsync(dir, services);
            var resolved = await ClientServiceBundle.ResolveAsync(dir, webA, File.ReadAllBytes(exePath));

            Assert.Equal(2, resolved.Count);
            Assert.Equal(2, resolved.Select(ConnectionIdentity.ConnectionId).Distinct().Count());
            Assert.Equal(new[] { 8181, 8281 }, resolved.Select(r => r.ClientTunnelPort).OrderBy(p => p).ToArray());
        }
        finally { Delete(dir); }
    }

    /// <summary>
    /// Each connection gets its own directory, its own key pair and its
    /// own enrollment state - including two WEB services on two servers.
    /// </summary>
    [Fact]
    public async Task ConnectionDirectories_AreIndependent_PerServerAndService()
    {
        using var serverA = RsaCrypto.GenerateKeyPair();
        using var serverB = RsaCrypto.GenerateKeyPair();
        var pemA = RsaCrypto.ExportPublicKeyPem(serverA);
        var pemB = RsaCrypto.ExportPublicKeyPem(serverB);

        var configs = new[]
        {
            Cfg("RDP", pemA, 4433, "Client01"),
            Cfg("WEB", pemA, 4480, "Client01"),
            Cfg("WEB", pemB, 4480, "Client01"),
        };

        // Isolated canonical connection root (the connection
        // directories no longer live inside exeDir).
        using var clientRoot = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-conn-dirs-");
        try
        {
            var runtimes = new List<ClientRuntime>();
            foreach (var cfg in configs)
            {
                var dir = ClientServiceBundle.PrepareIdentityDirectory(exeDir, cfg, configs.Length, configs[0]);
                runtimes.Add(await ClientRuntime.LoadOrCreateAsync(dir, cfg));
            }

            Assert.StartsWith(clientRoot.ProductRoot, Path.GetFullPath(runtimes[0].ConnectionDirectory));
            Assert.Equal(3, runtimes.Select(r => r.ConnectionDirectory).Distinct().Count());
            Assert.Equal(3, runtimes.Select(r => r.ClientPublicKeyFingerprint).Distinct().Count());
            Assert.All(runtimes, r => Assert.False(r.IsEnrolled));
        }
        finally { Delete(exeDir); }
    }

    /// <summary>
    /// A stored profile of one connection must never make another
    /// connection look enrolled, even if the key pair is copied over.
    /// </summary>
    [Fact]
    public async Task StoredProfile_OfOneConnection_DoesNotEnrollAnother()
    {
        using var serverA = RsaCrypto.GenerateKeyPair();
        using var serverB = RsaCrypto.GenerateKeyPair();
        var rdpA = Cfg("RDP", RsaCrypto.ExportPublicKeyPem(serverA), 4433, "Client01");
        var webA = Cfg("WEB", RsaCrypto.ExportPublicKeyPem(serverA), 4480, "Client01");
        var webB = Cfg("WEB", RsaCrypto.ExportPublicKeyPem(serverB), 4480, "Client01");

        var dir = NewTempDir("ssp-profile-");
        try
        {
            // Simulate a fully enrolled ServerA/RDP connection directory.
            var rdpRuntime = await ClientRuntime.LoadOrCreateAsync(dir, rdpA);
            await rdpRuntime.ReloadKeysAsync();
            Assert.True(rdpRuntime.IsEnrolled);

            // The very same directory, reinterpreted as another service or
            // another server, must NOT be considered enrolled.
            Assert.False((await ClientRuntime.LoadOrCreateAsync(dir, webA)).IsEnrolled);
            Assert.False((await ClientRuntime.LoadOrCreateAsync(dir, webB)).IsEnrolled);

            // ... while the original connection still is.
            Assert.True((await ClientRuntime.LoadOrCreateAsync(dir, rdpA)).IsEnrolled);
        }
        finally { Delete(dir); }
    }

    // ────────────────────────────────────────────────────────────────
    // The full matrix, end to end
    // ────────────────────────────────────────────────────────────────

    [Fact(Timeout = 180000)]
    public async Task Matrix_MultiServerMultiService_EnrollsIndependently()
    {
        var root = NewTempDir("ssp-matrix-");
        // Isolated canonical connection root for this test (the
        // connection state is machine-wide per ConnectionId).
        using var clientRoot = new ClientConnectionRootScope(root);
        var serverA = Path.Combine(root, "ServerA", "services");
        var serverB = Path.Combine(root, "ServerB", "services");
        Directory.CreateDirectory(serverA);
        Directory.CreateDirectory(serverB);

        var exeDir = NewTempDir("ssp-matrix-client-");

        SspTestHarness? aRdpHost = null;
        SspTestHarness? aWebHost = null;
        SspTestHarness? bWebHost = null;

        try
        {
            // ── provisioning ────────────────────────────────────────
            var aRdpSetup = await SetupAsync(serverA, "RDP", "Client01");
            var aWebSetup = await SetupAsync(serverA, "WEB", "Client01");
            var bWebSetup = await SetupAsync(serverB, "WEB", "Client01");

            // §4/§10: independent RSA key pairs per Server + Service.
            var fingerprints = new List<string>();
            foreach (var setup in new[] { aRdpSetup, aWebSetup, bWebSetup })
            {
                var pubPem = await PemStore.LoadPublicKeyAsync(setup.ServerPublicKeyPath);
                fingerprints.Add(RsaCrypto.ComputePublicKeyFingerprintFromPem(pubPem));
            }
            Assert.Equal(3, fingerprints.Distinct().Count());

            var aRdpCfg = PatchedConfig(aRdpSetup);
            var aWebCfg = PatchedConfig(aWebSetup);
            var bWebCfg = PatchedConfig(bWebSetup);

            // §6/§10: three distinct connection identities, three distinct
            // server public keys, three distinct OTTs - same client name.
            Assert.Equal("Client01", aRdpCfg.ClientName);
            Assert.Equal("Client01", bWebCfg.ClientName);
            Assert.Equal(3, new[] { aRdpCfg, aWebCfg, bWebCfg }
                .Select(ConnectionIdentity.ConnectionId).Distinct().Count());
            Assert.Equal(3, new[] { aRdpCfg, aWebCfg, bWebCfg }
                .Select(c => c.ServerPublicKeyPem).Distinct().Count());
            Assert.Equal(3, new[] { aRdpCfg, aWebCfg, bWebCfg }
                .Select(c => c.OneTimeToken).Distinct().Count());

            aRdpHost = await StartAsync(aRdpSetup);
            aWebHost = await StartAsync(aWebSetup);
            bWebHost = await StartAsync(bWebSetup);

            var configs = new[] { aRdpCfg, aWebCfg, bWebCfg };
            var runtimes = new List<ClientRuntime>();
            foreach (var cfg in configs)
            {
                var dir = ClientServiceBundle.PrepareIdentityDirectory(exeDir, cfg, configs.Length, aRdpCfg);
                runtimes.Add(await ClientRuntime.LoadOrCreateAsync(dir, cfg));
            }

            // §13: connection-specific local tunnel ports.
            Assert.Equal(3, runtimes.Select(r => r.Config.ClientTunnelPort).Distinct().Count());

            // ── Case 1: ServerA/RDP + Client01 ─────────────────────
            await EnrollmentHelper.EnrollAsync(runtimes[0]);
            Assert.True(runtimes[0].IsEnrolled);

            // §3: the RDP enrollment must not satisfy WEB.
            Assert.False(runtimes[1].IsEnrolled);
            Assert.False(runtimes[2].IsEnrolled);
            Assert.Empty((await UsersAsync(aWebSetup)).Users);
            Assert.Empty((await UsersAsync(bWebSetup)).Users);

            // ── Case 3: ServerA/WEB + Client01 ─────────────────────
            await EnrollmentHelper.EnrollAsync(runtimes[1]);
            Assert.True(runtimes[1].IsEnrolled);
            Assert.False(runtimes[2].IsEnrolled);
            Assert.Empty((await UsersAsync(bWebSetup)).Users);

            // ── Case 4: ServerB/WEB + Client01 ─────────────────────
            await EnrollmentHelper.EnrollAsync(runtimes[2]);
            Assert.True(runtimes[2].IsEnrolled);

            // ── Case 5: three independent enrollments ──────────────
            var aRdpUsers = await UsersAsync(aRdpSetup);
            var aWebUsers = await UsersAsync(aWebSetup);
            var bWebUsers = await UsersAsync(bWebSetup);
            Assert.Single(aRdpUsers.Users);
            Assert.Single(aWebUsers.Users);
            Assert.Single(bWebUsers.Users);
            Assert.Equal(3, new[] { aRdpUsers, aWebUsers, bWebUsers }
                .Select(u => u.Users[0].ClientPublicKeyFingerprint).Distinct().Count());

            // §8: each OTT was consumed only by its own connection.
            foreach (var setup in new[] { aRdpSetup, aWebSetup, bWebSetup })
            {
                var cfg = await ServiceConfigStore.LoadAsync(setup.ServerConfigPath);
                Assert.DoesNotContain(cfg.PendingOneTimeTokens,
                    p => p.OneTimeTokenHash == setup.OneTimeTokenHash);
            }

            // ── Case 6: restart ServerA/WEB ────────────────────────
            await aWebHost.DisposeAsync();
            aWebHost = null;
            await Task.Delay(200);
            aWebHost = await StartAsync(aWebSetup);

            foreach (var (cfg, runtime) in configs.Zip(runtimes))
            {
                var reloaded = await ClientRuntime.LoadOrCreateAsync(runtime.ConnectionDirectory, cfg);
                Assert.True(reloaded.IsEnrolled, $"{reloaded.ConnectionId} lost its enrollment across restart.");
            }

            // The restarted service still authenticates the same client
            // through the future-authorization path (no re-enrollment).
            var reWeb = await ClientRuntime.LoadOrCreateAsync(runtimes[1].ConnectionDirectory, aWebCfg);
            var (tcp, sessionKey) = await new ClientProtocol(reWeb).ConnectAndAuthenticateAsync();
            Assert.Equal(32, sessionKey.Length);
            tcp.Dispose();

            // ── Case 2 + Case 7: a second client on ServerA/RDP ────
            var client02Ott = await ProvisionAdditionalClientAsync(aRdpSetup, "Client02");
            var client02Cfg = aRdpCfg.Clone();
            client02Cfg.ClientName = "Client02";
            client02Cfg.OneTimeToken = client02Ott;

            var client02Dir = NewTempDir("ssp-matrix-client02-");
            try
            {
                // §7, canonical-root semantics: the connection state is
                // machine-wide per ConnectionId
                // (C:\Program Files\SSP\connections\{ConnectionId}), so a
                // second executable of the SAME connection on the SAME
                // machine - even from a different folder - resolves to
                // the SAME directory and reuses the existing identity
                // instead of enrolling a second one.
                var client02ConnDir = ClientServiceBundle.ConnectionDirectory(client02Dir, client02Cfg);
                Assert.Equal(runtimes[0].ConnectionDirectory, client02ConnDir);

                var client02Runtime = await ClientRuntime.LoadOrCreateAsync(
                    client02ConnDir, client02Cfg);

                // Same connection id, a different client name: the same
                // shared identity, already enrolled - no re-enrollment.
                Assert.Equal(runtimes[0].ConnectionId, client02Runtime.ConnectionId);
                Assert.True(client02Runtime.IsEnrolled);
                Assert.Equal(
                    runtimes[0].ClientPublicKeyFingerprint,
                    client02Runtime.ClientPublicKeyFingerprint);

                // §15: Client01 on ServerA/RDP survived and remains the
                // single authorised user of this connection.
                var client02ArdpUsers = (await UsersAsync(aRdpSetup)).Users;
                Assert.Single(client02ArdpUsers);
                Assert.Equal(
                    runtimes[0].ClientPublicKeyFingerprint,
                    client02ArdpUsers[0].ClientPublicKeyFingerprint);

                // §7/Case 7: WEB connections untouched.
                Assert.Single((await UsersAsync(aWebSetup)).Users);
                Assert.Single((await UsersAsync(bWebSetup)).Users);
                Assert.True((await ClientRuntime.LoadOrCreateAsync(runtimes[1].ConnectionDirectory, aWebCfg)).IsEnrolled);
                Assert.True((await ClientRuntime.LoadOrCreateAsync(runtimes[2].ConnectionDirectory, bWebCfg)).IsEnrolled);
            }
            finally { Delete(client02Dir); }
        }
        finally
        {
            if (aRdpHost != null) await aRdpHost.DisposeAsync();
            if (aWebHost != null) await aWebHost.DisposeAsync();
            if (bWebHost != null) await bWebHost.DisposeAsync();
            Delete(exeDir);
            Delete(root);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Negative security tests (§17)
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// An OTT issued for ServerA/RDP must not enroll against ServerA/WEB,
    /// and an OTT issued for ServerA/WEB must not enroll against
    /// ServerB/WEB - even though the client name is identical.
    /// </summary>
    [Fact(Timeout = 120000)]
    public async Task Ott_IsBoundToItsOwnServerAndService()
    {
        var ottARdp = TokenGenerator.GenerateOneTimeToken();
        var ottAWeb = TokenGenerator.GenerateOneTimeToken();
        var ottBWeb = TokenGenerator.GenerateOneTimeToken();

        await using var aRdp = await SspTestHarness.CreateWithExplicitTokenAsync(ottARdp, "RDP");
        await using var aWeb = await SspTestHarness.CreateWithExplicitTokenAsync(ottAWeb, "WEB");
        await using var bWeb = await SspTestHarness.CreateWithExplicitTokenAsync(ottBWeb, "WEB");

        // Isolated canonical connection root (identities are
        // machine-wide per ConnectionId).
        using var clientRoot = new ClientConnectionRootScope();
        var dir = NewTempDir("ssp-ott-neg-");
        try
        {
            // ServerA/RDP's token presented to ServerA/WEB.
            var wrong1 = await RuntimeFor(bundleDir: dir, harness: aWeb, ott: ottARdp, tag: "a");
            await Assert.ThrowsAnyAsync<Exception>(() => EnrollmentHelper.EnrollAsync(wrong1));
            Assert.Empty((await UsersAsync(aWeb)).Users);

            // ServerA/WEB's token presented to ServerB/WEB (same service
            // name, different server).
            var wrong2 = await RuntimeFor(bundleDir: dir, harness: bWeb, ott: ottAWeb, tag: "b");
            await Assert.ThrowsAnyAsync<Exception>(() => EnrollmentHelper.EnrollAsync(wrong2));
            Assert.Empty((await UsersAsync(bWeb)).Users);

            // ... and the legitimate tokens still work afterwards.
            var right = await RuntimeFor(bundleDir: dir, harness: aWeb, ott: ottAWeb, tag: "c");
            await EnrollmentHelper.EnrollAsync(right);
            Assert.Single((await UsersAsync(aWeb)).Users);
        }
        finally { Delete(dir); }
    }

    /// <summary>
    /// The server public key of one connection must never silently
    /// authenticate another connection: pointing a client that carries
    /// ServerA/WEB's key at ServerA/RDP's endpoint must fail.
    /// </summary>
    [Fact(Timeout = 60000)]
    public async Task ServerPublicKey_OfAnotherConnection_DoesNotAuthenticate()
    {
        var ottRdp = TokenGenerator.GenerateOneTimeToken();
        var ottWeb = TokenGenerator.GenerateOneTimeToken();
        await using var rdp = await SspTestHarness.CreateWithExplicitTokenAsync(ottRdp, "RDP");
        await using var web = await SspTestHarness.CreateWithExplicitTokenAsync(ottWeb, "WEB");

        // Isolated canonical connection root (identities are
        // machine-wide per ConnectionId).
        using var clientRoot = new ClientConnectionRootScope();
        var dir = NewTempDir("ssp-key-neg-");
        try
        {
            var mismatched = new ClientConfig
            {
                ApplicationName        = "RDP",
                ServerPublicKeyPem     = web.ServerPublicKeyPem,   // wrong connection's key
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = rdp.GatewayPort,          // ... pointed at RDP
                LocalApplicationPort   = rdp.LocalAppPort,
                ClientTunnelPort       = rdp.ClientTunnelPort,
                OneTimeToken           = ottRdp,
                ClientName             = "Client01",
            };

            var runtime = await ClientRuntime.LoadOrCreateAsync(
                ClientServiceBundle.ConnectionDirectory(dir, mismatched), mismatched);

            await Assert.ThrowsAnyAsync<Exception>(() => EnrollmentHelper.EnrollAsync(runtime));
            Assert.Empty((await UsersAsync(rdp)).Users);
        }
        finally { Delete(dir); }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    private static ClientConfig Cfg(string app, string serverPem, int gatewayPort, string clientName) => new()
    {
        ApplicationName        = app,
        ServerPublicKeyPem     = serverPem,
        ServerFingerprint      = RsaCrypto.ComputePublicKeyFingerprintFromPem(serverPem),
        GatewayPublicIpAddress = "1.1.1.2",
        GatewayPort            = gatewayPort,
        LocalApplicationPort   = 1,
        ClientTunnelPort       = 2,
        ClientName             = clientName,
    };

    private static async Task<ClientRuntime> RuntimeFor(
        string bundleDir, SspTestHarness harness, string ott, string tag)
    {
        var cfg = new ClientConfig
        {
            ApplicationName        = harness.Config.ApplicationName,
            ServerPublicKeyPem     = harness.ServerPublicKeyPem,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = harness.GatewayPort,
            LocalApplicationPort   = harness.LocalAppPort,
            ClientTunnelPort       = harness.ClientTunnelPort,
            OneTimeToken           = ott,
            ClientName             = "Client01",
        };

        // The connection identity is machine-wide per ConnectionId
        // (canonical connections root), so the folder (tag) no longer
        // changes WHICH identity a connection uses - the connection id
        // itself (Server + Service) does.
        var dir = Path.Combine(bundleDir, tag);
        Directory.CreateDirectory(dir);
        return await ClientRuntime.LoadOrCreateAsync(
            ClientServiceBundle.ConnectionDirectory(dir, cfg), cfg);
    }

    private static async Task<SetupResult> SetupAsync(string servicesRoot, string app, string clientName)
    {
        var engine = new SetupEngine(UnlicensedTestGate.Instance);
        await engine.RunAsync(new SetupParameters
        {
            ApplicationName        = app,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = FreePort(),
            LocalApplicationPort   = FreePort(),
            ClientTunnelPort       = FreePort(),
            ServiceDirectory       = Path.Combine(servicesRoot, app),
            InstallWindowsService  = false,
            ClientName             = clientName,
        });
        Assert.True(engine.Result.Success);
        return engine.Result;
    }

    private static async Task<string> ProvisionAdditionalClientAsync(SetupResult existing, string clientName)
    {
        var engine = new SetupEngine(UnlicensedTestGate.Instance);
        await engine.RunAsync(new SetupParameters
        {
            ApplicationName       = Path.GetFileName(existing.ServiceDirectory),
            ServiceDirectory      = existing.ServiceDirectory,
            ClientName            = clientName,
            InstallWindowsService = false,
        });
        Assert.True(engine.Result.Success);
        Assert.True(engine.Result.IsAdditionalClient);
        return engine.Result.OneTimeToken;
    }

    private static async Task<SspTestHarness> StartAsync(SetupResult setup)
    {
        var config = await ServiceConfigStore.LoadAsync(setup.ServerConfigPath);
        var privPem = await PemStore.LoadPrivateKeyAsync(setup.ServerPrivateKeyPath);
        var pubPem = await PemStore.LoadPublicKeyAsync(setup.ServerPublicKeyPath);
        return await SspTestHarness.CreateFromExistingConfigAsync(
            setup.ServiceDirectory, config, privPem, pubPem);
    }

    private static ClientConfig PatchedConfig(SetupResult setup) =>
        ClientTemplate.ReadPatchSlot(File.ReadAllBytes(setup.ClientExecutablePath));

    private static Task<AuthorisedUsersFile> UsersAsync(SetupResult setup) =>
        AuthorisedUsersStore.LoadAsync(setup.AuthorisedUsersPath);

    private static Task<AuthorisedUsersFile> UsersAsync(SspTestHarness harness) =>
        AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));

    private static string NewTempDir(string prefix)
    {
        var dir = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void Delete(string dir)
    {
        try { Directory.Delete(dir, true); } catch { }
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}

internal static class ClientConfigCloneExtensions
{
    /// <summary>Shallow copy used by tests to derive a second client of
    /// the SAME connection (Server + Service).</summary>
    public static ClientConfig Clone(this ClientConfig c) => new()
    {
        ApplicationName        = c.ApplicationName,
        ServerPublicKeyPem     = c.ServerPublicKeyPem,
        ServerFingerprint      = c.ServerFingerprint,
        GatewayPublicIpAddress = c.GatewayPublicIpAddress,
        GatewayPort            = c.GatewayPort,
        LocalApplicationPort   = c.LocalApplicationPort,
        ClientTunnelPort       = c.ClientTunnelPort,
        AutoLaunchApplication  = c.AutoLaunchApplication,
        OneTimeToken           = c.OneTimeToken,
        ClientName             = c.ClientName,
    };
}
