// File: tests/SSP.Tests/OneClientMultiServiceTests.cs
//
// One client process, three independent services: separate identity,
// OTT, enrollment, session key, and TCP tunnel. No multiplexing.

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Util;
using SSP.Server.Setup;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class OneClientMultiServiceTests
{
    [Fact]
    public async Task Bundle_WhenMissing_UsesPatchedConfigOnly()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-bundle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var patched = new ClientConfig { ApplicationName = "RDP", GatewayPort = 4433 };
            // No executable was provisioned, so there is no embedded
            // client_services.json to read.
            var resolved = await ClientServiceBundle.ResolveAsync(dir, patched, embeddedServicesJson: null);
            Assert.Single(resolved);
            Assert.Equal("RDP", resolved[0].ApplicationName);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public async Task Bundle_WhenPresent_IsSourceOfTruth()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-bundle2-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var patched = new ClientConfig { ApplicationName = "RDP", GatewayPort = 1 };
            var exePath = Path.Combine(dir, "SSP.Client.RDP.Client01.exe");
            await SetupEngine.BuildPatchedClientAsync(exePath, patched);
            await SetupEngine.WriteClientServiceBundleAsync(dir, new[]
            {
                new ClientConfig { ApplicationName = "RDP", GatewayPort = 4433, ClientTunnelPort = 3390 },
                new ClientConfig { ApplicationName = "WEB", GatewayPort = 4480, ClientTunnelPort = 8181 },
                new ClientConfig { ApplicationName = "SQL", GatewayPort = 4490, ClientTunnelPort = 14330 },
            });

            // The bundle travels inside the executable - no sidecar file.
            Assert.False(File.Exists(Path.Combine(dir, "client_services.json")));

            var resolved = await ClientServiceBundle.ResolveAsync(dir, patched, File.ReadAllBytes(exePath));
            Assert.Equal(3, resolved.Count);
            Assert.Equal(new[] { "RDP", "WEB", "SQL" }, resolved.Select(c => c.ApplicationName).ToArray());
            Assert.Equal(4480, resolved[1].GatewayPort);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public async Task Bundle_LaunchedWebSlot_IsFirstAndAuthoritative()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-bundle-web-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using var rdpKey = RsaCrypto.GenerateKeyPair();
            using var webKey = RsaCrypto.GenerateKeyPair();
            var rdpPem = RsaCrypto.ExportPublicKeyPem(rdpKey);
            var webPem = RsaCrypto.ExportPublicKeyPem(webKey);

            var launchedExe = Path.Combine(dir, "SSP.Client.WEB.Web-C1.exe");
            var launchedWeb = new ClientConfig
            {
                ApplicationName = "WEB",
                ServerPublicKeyPem = webPem,
                ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(webPem),
                GatewayPublicIpAddress = "1.1.1.2",
                GatewayPort = 4480,
                OneTimeToken = "fresh-web-ott",
                ClientName = "Web-C1",
            };
            await SetupEngine.BuildPatchedClientAsync(launchedExe, launchedWeb);

            await SetupEngine.WriteClientServiceBundleAsync(dir, new[]
            {
                new ClientConfig
                {
                    ApplicationName = "RDP",
                    ServerPublicKeyPem = rdpPem,
                    ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(rdpPem),
                    GatewayPublicIpAddress = "1.1.1.2",
                    GatewayPort = 4433,
                    OneTimeToken = "rdp-ott",
                },
                new ClientConfig
                {
                    ApplicationName = "WEB",
                    ServerPublicKeyPem = webPem,
                    ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(webPem),
                    GatewayPublicIpAddress = "1.1.1.2",
                    GatewayPort = 4480,
                    OneTimeToken = "stale-web-ott",
                },
            });

            var resolved = await ClientServiceBundle.ResolveAsync(dir, launchedWeb, File.ReadAllBytes(launchedExe));
            Assert.Equal(2, resolved.Count);
            Assert.Equal("WEB", resolved[0].ApplicationName);
            Assert.Equal(4480, resolved[0].GatewayPort);
            Assert.Equal("fresh-web-ott", resolved[0].OneTimeToken);
            Assert.Equal("1.1.1.2", resolved[0].GatewayPublicIpAddress);
            Assert.Equal("RDP", resolved[1].ApplicationName);
            Assert.Equal("rdp-ott", resolved[1].OneTimeToken);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public void IdentityDirectory_MultiService_IsPerApplication()
    {
        var exe = "/opt/ssp";
        var rdp = new ClientConfig { ApplicationName = "RDP" };
        var web = new ClientConfig { ApplicationName = "WEB" };
        Assert.Equal(exe, ClientServiceBundle.IdentityDirectory(exe, rdp, 1));
        Assert.NotEqual(
            ClientServiceBundle.IdentityDirectory(exe, rdp, 3),
            ClientServiceBundle.IdentityDirectory(exe, web, 3));
        Assert.Contains("RDP", ClientServiceBundle.IdentityDirectory(exe, rdp, 3));
        Assert.Contains("WEB", ClientServiceBundle.IdentityDirectory(exe, web, 3));
    }

    [Fact]
    public async Task MultiService_IdentitiesAreIndependent()
    {
        var exeDir = Path.Combine(Path.GetTempPath(), "ssp-ids-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(exeDir);
        try
        {
            var configs = new[]
            {
                new ClientConfig { ApplicationName = "RDP", GatewayPort = 1, ClientTunnelPort = 2, LocalApplicationPort = 3, GatewayPublicIpAddress = "127.0.0.1" },
                new ClientConfig { ApplicationName = "WEB", GatewayPort = 4, ClientTunnelPort = 5, LocalApplicationPort = 6, GatewayPublicIpAddress = "127.0.0.1" },
            };

            var rt1 = await ClientRuntime.LoadOrCreateAsync(
                ClientServiceBundle.IdentityDirectory(exeDir, configs[0], 2), configs[0]);
            var rt2 = await ClientRuntime.LoadOrCreateAsync(
                ClientServiceBundle.IdentityDirectory(exeDir, configs[1], 2), configs[1]);

            Assert.False(rt1.IsEnrolled);
            Assert.False(rt2.IsEnrolled);
            Assert.NotEqual(rt1.ClientPublicKeyFingerprint, rt2.ClientPublicKeyFingerprint);
            Assert.True(File.Exists(Path.Combine(exeDir, "runtime", "RDP", ".cache.dat")));
            Assert.True(File.Exists(Path.Combine(exeDir, "runtime", "WEB", ".cache.dat")));
            Assert.False(File.Exists(Path.Combine(exeDir, ".cache.dat")));
        }
        finally
        {
            try { Directory.Delete(exeDir, true); } catch { }
        }
    }

    [Fact(Timeout = 60000)]
    public async Task OneProcess_ThreeServices_IndependentTunnelsAndEnrollment()
    {
        var ottRdp = TokenGenerator.GenerateOneTimeToken();
        var ottWeb = TokenGenerator.GenerateOneTimeToken();
        var ottSql = TokenGenerator.GenerateOneTimeToken();

        await using var rdp = await SspTestHarness.CreateWithExplicitTokenAsync(ottRdp, "RDP");
        await using var web = await SspTestHarness.CreateWithExplicitTokenAsync(ottWeb, "WEB");
        await using var sql = await SspTestHarness.CreateWithExplicitTokenAsync(ottSql, "SQL");

        var exeDir = Path.Combine(Path.GetTempPath(), "ssp-oneclient-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(exeDir);

        try
        {
            var specs = new[]
            {
                (Harness: rdp, Ott: ottRdp, Marker: "RDP-PAYLOAD"),
                (Harness: web, Ott: ottWeb, Marker: "WEB-PAYLOAD"),
                (Harness: sql, Ott: ottSql, Marker: "SQL-PAYLOAD"),
            };

            var runtimes = new List<ClientRuntime>();
            foreach (var s in specs)
            {
                var cfg = new ClientConfig
                {
                    ApplicationName = s.Harness.Config.ApplicationName,
                    ServerPublicKeyPem = s.Harness.ServerPublicKeyPem,
                    GatewayPublicIpAddress = "127.0.0.1",
                    GatewayPort = s.Harness.GatewayPort,
                    LocalApplicationPort = s.Harness.LocalAppPort,
                    ClientTunnelPort = s.Harness.ClientTunnelPort,
                    OneTimeToken = s.Ott,
                };
                var idDir = ClientServiceBundle.IdentityDirectory(exeDir, cfg, specs.Length);
                Directory.CreateDirectory(idDir);
                runtimes.Add(await ClientRuntime.LoadOrCreateAsync(idDir, cfg));
            }

            Assert.Equal(3, runtimes.Select(r => r.ClientPublicKeyFingerprint).Distinct().Count());

            await EnrollmentHelper.EnrollAsync(runtimes[0]);
            Assert.True(runtimes[0].IsEnrolled);
            Assert.False(runtimes[1].IsEnrolled);
            Assert.False(runtimes[2].IsEnrolled);

            var webUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(web.ServiceDir, ".index.dat"));
            Assert.Empty(webUsers.Users);

            await EnrollmentHelper.EnrollAsync(runtimes[1]);
            await EnrollmentHelper.EnrollAsync(runtimes[2]);

            var rdpUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(rdp.ServiceDir, ".index.dat"));
            webUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(web.ServiceDir, ".index.dat"));
            var sqlUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(sql.ServiceDir, ".index.dat"));
            Assert.Single(rdpUsers.Users);
            Assert.Single(webUsers.Users);
            Assert.Single(sqlUsers.Users);
            Assert.NotEqual(rdpUsers.Users[0].ClientPublicKeyFingerprint, webUsers.Users[0].ClientPublicKeyFingerprint);
            Assert.NotEqual(webUsers.Users[0].ClientPublicKeyFingerprint, sqlUsers.Users[0].ClientPublicKeyFingerprint);

            foreach (var s in specs)
                StartEcho(s.Harness);

            using var cts = new CancellationTokenSource();
            var host = new ClientSessionHost(runtimes);
            var hostTask = Task.Run(() => host.RunAsync(cts.Token));

            foreach (var rt in runtimes)
            {
                var ok = false;
                for (var i = 0; i < 200 && !ok; i++)
                {
                    ok = IsPortListening(rt.Config.ClientTunnelPort);
                    if (!ok) await Task.Delay(25);
                }
                Assert.True(ok, $"{rt.Config.ApplicationName} tunnel not listening");
            }

            foreach (var s in specs)
            {
                var echoed = await EchoOnceAsync(s.Harness.ClientTunnelPort, s.Marker);
                Assert.Equal(s.Marker, echoed);
            }

            await web.DisposeAsync();

            var rdpEcho = await EchoOnceAsync(rdp.ClientTunnelPort, "RDP-AFTER-WEB-DOWN");
            Assert.Equal("RDP-AFTER-WEB-DOWN", rdpEcho);
            var sqlEcho = await EchoOnceAsync(sql.ClientTunnelPort, "SQL-AFTER-WEB-DOWN");
            Assert.Equal("SQL-AFTER-WEB-DOWN", sqlEcho);

            cts.Cancel();
            await Task.WhenAny(hostTask, Task.Delay(3000));
        }
        finally
        {
            try { Directory.Delete(exeDir, true); } catch { }
        }
    }

    [Fact]
    public async Task Setup_EmbedsClientServicesJson_InClientExecutable()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "ssp-json1-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseDir);
        try
        {
            var engine = new SetupEngine();
            await engine.RunAsync(new SetupParameters
            {
                ApplicationName = "RDP",
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort = FreePort(),
                LocalApplicationPort = FreePort(),
                ClientTunnelPort = FreePort(),
                ServiceDirectory = baseDir,
                InstallWindowsService = false,
                ClientName = "Client01",
            });

            var clientDir = Path.GetDirectoryName(engine.Result.ClientExecutablePath)!;
            // The bundle is embedded in the EXE; no sidecar file is written.
            Assert.False(File.Exists(Path.Combine(clientDir, "client_services.json")));

            var clientBytes = await File.ReadAllBytesAsync(engine.Result.ClientExecutablePath);
            var bundle = ClientServiceBundle.LoadEmbedded(clientBytes)
                         ?? throw new InvalidOperationException("No embedded service bundle.");
            Assert.Single(bundle.Services);
            Assert.Equal("RDP", bundle.Services[0].ApplicationName);
            Assert.Equal("Client01", bundle.Services[0].ClientName);
            Assert.Equal(engine.Result.OneTimeToken, bundle.Services[0].OneTimeToken);

            var patched = ClientTemplate.ReadPatchSlot(clientBytes);
            var resolved = await ClientServiceBundle.ResolveAsync(clientDir, patched, clientBytes);
            Assert.Single(resolved);
        }
        finally
        {
            try { Directory.Delete(baseDir, true); } catch { }
        }
    }

    [Fact]
    public async Task Setup_SameClientName_UnderServicesRoot_MergesBundle()
    {
        var root = Path.Combine(Path.GetTempPath(), "ssp-merge-" + Guid.NewGuid().ToString("N"));
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);
        try
        {
            var rdp = await SetupAppAsync(servicesRoot, "RDP", "Client01");
            var web = await SetupAppAsync(servicesRoot, "WEB", "Client01");
            var sql = await SetupAppAsync(servicesRoot, "SQL", "Client01");

            Assert.NotEqual(rdp.OneTimeToken, web.OneTimeToken);
            Assert.NotEqual(web.OneTimeToken, sql.OneTimeToken);

            foreach (var result in new[] { rdp, web, sql })
            {
                var clientDir = Path.GetDirectoryName(result.ClientExecutablePath)!;
                Assert.False(File.Exists(Path.Combine(clientDir, "client_services.json")));
                var clientBytes = await File.ReadAllBytesAsync(result.ClientExecutablePath);
                var bundle = ClientServiceBundle.LoadEmbedded(clientBytes)
                             ?? throw new InvalidOperationException("No embedded service bundle.");
                Assert.Equal(3, bundle.Services.Count);
                Assert.Equal(new[] { "RDP", "WEB", "SQL" }, bundle.Services.Select(s => s.ApplicationName).ToArray());
                Assert.Equal(3, bundle.Services.Select(s => s.OneTimeToken).Distinct().Count());
                Assert.Equal(3, bundle.Services.Select(s => s.GatewayPort).Distinct().Count());
                Assert.Equal(3, bundle.Services.Select(s => s.ClientTunnelPort).Distinct().Count());
                Assert.All(bundle.Services, s => Assert.Equal("Client01", s.ClientName));

                var patched = ClientTemplate.ReadPatchSlot(clientBytes);
                var resolved = await ClientServiceBundle.ResolveAsync(clientDir, patched, clientBytes);
                Assert.Equal(3, resolved.Count);
            }
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    [Fact]
    public async Task Setup_DifferentClientName_DoesNotMergeIntoOtherClient()
    {
        var root = Path.Combine(Path.GetTempPath(), "ssp-c2-" + Guid.NewGuid().ToString("N"));
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);
        try
        {
            var client01 = await SetupAppAsync(servicesRoot, "RDP", "Client01");
            var client02Engine = new SetupEngine();
            await client02Engine.RunAsync(new SetupParameters
            {
                ApplicationName = "RDP",
                ServiceDirectory = Path.Combine(servicesRoot, "RDP"),
                InstallWindowsService = false,
                ClientName = "Client02",
            });
            await SetupAppAsync(servicesRoot, "WEB", "Client01");

            var c01 = ClientServiceBundle.LoadEmbedded(client01.ClientExecutablePath)
                      ?? throw new InvalidOperationException("Client01 has no embedded service bundle.");
            var c02 = ClientServiceBundle.LoadEmbedded(client02Engine.Result.ClientExecutablePath)
                      ?? throw new InvalidOperationException("Client02 has no embedded service bundle.");

            Assert.Equal(2, c01.Services.Count);
            Assert.Equal(new[] { "RDP", "WEB" }, c01.Services.Select(s => s.ApplicationName).ToArray());
            Assert.All(c01.Services, s => Assert.Equal("Client01", s.ClientName));

            Assert.Single(c02.Services);
            Assert.Equal("RDP", c02.Services[0].ApplicationName);
            Assert.Equal("Client02", c02.Services[0].ClientName);
            Assert.NotEqual(c01.Services[0].OneTimeToken, c02.Services[0].OneTimeToken);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    [Fact]
    public async Task Resolve_SiblingExecutables_SameClientName_AreMerged()
    {
        var root = Path.Combine(Path.GetTempPath(), "ssp-sib-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var rdp = await SetupAppAsync(root, "RDP", "Client01");
            var web = await SetupAppAsync(root, "WEB", "Client01");

            var combined = Path.Combine(root, "combined");
            Directory.CreateDirectory(combined);
            File.Copy(rdp.ClientExecutablePath, Path.Combine(combined, Path.GetFileName(rdp.ClientExecutablePath)));
            File.Copy(web.ClientExecutablePath, Path.Combine(combined, Path.GetFileName(web.ClientExecutablePath)));

            var launchedBytes = await File.ReadAllBytesAsync(
                Path.Combine(combined, Path.GetFileName(rdp.ClientExecutablePath)));
            var patched = ClientTemplate.ReadPatchSlot(launchedBytes);
            var resolved = await ClientServiceBundle.ResolveAsync(combined, patched, launchedBytes);
            Assert.Equal(2, resolved.Count);
            Assert.Contains(resolved, s => s.ApplicationName == "RDP");
            Assert.Contains(resolved, s => s.ApplicationName == "WEB");
            Assert.NotEqual(
                resolved.Single(s => s.ApplicationName == "RDP").OneTimeToken,
                resolved.Single(s => s.ApplicationName == "WEB").OneTimeToken);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    [Fact]
    public void PrepareIdentityDirectory_MigratesOnlyLaunchedApplicationKeys()
    {
        // These configs carry no server identity, so their ConnectionId
        // (endpoint fallback tag) is the same for every such test run -
        // an isolated canonical connection root is mandatory here.
        using var clientRoot = new ClientConnectionRootScope();
        var exeDir = Path.Combine(Path.GetTempPath(), "ssp-mig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(exeDir);
        try
        {
            File.WriteAllText(Path.Combine(exeDir, "client_private_key.pem"), "priv");
            File.WriteAllText(Path.Combine(exeDir, "client_public_key.pem"), "pub");
            var rdp = new ClientConfig { ApplicationName = "RDP" };
            var web = new ClientConfig { ApplicationName = "WEB" };

            var destRdp = ClientServiceBundle.PrepareIdentityDirectory(exeDir, rdp, 2, rdp);
            var destWeb = ClientServiceBundle.PrepareIdentityDirectory(exeDir, web, 2, rdp);

            Assert.StartsWith(clientRoot.ProductRoot, Path.GetFullPath(destRdp));
            Assert.True(File.Exists(Path.Combine(destRdp, ".cache.dat")));
            Assert.True(File.Exists(Path.Combine(destRdp, ".index.dat")));
            Assert.False(File.Exists(Path.Combine(destWeb, ".cache.dat")));
            Assert.NotEqual(destRdp, destWeb);
        }
        finally
        {
            try { Directory.Delete(exeDir, true); } catch { }
        }
    }

    [Fact(Timeout = 120000)]
    public async Task SetupThenOneProcess_RdpWebSql_IndependentTunnelsAndEnrollment()
    {
        var root = Path.Combine(Path.GetTempPath(), "ssp-e2e-" + Guid.NewGuid().ToString("N"));
        // Isolated canonical connection root for this test (the
        // connection state no longer lives inside rdpClientDir).
        using var clientRoot = new ClientConnectionRootScope(root);
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);

        SspTestHarness? rdpHarness = null;
        SspTestHarness? webHarness = null;
        SspTestHarness? sqlHarness = null;
        try
        {
            var rdpSetup = await SetupAppAsync(servicesRoot, "RDP", "Client01");
            var webSetup = await SetupAppAsync(servicesRoot, "WEB", "Client01");
            var sqlSetup = await SetupAppAsync(servicesRoot, "SQL", "Client01");

            var rdpClientDir = Path.GetDirectoryName(rdpSetup.ClientExecutablePath)!;
            var rdpClientBytes = await File.ReadAllBytesAsync(rdpSetup.ClientExecutablePath);
            var patched = ClientTemplate.ReadPatchSlot(rdpClientBytes);
            var configs = await ClientServiceBundle.ResolveAsync(rdpClientDir, patched, rdpClientBytes);
            Assert.Equal(3, configs.Count);
            Assert.Equal(new[] { "RDP", "WEB", "SQL" }, configs.Select(c => c.ApplicationName).ToArray());
            Assert.Equal(3, configs.Select(c => c.OneTimeToken).Distinct().Count());
            Assert.Equal(3, configs.Select(c => c.GatewayPort).Distinct().Count());
            Assert.Equal(3, configs.Select(c => c.ClientTunnelPort).Distinct().Count());

            rdpHarness = await StartHarnessFromSetupAsync(rdpSetup);
            webHarness = await StartHarnessFromSetupAsync(webSetup);
            sqlHarness = await StartHarnessFromSetupAsync(sqlSetup);

            var runtimes = new List<ClientRuntime>();
            foreach (var cfg in configs)
            {
                var idDir = ClientServiceBundle.PrepareIdentityDirectory(rdpClientDir, cfg, configs.Count, patched);
                runtimes.Add(await ClientRuntime.LoadOrCreateAsync(idDir, cfg));
            }

            Assert.Equal(3, runtimes.Select(r => r.ClientPublicKeyFingerprint).Distinct().Count());
            Assert.All(runtimes, r => Assert.False(r.IsEnrolled));

            await EnrollmentHelper.EnrollAsync(runtimes[0]);
            Assert.True(runtimes[0].IsEnrolled);
            Assert.False(runtimes[1].IsEnrolled);
            Assert.False(runtimes[2].IsEnrolled);

            var webUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(webHarness.ServiceDir, ".index.dat"));
            Assert.Empty(webUsers.Users);

            await EnrollmentHelper.EnrollAsync(runtimes[1]);
            await EnrollmentHelper.EnrollAsync(runtimes[2]);

            var rdpUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(rdpHarness.ServiceDir, ".index.dat"));
            webUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(webHarness.ServiceDir, ".index.dat"));
            var sqlUsers = await AuthorisedUsersStore.LoadAsync(
                Path.Combine(sqlHarness.ServiceDir, ".index.dat"));
            Assert.Single(rdpUsers.Users);
            Assert.Single(webUsers.Users);
            Assert.Single(sqlUsers.Users);
            Assert.NotEqual(rdpUsers.Users[0].ClientPublicKeyFingerprint, webUsers.Users[0].ClientPublicKeyFingerprint);
            Assert.NotEqual(webUsers.Users[0].ClientPublicKeyFingerprint, sqlUsers.Users[0].ClientPublicKeyFingerprint);

            StartEcho(rdpHarness);
            StartEcho(webHarness);
            StartEcho(sqlHarness);

            using var cts = new CancellationTokenSource();
            var host = new ClientSessionHost(runtimes);
            var hostTask = Task.Run(() => host.RunAsync(cts.Token));

            foreach (var rt in runtimes)
            {
                var ok = false;
                for (var i = 0; i < 200 && !ok; i++)
                {
                    ok = IsPortListening(rt.Config.ClientTunnelPort);
                    if (!ok) await Task.Delay(25);
                }
                Assert.True(ok, $"{rt.Config.ApplicationName} tunnel not listening");
            }

            Assert.Equal("RDP-PAYLOAD", await EchoOnceAsync(runtimes[0].Config.ClientTunnelPort, "RDP-PAYLOAD"));
            Assert.Equal("WEB-PAYLOAD", await EchoOnceAsync(runtimes[1].Config.ClientTunnelPort, "WEB-PAYLOAD"));
            Assert.Equal("SQL-PAYLOAD", await EchoOnceAsync(runtimes[2].Config.ClientTunnelPort, "SQL-PAYLOAD"));

            await webHarness.DisposeAsync();
            webHarness = null;

            Assert.Equal("RDP-AFTER-WEB-DOWN", await EchoOnceAsync(runtimes[0].Config.ClientTunnelPort, "RDP-AFTER-WEB-DOWN"));
            Assert.Equal("SQL-AFTER-WEB-DOWN", await EchoOnceAsync(runtimes[2].Config.ClientTunnelPort, "SQL-AFTER-WEB-DOWN"));

            cts.Cancel();
            await Task.WhenAny(hostTask, Task.Delay(3000));
        }
        finally
        {
            if (webHarness != null) await webHarness.DisposeAsync();
            if (rdpHarness != null) await rdpHarness.DisposeAsync();
            if (sqlHarness != null) await sqlHarness.DisposeAsync();
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static async Task<SetupResult> SetupAppAsync(string parentDir, string appName, string clientName)
    {
        var engine = new SetupEngine();
        await engine.RunAsync(new SetupParameters
        {
            ApplicationName = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = FreePort(),
            LocalApplicationPort = FreePort(),
            ClientTunnelPort = FreePort(),
            ServiceDirectory = Path.Combine(parentDir, appName),
            InstallWindowsService = false,
            ClientName = clientName,
        });
        Assert.True(engine.Result.Success);
        return engine.Result;
    }

    private static async Task<SspTestHarness> StartHarnessFromSetupAsync(SetupResult setup)
    {
        var config = await ServiceConfigStore.LoadAsync(setup.ServerConfigPath);
        var privPem = await PemStore.LoadPrivateKeyAsync(setup.ServerPrivateKeyPath);
        var pubPem = await PemStore.LoadPublicKeyAsync(setup.ServerPublicKeyPath);
        return await SspTestHarness.CreateFromExistingConfigAsync(setup.ServiceDirectory, config, privPem, pubPem);
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static void StartEcho(SspTestHarness harness)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    TcpClient client;
                    try { client = await harness.AcceptFakeAppClientAsync(); }
                    catch { break; }
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await using var s = client.GetStream();
                            var buffer = new byte[4096];
                            int read;
                            while ((read = await s.ReadAsync(buffer.AsMemory(0, buffer.Length))) > 0)
                            {
                                await s.WriteAsync(buffer.AsMemory(0, read));
                                await s.FlushAsync();
                            }
                        }
                        catch { }
                    });
                }
            }
            catch { }
        });
    }

    private static async Task<string> EchoOnceAsync(int tunnelPort, string payload)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, tunnelPort);
        await using var stream = client.GetStream();
        var bytes = Encoding.UTF8.GetBytes(payload);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
        var buf = new byte[bytes.Length];
        var offset = 0;
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (offset < buf.Length && DateTime.UtcNow < deadline)
        {
            var n = await stream.ReadAsync(buf.AsMemory(offset, buf.Length - offset));
            if (n == 0) break;
            offset += n;
        }
        return Encoding.UTF8.GetString(buf, 0, offset);
    }

    private static bool IsPortListening(int port) =>
        IPGlobalProperties.GetIPGlobalProperties()
            .GetActiveTcpListeners()
            .Any(e => e.Port == port);
}
