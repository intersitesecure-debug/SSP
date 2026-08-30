// File: tests/SSP.Tests/MultiServiceEnrollmentAcceptanceTests.cs
//
// Acceptance regression tests for the multi-service enrollment scenario:
//
//   one server, one physical client installation, RDP first then Web:
//
//     RDP  -> gateway <ip>:4433-ish   client RDP-C1   enrolled, working tunnel
//     Web  -> gateway <ip>:4480-ish   client Web-C1   MUST independently reach
//                                             "Enrollment required ... Enter
//                                             Authentication Code:" and enroll,
//                                             without disturbing RDP.
//
// The production startup path is used throughout (ClientProtocol.
// EnsureEnrolledAsync - the exact method the generated client executable
// calls from ClientTunnelRuntime.RunAsync), including its console output,
// because the reported field failure (SocketException 10060 at
// EnsureEnrolledAsync) happened on that path.
//
// These tests also pin the failure SIGNATURE of an unreachable gateway:
// a TCP connect failure happens before any protocol message and is
// unrelated to enrollment state - it means the network path to the
// gateway endpoint (firewall / NAT / port forwarding) is closed.

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
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

public class MultiServiceEnrollmentAcceptanceTests
{
    /// <summary>
    /// The exact reported sequence:
    ///
    ///   1. RDP provisioned + gateway running + RDP-C1 enrolled.
    ///   2. Web provisioned afterwards (RDP gateway keeps running - no
    ///      restart of anything), Web service starts.
    ///   3. Same client installation launches Web-C1: it MUST still be
    ///      un-enrolled, ask for the Authentication Code against the WEB
    ///      gateway endpoint, enroll, and leave RDP untouched.
    ///   4. Both tunnels carry traffic, from one process.
    ///
    /// If the WEB connection had dialed the RDP endpoint (or reused RDP
    /// enrollment), step 3 would fail: the WEB OTT is rejected by the RDP
    /// service and the RDP server key cannot sign for the WEB connection.
    /// </summary>
    [Fact(Timeout = 180000)]
    public async Task RdpFirstThenWeb_SameInstallation_IndependentEnrollmentAndTunnels()
    {
        var root = NewTempDir("ssp-accept-");
        // Isolated canonical connection root for this test (the
        // connection state no longer lives inside exeDir).
        using var clientRoot = new ClientConnectionRootScope(root);
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);

        var exeDir = NewTempDir("ssp-accept-client-");

        SspTestHarness? rdpHarness = null;
        SspTestHarness? webHarness = null;
        try
        {
            // ── 1. RDP service + gateway running + RDP-C1 enrolled ──
            var rdpSetup = await SetupAppAsync(servicesRoot, "RDP", "RDP-C1");
            rdpHarness = await StartGatewayAsync(rdpSetup);

            var rdpCfg = PatchedConfig(rdpSetup);
            await AssertEmbeddedConfigAsync(rdpSetup, rdpCfg, "RDP", "RDP-C1");

            // Each generated client folder resolves to exactly its own
            // single connection (the C:\2 behaviour of the report).
            var rdpClientDir = Path.GetDirectoryName(rdpSetup.ClientExecutablePath)!;
            var resolvedRdp = await ClientServiceBundle.ResolveAsync(
                rdpClientDir, rdpCfg, File.ReadAllBytes(rdpSetup.ClientExecutablePath));
            Assert.Single(resolvedRdp);
            Assert.Equal("RDP", resolvedRdp[0].ApplicationName);

            var rdpRuntime = await ClientRuntime.LoadOrCreateAsync(
                ClientServiceBundle.ConnectionDirectory(exeDir, rdpCfg), rdpCfg);
            Assert.False(rdpRuntime.IsEnrolled);

            var rdpOut = new StringWriter();
            await EnrollViaStartupPathAsync(rdpRuntime, rdpOut);
            Assert.True(rdpRuntime.IsEnrolled);

            var rdpText = rdpOut.ToString();
            Assert.Contains("Connecting to server...", rdpText);
            Assert.Contains("Enrollment required for connection RDP-", rdpText);
            Assert.Contains($"(RDP @ 127.0.0.1:{rdpHarness.GatewayPort}).", rdpText);
            Assert.Contains("Enter Authentication Code:", rdpText);
            Assert.Contains("Enrollment completed successfully.", rdpText);
            Assert.Contains("Enrollment successful.", rdpText);

            // ── 2. Web provisioned while the RDP gateway keeps running ──
            var webSetup = await SetupAppAsync(servicesRoot, "Web", "Web-C1");
            webHarness = await StartGatewayAsync(webSetup);

            // Provisioning Web must not have touched the RDP service state.
            var rdpSvc = await ServiceConfigStore.LoadAsync(rdpSetup.ServerConfigPath);
            Assert.DoesNotContain(rdpSvc.PendingOneTimeTokens,
                p => TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, rdpSetup.OneTimeTokenHash));
            Assert.Single((await UsersAsync(rdpSetup)).Users);

            var webCfg = PatchedConfig(webSetup);
            await AssertEmbeddedConfigAsync(webSetup, webCfg, "Web", "Web-C1");

            // The two embedded configurations are fully independent.
            Assert.NotEqual(rdpCfg.ServerPublicKeyPem, webCfg.ServerPublicKeyPem);
            Assert.NotEqual(rdpCfg.ServerFingerprint, webCfg.ServerFingerprint);
            Assert.NotEqual(rdpCfg.OneTimeToken, webCfg.OneTimeToken);
            Assert.NotEqual(rdpCfg.GatewayPort, webCfg.GatewayPort);
            Assert.NotEqual(ConnectionIdentity.ConnectionId(rdpCfg), ConnectionIdentity.ConnectionId(webCfg));

            // The Web client folder resolves to exactly the WEB connection
            // (the C:\1 behaviour of the report).
            var webClientDir = Path.GetDirectoryName(webSetup.ClientExecutablePath)!;
            var resolvedWeb = await ClientServiceBundle.ResolveAsync(
                webClientDir, webCfg, File.ReadAllBytes(webSetup.ClientExecutablePath));
            Assert.Single(resolvedWeb);
            Assert.Equal("Web", resolvedWeb[0].ApplicationName);
            Assert.Equal(webCfg.GatewayPort, resolvedWeb[0].GatewayPort);

            // ── 3. Same installation: RDP enrolled does NOT enroll Web ──
            var webRuntime = await ClientRuntime.LoadOrCreateAsync(
                ClientServiceBundle.ConnectionDirectory(exeDir, webCfg), webCfg);
            Assert.False(webRuntime.IsEnrolled);
            Assert.NotEqual(rdpRuntime.ClientPublicKeyFingerprint, webRuntime.ClientPublicKeyFingerprint);
            Assert.Empty((await UsersAsync(webSetup)).Users);

            var webOut = new StringWriter();
            await EnrollViaStartupPathAsync(webRuntime, webOut);
            Assert.True(webRuntime.IsEnrolled);

            var webText = webOut.ToString();
            Assert.Contains("Enrollment required for connection WEB-", webText);
            Assert.Contains($"(Web @ 127.0.0.1:{webHarness.GatewayPort}).", webText);
            Assert.Contains("Enter Authentication Code:", webText);
            Assert.Contains("Enrollment completed successfully.", webText);
            Assert.Contains("Enrollment successful.", webText);

            // Enrollment isolation: each service authorized exactly its own
            // client, and each OTT was consumed by its own connection only.
            var rdpUsers = await UsersAsync(rdpSetup);
            var webUsers = await UsersAsync(webSetup);
            Assert.Single(rdpUsers.Users);
            Assert.Single(webUsers.Users);
            Assert.Equal(rdpRuntime.ClientPublicKeyFingerprint, rdpUsers.Users[0].ClientPublicKeyFingerprint);
            Assert.Equal(webRuntime.ClientPublicKeyFingerprint, webUsers.Users[0].ClientPublicKeyFingerprint);
            Assert.NotEqual(rdpUsers.Users[0].ClientPublicKeyFingerprint, webUsers.Users[0].ClientPublicKeyFingerprint);

            var webSvc = await ServiceConfigStore.LoadAsync(webSetup.ServerConfigPath);
            Assert.DoesNotContain(webSvc.PendingOneTimeTokens,
                p => TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, webSetup.OneTimeTokenHash));

            // RDP stayed enrolled the whole time (client-side persistence).
            Assert.True((await ClientRuntime.LoadOrCreateAsync(
                rdpRuntime.ConnectionDirectory, rdpCfg)).IsEnrolled);
            Assert.True((await ClientRuntime.LoadOrCreateAsync(
                webRuntime.ConnectionDirectory, webCfg)).IsEnrolled);

            // ── 4. Both tunnels carry traffic from one process ──
            StartEcho(rdpHarness);
            StartEcho(webHarness);

            using var cts = new CancellationTokenSource();
            var runtimes = new List<ClientRuntime> { rdpRuntime, webRuntime };
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

            Assert.Equal("RDP-PAYLOAD", await EchoOnceAsync(rdpRuntime.Config.ClientTunnelPort, "RDP-PAYLOAD"));
            Assert.Equal("WEB-PAYLOAD", await EchoOnceAsync(webRuntime.Config.ClientTunnelPort, "WEB-PAYLOAD"));

            cts.Cancel();
            await Task.WhenAny(hostTask, Task.Delay(3000));
        }
        finally
        {
            if (rdpHarness != null) await rdpHarness.DisposeAsync();
            if (webHarness != null) await webHarness.DisposeAsync();
            Delete(exeDir);
            Delete(root);
        }
    }

    /// <summary>
    /// The reported failure signature: when the gateway endpoint of a
    /// connection is not reachable, the client fails at the TCP connect
    /// step - BEFORE ServerNonce / EnrollmentResult - regardless of the
    /// enrollment state of any other connection in the same installation.
    /// After the fix the failure is reported as a clean, actionable
    /// message (no stack trace) naming the exact endpoint that was dialed.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task GatewayUnreachable_FailsAtTcpConnect_WithActionableMessage_NotStackDump()
    {
        // A port with nothing listening on it: connection refused/failed
        // at the TCP layer, exactly like a firewall-dropped 10060 but fast.
        var deadPort = FreePort();

        using var serverKey = RsaCrypto.GenerateKeyPair();
        var cfg = new ClientConfig
        {
            ApplicationName        = "Web",
            ServerPublicKeyPem     = RsaCrypto.ExportPublicKeyPem(serverKey),
            ServerFingerprint      = RsaCrypto.ComputePublicKeyFingerprint(serverKey),
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = deadPort,
            LocalApplicationPort   = 80,
            ClientTunnelPort       = 8181,
            OneTimeToken           = TokenGenerator.GenerateOneTimeToken(),
            ClientName             = "Web-C1",
        };

        // Isolated canonical connection root for this test.
        using var clientRoot = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-accept-dead-");
        try
        {
            var runtime = await ClientRuntime.LoadOrCreateAsync(
                ClientServiceBundle.ConnectionDirectory(exeDir, cfg), cfg);
            Assert.False(runtime.IsEnrolled);

            var originalOut = Console.Out;
            var output = new StringWriter();
            Console.SetOut(output);
            try
            {
                var protocol = new ClientProtocol(runtime, () => Task.FromResult("1234567890"));
                var ex = await Assert.ThrowsAsync<EnrollmentFailedException>(
                    () => protocol.EnsureEnrolledAsync());

                // The exception summarizes; the console carries the full
                // actionable diagnosis naming the exact dialed endpoint.
                Assert.Contains($"Could not connect to the SSP gateway at 127.0.0.1:{deadPort}", ex.Message);

                var text = output.ToString();
                Assert.Contains("Enrollment required for connection WEB-", text);
                Assert.Contains($"Could not connect to the SSP gateway at 127.0.0.1:{deadPort}", text);
                Assert.Contains("socket error", text);
                Assert.Contains("Test-NetConnection 127.0.0.1", text);
                Assert.Contains("advfirewall", text);
                Assert.Contains("Enrollment failed.", text);

                // Clean UX: no stack trace (spec §14).
                Assert.DoesNotContain("   at ", text);
                Assert.DoesNotContain("[SSP.Client] Fatal:", text);

                // The connection did not become enrolled, and no protocol
                // message was ever exchanged (identity state untouched).
                Assert.False(runtime.IsEnrolled);
            }
            finally
            {
                Console.SetOut(originalOut);
            }
        }
        finally
        {
            Delete(exeDir);
        }
    }

    /// <summary>
    /// Launching Web-C1 after RDP-C1 is enrolled, from a folder whose
    /// merged client_services.json lists RDP first: the launched Web
    /// patch slot is the connection that enrolls. RDP stays enrolled,
    /// Web is not assumed enrolled, Web dials its own gateway and sends
    /// its own OTT, and the production EnsureEnrolledAsync path reaches
    /// "Enter Authentication Code:".
    /// </summary>
    [Fact(Timeout = 180000)]
    public async Task LaunchingWebExe_AfterRdpEnrolled_MergedBundle_IndependentEnrollment()
    {
        var root = NewTempDir("ssp-launch-web-");
        // Isolated canonical connection root for this test.
        using var clientRoot = new ClientConnectionRootScope(root);
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);
        var exeDir = NewTempDir("ssp-launch-web-client-");

        SspTestHarness? rdpHarness = null;
        SspTestHarness? webHarness = null;
        try
        {
            var rdpSetup = await SetupAppAsync(servicesRoot, "RDP", "Client01");
            rdpHarness = await StartGatewayAsync(rdpSetup);
            var rdpCfg = PatchedConfig(rdpSetup);

            var rdpRuntime = await ClientRuntime.LoadOrCreateAsync(
                ClientServiceBundle.ConnectionDirectory(exeDir, rdpCfg), rdpCfg);
            await EnrollViaStartupPathAsync(rdpRuntime, new StringWriter());
            Assert.True(rdpRuntime.IsEnrolled);

            var webSetup = await SetupAppAsync(servicesRoot, "Web", "Client01");
            webHarness = await StartGatewayAsync(webSetup);
            var webCfg = PatchedConfig(webSetup);

            // Combined installation: the merged bundle embedded in the
            // Web executable lists RDP first, as SetupEngine writes when
            // both Applications share Client01.
            var webClientDir = Path.GetDirectoryName(webSetup.ClientExecutablePath)!;
            var webClientBytes = File.ReadAllBytes(webSetup.ClientExecutablePath);
            var merged = ClientServiceBundle.LoadEmbedded(webClientBytes)
                         ?? throw new InvalidOperationException("No embedded service bundle.");
            Assert.Equal(2, merged.Services.Count);
            Assert.Equal("RDP", merged.Services[0].ApplicationName);

            // Simulate launching SSP.Client.Web.Client01.exe from that folder.
            var resolved = await ClientServiceBundle.ResolveAsync(webClientDir, webCfg, webClientBytes);
            Assert.Equal(2, resolved.Count);
            Assert.Equal("Web", resolved[0].ApplicationName);
            Assert.Equal(webCfg.GatewayPort, resolved[0].GatewayPort);
            Assert.Equal(webCfg.OneTimeToken, resolved[0].OneTimeToken);
            Assert.Equal(webCfg.ServerPublicKeyPem, resolved[0].ServerPublicKeyPem);
            Assert.NotEqual(rdpCfg.GatewayPort, resolved[0].GatewayPort);
            Assert.NotEqual(rdpCfg.OneTimeToken, resolved[0].OneTimeToken);

            var runtimes = new List<ClientRuntime>();
            foreach (var cfg in resolved)
            {
                var dir = ClientServiceBundle.PrepareIdentityDirectory(
                    exeDir, cfg, resolved.Count, webCfg);
                runtimes.Add(await ClientRuntime.LoadOrCreateAsync(dir, cfg));
            }

            Assert.Equal("Web", runtimes[0].Config.ApplicationName);
            Assert.False(runtimes[0].IsEnrolled);
            Assert.True(runtimes.Single(r => r.Config.ApplicationName == "RDP").IsEnrolled);
            Assert.NotEqual(
                runtimes[0].ClientPublicKeyFingerprint,
                runtimes.Single(r => r.Config.ApplicationName == "RDP").ClientPublicKeyFingerprint);

            var webOut = new StringWriter();
            await EnrollViaStartupPathAsync(runtimes[0], webOut);
            Assert.True(runtimes[0].IsEnrolled);

            var webText = webOut.ToString();
            Assert.Contains("Enrollment required for connection WEB-", webText);
            Assert.Contains($"(Web @ 127.0.0.1:{webHarness.GatewayPort}).", webText);
            Assert.Contains("Enter Authentication Code:", webText);
            Assert.Contains("Enrollment successful.", webText);

            Assert.True((await ClientRuntime.LoadOrCreateAsync(
                rdpRuntime.ConnectionDirectory, rdpCfg)).IsEnrolled);
            Assert.Single((await UsersAsync(rdpSetup)).Users);
            Assert.Single((await UsersAsync(webSetup)).Users);
            Assert.NotEqual(
                (await UsersAsync(rdpSetup)).Users[0].ClientPublicKeyFingerprint,
                (await UsersAsync(webSetup)).Users[0].ClientPublicKeyFingerprint);
        }
        finally
        {
            if (rdpHarness != null) await rdpHarness.DisposeAsync();
            if (webHarness != null) await webHarness.DisposeAsync();
            Delete(exeDir);
            Delete(root);
        }
    }

    /// <summary>
    /// A dummy patch slot (no server identity) must not be injected
    /// next to a valid bundle — that was the PR #15 3-vs-4 bug. A real
    /// launched Web slot with a server key IS injected/overlaid.
    /// </summary>
    [Fact]
    public void ApplyLaunchedConnection_DummyPatch_DoesNotCreatePhantomEntry()
    {
        using var serverKey = RsaCrypto.GenerateKeyPair();
        var pem = RsaCrypto.ExportPublicKeyPem(serverKey);
        var rdp = new ClientConfig
        {
            ApplicationName = "RDP",
            ServerPublicKeyPem = pem,
            ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(pem),
            GatewayPublicIpAddress = "1.1.1.2",
            GatewayPort = 4433,
            OneTimeToken = "rdp-ott",
        };
        var web = new ClientConfig
        {
            ApplicationName = "Web",
            ServerPublicKeyPem = pem,
            ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(pem),
            GatewayPublicIpAddress = "1.1.1.2",
            GatewayPort = 4480,
            OneTimeToken = "web-ott",
        };

        var dummy = new ClientConfig { ApplicationName = "RDP", GatewayPort = 1 };
        var services = new List<ClientConfig> { rdp, web };
        ClientServiceBundle.ApplyLaunchedConnection(services, dummy);
        Assert.Equal(2, services.Count);
        Assert.Equal(4433, services[0].GatewayPort);

        ClientServiceBundle.ApplyLaunchedConnection(services, web);
        Assert.Equal(2, services.Count);
        Assert.Equal("Web", services[0].ApplicationName);
        Assert.Equal(4480, services[0].GatewayPort);
        Assert.Equal("web-ott", services[0].OneTimeToken);
        Assert.Equal("RDP", services[1].ApplicationName);
    }

    /// <summary>
    /// Launching Web must not adopt RDP's exe-root key pair just because
    /// the folder still has client_private_key.pem from the RDP install.
    /// </summary>
    [Fact]
    public async Task PrepareIdentityDirectory_LaunchingWeb_DoesNotAdoptRdpRootKeys()
    {
        // Isolated canonical connection root for this test.
        using var clientRoot = new ClientConnectionRootScope();
        var exeDir = NewTempDir("ssp-no-steal-");
        try
        {
            File.WriteAllText(Path.Combine(exeDir, "client_private_key.pem"), "rdp-priv");
            File.WriteAllText(Path.Combine(exeDir, "client_public_key.pem"), "rdp-pub");

            using var rdpKey = RsaCrypto.GenerateKeyPair();
            using var webKey = RsaCrypto.GenerateKeyPair();
            var rdp = new ClientConfig
            {
                ApplicationName = "RDP",
                ServerPublicKeyPem = RsaCrypto.ExportPublicKeyPem(rdpKey),
                GatewayPublicIpAddress = "1.1.1.2",
                GatewayPort = 4433,
            };
            var web = new ClientConfig
            {
                ApplicationName = "Web",
                ServerPublicKeyPem = RsaCrypto.ExportPublicKeyPem(webKey),
                GatewayPublicIpAddress = "1.1.1.2",
                GatewayPort = 4480,
            };

            // Legacy RDP install: root keys migrate into the RDP connection
            // under their new connection-directory names.
            var destRdp = ClientServiceBundle.PrepareIdentityDirectory(exeDir, rdp, 1, rdp);
            Assert.True(File.Exists(Path.Combine(destRdp, ".cache.dat")));

            // Web is then added to the same folder. Root keys are now
            // ambiguous and must not be copied into the Web identity.
            // The merged bundle lives INSIDE the client executable: it
            // is patched for Web but its embedded service list also
            // holds RDP, which is what makes the folder ambiguous.
            var clientExe = Path.Combine(exeDir, "SSP.Client.Web.Client01.exe");
            await SetupEngine.BuildPatchedClientAsync(clientExe, web);
            await SetupEngine.WriteClientServiceBundleAsync(exeDir, new[] { rdp, web });
            var destWeb = ClientServiceBundle.PrepareIdentityDirectory(exeDir, web, 2, web);

            Assert.False(File.Exists(Path.Combine(destWeb, ".cache.dat")));
            Assert.NotEqual(destRdp, destWeb);
        }
        finally
        {
            Delete(exeDir);
        }
    }

    /// <summary>
    /// Setup must tell the operator that a locally verified listener is
    /// not the same as a reachable service, with the exact commands for
    /// this service's OWN gateway port (per-service firewall/NAT rules).
    /// </summary>
    [Fact]
    public void ReachabilityNotice_NamesOwnPort_AndExactCommands()
    {
        var config = new ServiceConfig
        {
            ApplicationName        = "Web",
            GatewayPublicIpAddress = "1.1.1.2",
            GatewayPort            = 4480,
        };

        var notice = WindowsServiceInstaller.BuildReachabilityNotice(config);

        Assert.Contains("4480", notice);
        Assert.Contains("netsh advfirewall firewall add rule", notice);
        Assert.Contains("localport=4480", notice);
        Assert.Contains("Test-NetConnection 1.1.1.2 -Port 4480", notice);
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Verify the embedded configuration of a generated client against the
    /// EMBEDDED CLIENT REQUIREMENT: ApplicationName, gateway endpoint,
    /// both ports, client name, the server public key AND fingerprint of
    /// exactly this service, and this client's own OTT.
    /// </summary>
    private static async Task AssertEmbeddedConfigAsync(
        SetupResult setup, ClientConfig cfg, string appName, string clientName)
    {
        Assert.Equal(appName, cfg.ApplicationName);
        Assert.Equal(clientName, cfg.ClientName);
        Assert.Equal("127.0.0.1", cfg.GatewayPublicIpAddress);
        Assert.Equal(setup.OneTimeToken, cfg.OneTimeToken);
        Assert.NotEmpty(cfg.ServerFingerprint);

        var serverPem = await PemStore.LoadPublicKeyAsync(setup.ServerPublicKeyPath);
        Assert.Equal(serverPem, cfg.ServerPublicKeyPem);
        Assert.Equal(
            RsaCrypto.ComputePublicKeyFingerprintFromPem(serverPem),
            cfg.ServerFingerprint);

        // The patched service configuration agrees on the endpoint/ports.
        var svc = await ServiceConfigStore.LoadAsync(setup.ServerConfigPath);
        Assert.Equal(svc.GatewayPort, cfg.GatewayPort);
        Assert.Equal(svc.LocalApplicationPort, cfg.LocalApplicationPort);
        Assert.Equal(svc.ClientTunnelPort, cfg.ClientTunnelPort);
    }

    /// <summary>
    /// Complete enrollment through the production startup path
    /// (EnsureEnrolledAsync, no session key on the enrollment socket),
    /// feeding the Authentication Code back from the captured server
    /// console banner, exactly like EnrollmentHelper.EnrollAsync does for
    /// the ConnectAndAuthenticateAsync path.
    /// </summary>
    private static async Task EnrollViaStartupPathAsync(ClientRuntime runtime, StringWriter output)
    {
        var originalOut = Console.Out;
        Console.SetOut(output);

        try
        {
            var protocol = new ClientProtocol(
                runtime,
                async () =>
                {
                    while (true)
                    {
                        if (EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out var extracted))
                            return extracted;

                        await Task.Delay(20);
                    }
                });

            await protocol.EnsureEnrolledAsync();
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    private static async Task<SetupResult> SetupAppAsync(string servicesRoot, string appName, string clientName)
    {
        var engine = new SetupEngine();
        await engine.RunAsync(new SetupParameters
        {
            ApplicationName        = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = FreePort(),
            LocalApplicationPort   = FreePort(),
            ClientTunnelPort       = FreePort(),
            ServiceDirectory       = Path.Combine(servicesRoot, appName),
            InstallWindowsService  = false,
            ClientName             = clientName,
        });
        Assert.True(engine.Result.Success);
        return engine.Result;
    }

    private static async Task<SspTestHarness> StartGatewayAsync(SetupResult setup)
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
