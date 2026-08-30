// File: tests/SSP.Tests/IndependentConnectionLifecycleTests.cs
//
// THE canonical SSP multi-connection acceptance scenario:
//
//   Server
//    ├── RDP
//    ├── Web
//    ├── SQL
//    └── SSH
//   Client
//    └── one installation
//
// Every Server + Service pair is ONE independent connection. Starting
// each connection must run its OWN complete lifecycle:
//
//   resolve THIS connection → load ITS config → use ITS server key →
//   use/generate ITS client key pair → present ITS One-Time Token to
//   ITS gateway → EnrollmentResult → 10-digit Authentication Code →
//   authorized → persist ITS enrollment state → ITS tunnel.
//
// RDP / Web / SQL / SSH are used here only as four instances of the
// GENERIC connection abstraction - nothing in the tested code paths is
// service-specific, so any other TCP service entering the same
// pipeline receives the same lifecycle without special cases.
//
// Regression root cause pinned by this file: the client used to run
// the startup lifecycle of EVERY connection listed in the merged
// client_services.json embedded in the executables, no matter which
// executable was launched. So starting the RDP executable:
//   * force-enrolled Web/SQL/SSH (consuming their One-Time Tokens and
//     asking for their Authentication Codes at RDP's start), making
//     "Start Web" later print an "already enrolled"-style no-op, or
//   * dialed their gateways when those services were not running,
//     surfacing as SocketException-style gateway failures during a
//     start that only asked for RDP, and
//   * bound the ClientTunnelPorts of ALL connections, so the next
//     executable could never bind its own tunnel port.
//
// The fix: ClientServiceBundle.SelectProcessConnections - a patched
// executable runs ONLY the connection embedded in its own patch slot.

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

public class IndependentConnectionLifecycleTests
{
    // ────────────────────────────────────────────────────────────────
    // 1. The full RDP → Web → SQL → SSH matrix, one installation
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// One server, four services (RDP/Web/SQL/SSH), ONE client
    /// installation holding all four executables, each embedding the
    /// merged client_services.json. Each connection is started in
    /// sequence and must complete its own full enrollment lifecycle;
    /// no connection may reuse, skip or disturb another.
    /// </summary>
    [Fact(Timeout = 300000)]
    public async Task FourConnections_StartedInSequence_EachCompletesOwnLifecycleIndependently()
    {
        var root = NewTempDir("ssp-life-");
        // The connection state now lives under the canonical product
        // root (C:\Program Files\SSP\connections), so this test gives
        // itself an isolated root under its own temp root.
        using var clientRoot = new ClientConnectionRootScope(root);
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);
        var installDir = NewTempDir("ssp-life-install-");

        var harnesses = new List<SspTestHarness>();
        try
        {
            // ── provisioning: four independent services on one server ──
            var appNames = new[] { "RDP", "Web", "SQL", "SSH" };
            var setups = new Dictionary<string, SetupResult>();
            var serverPems = new Dictionary<string, string>();
            foreach (var app in appNames)
            {
                setups[app] = await SetupAppAsync(servicesRoot, app, "Client01");
                serverPems[app] = await PemStore.LoadPublicKeyAsync(setups[app].ServerPublicKeyPath);
            }

            // Independence of the provisioned connections themselves.
            Assert.Equal(4, setups.Values.Select(s => s.OneTimeToken).Distinct().Count());
            Assert.Equal(4, setups.Values.Select(s => s.OneTimeTokenHash).Distinct().Count());
            Assert.Equal(4, setups.Values.Select(s => s.GatewayPort).Distinct().Count());
            Assert.Equal(4, serverPems.Values.Distinct().Count());

            // ── one client installation: every exe, each carrying the
            //    merged client_services.json INSIDE itself ──
            foreach (var app in appNames)
            {
                var exe = setups[app].ClientExecutablePath;
                File.Copy(exe, Path.Combine(installDir, Path.GetFileName(exe)));
            }
            Assert.Empty(Directory.EnumerateFiles(installDir, "client_services.json"));

            var embedded = ClientServiceBundle.LoadEmbedded(setups["RDP"].ClientExecutablePath)
                           ?? throw new InvalidOperationException("No embedded service bundle.");
            Assert.Equal(4, embedded.Services.Count);
            Assert.Equal(4, embedded.Services.Select(s => s.OneTimeToken).Distinct().Count());
            Assert.Equal(4, embedded.Services.Select(ConnectionIdentity.ConnectionId).Distinct().Count());

            // ── server side: all four gateways running ──
            foreach (var app in appNames)
                harnesses.Add(await StartGatewayAsync(setups[app]));

            // ── the user's sequence: Start RDP → Web → SQL → SSH ──
            var codes = new Dictionary<string, string>();
            var fingerprints = new Dictionary<string, string>();
            var connectionIds = new Dictionary<string, string>();
            var runtimes = new Dictionary<string, ClientRuntime>();

            foreach (var app in appNames)
            {
                var exePath = Path.Combine(installDir, Path.GetFileName(setups[app].ClientExecutablePath));
                var launchedBytes = await File.ReadAllBytesAsync(exePath);
                var patched = ClientTemplate.ReadPatchSlot(launchedBytes);

                // Exactly Program.Main's resolution, applied verbatim.
                var resolved = (await ClientServiceBundle.ResolveAsync(installDir, patched, launchedBytes)).ToList();
                ClientServiceBundle.ApplyLaunchedConnection(resolved, patched);
                var processConnections = ClientServiceBundle.SelectProcessConnections(resolved, patched).ToList();

                // The installation knows four connections, but THIS
                // executable runs exactly ITS OWN connection.
                Assert.Equal(4, resolved.Count);
                Assert.Single(processConnections);
                Assert.Equal(app, processConnections[0].ApplicationName);
                Assert.Equal(patched.OneTimeToken, processConnections[0].OneTimeToken);
                Assert.Equal(patched.ServerFingerprint, processConnections[0].ServerFingerprint);

                var connectionDir = ClientServiceBundle.PrepareIdentityDirectory(
                    installDir, processConnections[0], processConnections.Count, patched);
                var runtime = await ClientRuntime.LoadOrCreateAsync(connectionDir, processConnections[0]);
                runtimes[app] = runtime;

                // THIS connection was never enrolled - by anyone, ever.
                Assert.False(runtime.IsEnrolled,
                    $"{app} must start its own full enrollment; another connection's enrollment " +
                    "must never satisfy it.");
                connectionIds[app] = runtime.ConnectionId;
                fingerprints[app] = runtime.ClientPublicKeyFingerprint;
                Assert.Equal(fingerprints.Count, fingerprints.Values.Distinct().Count());

                // Start the connection through the production startup
                // path (EnsureEnrolledAsync) and capture everything it
                // prints, feeding the 10-digit code back like the human
                // operator does.
                var output = new StringWriter();
                await EnrollViaStartupPathAsync(runtime, output);
                Assert.True(runtime.IsEnrolled);

                var text = output.ToString();
                Assert.Contains(
                    "Enrollment required for connection " +
                    ConnectionIdentity.Sanitize(app).ToUpperInvariant() + "-", text);
                Assert.Contains($"({app} @ 127.0.0.1:{setups[app].GatewayPort}).", text);
                Assert.Contains("Enter Authentication Code:", text);
                Assert.Contains("Enrollment completed successfully.", text);
                Assert.Contains("Enrollment successful.", text);

                // The 10-digit code THIS connection's server displayed.
                Assert.True(EnrollmentHelper.TryReadAuthenticationCode(text, out var code));
                codes[app] = code;

                // Server-side isolation after THIS start:
                foreach (var other in appNames)
                {
                    var users = await UsersAsync(setups[other]);
                    var svc = await ServiceConfigStore.LoadAsync(setups[other].ServerConfigPath);

                    if (other == app)
                    {
                        // authorized exactly once, with THIS connection's key
                        Assert.Single(users.Users);
                        Assert.Equal(fingerprints[app], users.Users[0].ClientPublicKeyFingerprint);
                        // ITS One-Time Token consumed by exactly THIS enrollment
                        Assert.DoesNotContain(svc.PendingOneTimeTokens, p =>
                            TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, setups[app].OneTimeTokenHash));
                    }
                    else if (setups.ContainsKey(other) && Earlier(appNames, other, app))
                    {
                        // an already-started connection stays untouched
                        Assert.Single(users.Users);
                        Assert.Equal(fingerprints[other], users.Users[0].ClientPublicKeyFingerprint);
                        Assert.Empty(svc.PendingOneTimeTokens);
                    }
                    else
                    {
                        // a not-yet-started connection is still fully pending
                        Assert.Empty(users.Users);
                        Assert.Contains(svc.PendingOneTimeTokens, p =>
                            TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, setups[other].OneTimeTokenHash));
                    }
                }

                // Client-side isolation: only connections actually started
                // have identity + state directories (under the canonical
                // product root), and each state dir reports exactly its
                // own connection.
                var connectionsRoot = ClientInstallPaths.GetConnectionsRoot();
                var startedSoFar = appNames.TakeWhile(a => a != app).Concat(new[] { app }).ToList();
                var dirs = Directory.GetDirectories(connectionsRoot)
                    .Select(d => Path.GetFileName(d)!)
                    .OrderBy(n => n)
                    .ToList();
                Assert.Equal(startedSoFar.Count, dirs.Count);
                foreach (var started in startedSoFar)
                {
                    var prefix = ConnectionIdentity.Sanitize(started).ToUpperInvariant() + "-";
                    Assert.Contains(dirs, d => d.StartsWith(prefix, StringComparison.Ordinal));
                    var state = ClientConnectionState.TryLoad(
                        Path.Combine(connectionsRoot, dirs.First(d => d.StartsWith(prefix, StringComparison.Ordinal))));
                    Assert.NotNull(state);
                    Assert.Equal(connectionIds[started], state.ConnectionId);
                    Assert.True(state.IsEnrolled);
                    Assert.True(state.IsAuthorized);
                }
            }

            // Four connections → four independent 10-digit codes, four
            // independent identities, four independent connection ids.
            Assert.Equal(4, codes.Values.Distinct().Count());
            Assert.All(codes.Values, c => Assert.Matches("^\\d{10}$", c));
            Assert.Equal(4, connectionIds.Values.Distinct(StringComparer.OrdinalIgnoreCase).Count());

            // Every OTT is now consumed exactly once - replaying any of
            // them against its own service must fail, must not enroll
            // the replaying identity and must not add a second user.
            foreach (var app in appNames)
            {
                var replayDir = NewTempDir("ssp-replay-");
                var replayRuntime = await ClientRuntime.LoadOrCreateAsync(
                    replayDir, ReplayConfig(setups[app]));
                await Assert.ThrowsAnyAsync<Exception>(
                    () => new ClientProtocol(replayRuntime, () => Task.FromResult("1234567890"))
                        .ConnectAndAuthenticateAsync());
                Assert.False(replayRuntime.IsEnrolled);
                Assert.Single((await UsersAsync(setups[app])).Users);
                Delete(replayDir);
            }

            // ── Establish THIS connection's tunnel: all four at once ──
            foreach (var h in harnesses) StartEcho(h);

            using var cts = new CancellationTokenSource();
            var host = new ClientSessionHost(appNames.Select(a => runtimes[a]).ToList());
            var hostTask = Task.Run(() => host.RunAsync(cts.Token));

            foreach (var app in appNames)
            {
                var ok = false;
                for (var i = 0; i < 400 && !ok; i++)
                {
                    ok = IsPortListening(setups[app].ClientTunnelPort);
                    if (!ok) await Task.Delay(25);
                }
                Assert.True(ok, $"{app} tunnel never came up.");
            }

            foreach (var app in appNames)
            {
                var marker = app + "-PAYLOAD";
                Assert.Equal(marker, await EchoOnceAsync(setups[app].ClientTunnelPort, marker));
            }

            cts.Cancel();
            await Task.WhenAny(hostTask, Task.Delay(3000));
        }
        finally
        {
            foreach (var h in harnesses) await h.DisposeAsync();
            Delete(installDir);
            Delete(root);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 2. Starting one executable must not touch the others
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// THE reported failure mode. RDP is enrolled and running; Web, SQL
    /// and SSH are provisioned but their gateways are NOT running (the
    /// services exist - only their endpoints are down). Starting the
    /// RDP executable must:
    ///   * enroll RDP only, with no SocketException / gateway-unreachable
    ///     noise about Web/SQL/SSH (their endpoints are never dialed),
    ///   * create an identity directory for RDP only,
    ///   * leave the Web/SQL/SSH OTTs pending and their user lists empty.
    ///
    /// Then Web's gateway is started and "Start Web" (its own executable,
    /// same installation, RDP still running) MUST reach
    /// "Enrollment required for connection ..." + "Enter Authentication
    /// Code:" - never "already enrolled", never a SocketException.
    /// </summary>
    [Fact(Timeout = 240000)]
    public async Task RdpStart_WithOtherGatewaysDown_EnrollsOnlyRdp_ThenWebStartsFully()
    {
        var root = NewTempDir("ssp-rdpfirst-");
        // Isolated canonical connection root for this test (see the
        // first test in this file).
        using var clientRoot = new ClientConnectionRootScope(root);
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);
        var installDir = NewTempDir("ssp-rdpfirst-install-");

        SspTestHarness? rdpHarness = null;
        SspTestHarness? webHarness = null;
        try
        {
            var rdpSetup = await SetupAppAsync(servicesRoot, "RDP", "Client01");
            var webSetup = await SetupAppAsync(servicesRoot, "Web", "Client01");
            var sqlSetup = await SetupAppAsync(servicesRoot, "SQL", "Client01");
            var sshSetup = await SetupAppAsync(servicesRoot, "SSH", "Client01");

            foreach (var setup in new[] { rdpSetup, webSetup, sqlSetup, sshSetup })
            {
                var exe = setup.ClientExecutablePath;
                File.Copy(exe, Path.Combine(installDir, Path.GetFileName(exe)));
            }
            // No sidecar: each copied executable already embeds the
            // merged client_services.json of the whole installation.
            Assert.Empty(Directory.EnumerateFiles(installDir, "client_services.json"));

            // Only the RDP gateway runs. Web/SQL/SSH services exist but
            // their gateways are down - exactly the reported LAN setup.
            rdpHarness = await StartGatewayAsync(rdpSetup);

            // ── Start RDP (its own executable) ──
            var (rdpRuntime, rdpOut, rdpCts, rdpTask) = await StartConnectionLikeMainAsync(
                installDir, rdpSetup, enrollTimeoutSeconds: 60);

            var rdpText = rdpOut.ToString();
            Assert.Contains("Enrollment required for connection RDP-", rdpText);
            Assert.Contains("Enter Authentication Code:", rdpText);
            Assert.Contains("Enrollment completed successfully.", rdpText);
            Assert.True(rdpRuntime.IsEnrolled);

            // RDP's start dialed ONLY RDP's gateway. The other gateways
            // are down: before the fix their enrollment was force-run
            // here and produced gateway-unreachable / SocketException
            // output for connections nobody asked to start.
            Assert.DoesNotContain("Enrollment required for connection WEB-", rdpText);
            Assert.DoesNotContain("Enrollment required for connection SQL-", rdpText);
            Assert.DoesNotContain("Enrollment required for connection SSH-", rdpText);
            Assert.DoesNotContain("Could not connect to the SSP gateway", rdpText);
            Assert.DoesNotContain("Enrollment failed", rdpText);

            // Identity/state directories exist for RDP ONLY (under the
            // canonical product root).
            var connectionsRoot = ClientInstallPaths.GetConnectionsRoot();
            var dirs = Directory.GetDirectories(connectionsRoot)
                .Select(d => Path.GetFileName(d)!)
                .ToList();
            Assert.Single(dirs);
            Assert.StartsWith("RDP-", dirs[0], StringComparison.Ordinal);

            // Other connections untouched server-side.
            foreach (var setup in new[] { webSetup, sqlSetup, sshSetup })
            {
                Assert.Empty((await UsersAsync(setup)).Users);
                var svc = await ServiceConfigStore.LoadAsync(setup.ServerConfigPath);
                Assert.Contains(svc.PendingOneTimeTokens, p =>
                    TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, setup.OneTimeTokenHash));
            }
            var rdpSvcAfter = await ServiceConfigStore.LoadAsync(rdpSetup.ServerConfigPath);
            Assert.DoesNotContain(rdpSvcAfter.PendingOneTimeTokens, p =>
                TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, rdpSetup.OneTimeTokenHash));

            // RDP tunnel carries traffic while the other gateways are down.
            StartEcho(rdpHarness);
            Assert.Equal("RDP-PAYLOAD", await EchoOnceAsync(rdpSetup.ClientTunnelPort, "RDP-PAYLOAD"));

            // ── now the Web gateway comes up and "Start Web" happens ──
            webHarness = await StartGatewayAsync(webSetup);

            var (webRuntime, webOut, webCts, webTask) = await StartConnectionLikeMainAsync(
                installDir, webSetup, enrollTimeoutSeconds: 60);

            var webText = webOut.ToString();
            Assert.Contains("Enrollment required for connection WEB-", webText);
            Assert.Contains($"(Web @ 127.0.0.1:{webSetup.GatewayPort}).", webText);
            Assert.Contains("Enter Authentication Code:", webText);
            Assert.Contains("Enrollment completed successfully.", webText);
            Assert.True(webRuntime.IsEnrolled);

            // Web's own OTT, consumed only now, only by Web.
            var webSvc = await ServiceConfigStore.LoadAsync(webSetup.ServerConfigPath);
            Assert.DoesNotContain(webSvc.PendingOneTimeTokens, p =>
                TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, webSetup.OneTimeTokenHash));
            var webUsers = await UsersAsync(webSetup);
            Assert.Single(webUsers.Users);
            Assert.Equal(webRuntime.ClientPublicKeyFingerprint, webUsers.Users[0].ClientPublicKeyFingerprint);

            // SQL/SSH are still fully pending - starting Web changed nothing for them.
            foreach (var setup in new[] { sqlSetup, sshSetup })
            {
                Assert.Empty((await UsersAsync(setup)).Users);
                var svc = await ServiceConfigStore.LoadAsync(setup.ServerConfigPath);
                Assert.Contains(svc.PendingOneTimeTokens, p =>
                    TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, setup.OneTimeTokenHash));
            }

            // Both tunnels work at the same time, each on its own port.
            StartEcho(webHarness);
            Assert.Equal("WEB-PAYLOAD", await EchoOnceAsync(webSetup.ClientTunnelPort, "WEB-PAYLOAD"));
            Assert.Equal("RDP-STILL-OK", await EchoOnceAsync(rdpSetup.ClientTunnelPort, "RDP-STILL-OK"));

            // RDP remains enrolled with its original identity.
            Assert.True((await ClientRuntime.LoadOrCreateAsync(
                rdpRuntime.ConnectionDirectory, rdpRuntime.Config)).IsEnrolled);
            Assert.True((await ClientRuntime.LoadOrCreateAsync(
                webRuntime.ConnectionDirectory, webRuntime.Config)).IsEnrolled);

            rdpCts.Cancel();
            webCts.Cancel();
            await Task.WhenAny(rdpTask, Task.Delay(2000));
            await Task.WhenAny(webTask, Task.Delay(2000));
        }
        finally
        {
            if (rdpHarness != null) await rdpHarness.DisposeAsync();
            if (webHarness != null) await webHarness.DisposeAsync();
            Delete(installDir);
            Delete(root);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 3. Unit-level pins of the selection rules
    // ────────────────────────────────────────────────────────────────

    private static ClientConfig RealConfig(string app, int port, string ott)
    {
        using var key = RsaCrypto.GenerateKeyPair();
        var pem = RsaCrypto.ExportPublicKeyPem(key);
        return new ClientConfig
        {
            ApplicationName = app,
            ServerPublicKeyPem = pem,
            ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(pem),
            GatewayPublicIpAddress = "10.0.0.10",
            GatewayPort = port,
            OneTimeToken = ott,
            ClientName = "Client01",
        };
    }

    /// <summary>
    /// A patched executable runs exactly its own connection, even when
    /// the installation holds a four-connection merged bundle.
    /// </summary>
    [Fact]
    public void SelectProcessConnections_PatchedExecutable_RunsOnlyItsOwnConnection()
    {
        var rdp = RealConfig("RDP", 4433, "ott-rdp");
        var web = RealConfig("Web", 4480, "ott-web");
        var sql = RealConfig("SQL", 4490, "ott-sql");
        var ssh = RealConfig("SSH", 4500, "ott-ssh");
        var bundle = new List<ClientConfig> { rdp, web, sql, ssh };

        var selectedRdp = ClientServiceBundle.SelectProcessConnections(bundle, rdp);
        Assert.Single(selectedRdp);
        Assert.Same(rdp, selectedRdp[0]);

        var selectedWeb = ClientServiceBundle.SelectProcessConnections(bundle, web);
        Assert.Single(selectedWeb);
        Assert.Same(web, selectedWeb[0]);
        Assert.Equal("ott-web", selectedWeb[0].OneTimeToken);
    }

    /// <summary>
    /// An unpatched template binary (no server identity) has no
    /// connection of its own and hosts the whole bundle.
    /// </summary>
    [Fact]
    public void SelectProcessConnections_UnpatchedTemplate_HostsWholeBundle()
    {
        var rdp = RealConfig("RDP", 4433, "ott-rdp");
        var web = RealConfig("Web", 4480, "ott-web");
        var bundle = new List<ClientConfig> { rdp, web };
        var dummy = new ClientConfig { ApplicationName = "RDP", ClientName = "Client01" };

        var selected = ClientServiceBundle.SelectProcessConnections(bundle, dummy);
        Assert.Equal(2, selected.Count);

        var selectedNull = ClientServiceBundle.SelectProcessConnections(bundle, null);
        Assert.Equal(2, selectedNull.Count);
    }

    /// <summary>
    /// Same ApplicationName + same endpoint but a DIFFERENT server key
    /// is a different connection (ServerB/WEB next to ServerA/WEB): the
    /// launched entry must not replace it - both stay side by side.
    /// </summary>
    [Fact]
    public void ApplyLaunchedConnection_SameAppDifferentServer_KeepsBothEntries()
    {
        var webA = RealConfig("WEB", 4480, "ott-a");
        var webB = RealConfig("WEB", 4480, "ott-b");   // same endpoint, different key
        var webC = RealConfig("WEB", 4480, "ott-c");   // launched, third key

        Assert.NotEqual(webA.ServerFingerprint, webB.ServerFingerprint);

        var services = new List<ClientConfig> { webA, webB };
        ClientServiceBundle.ApplyLaunchedConnection(services, webC);

        Assert.Equal(3, services.Count);
        Assert.Same(webC, services[0]);                 // launched first
        Assert.Contains(webA, services);                // neither sibling lost
        Assert.Contains(webB, services);
    }

    /// <summary>
    /// A dummy (identity-less) patch slot must not become a phantom
    /// connection beside real sibling executables.
    /// </summary>
    [Fact(Timeout = 120000)]
    public async Task ResolveAsync_DummyPatchSlot_DroppedWhenSiblingsExist()
    {
        var parent = NewTempDir("ssp-dummy-");
        var installDir = NewTempDir("ssp-dummy-install-");
        try
        {
            var rdp = await SetupAppAsync(parent, "RDP", "Client01");
            var web = await SetupAppAsync(parent, "Web", "Client01");

            foreach (var s in new[] { rdp, web })
                File.Copy(s.ClientExecutablePath,
                    Path.Combine(installDir, Path.GetFileName(s.ClientExecutablePath)));

            // No sidecar in the folder; the "launched" slot is a dummy
            // build with a client name but no server identity.
            var dummy = new ClientConfig { ApplicationName = "TEMPLATE", ClientName = "Client01" };
            var resolved = await ClientServiceBundle.ResolveAsync(installDir, dummy, embeddedServicesJson: null);

            Assert.Equal(2, resolved.Count);
            Assert.DoesNotContain(resolved, c => c.ApplicationName == "TEMPLATE");
            Assert.Equal(new[] { "RDP", "Web" },
                resolved.Select(c => c.ApplicationName).OrderBy(n => n).ToArray());
        }
        finally
        {
            Delete(installDir);
            Delete(parent);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // 4. Setup-time protection of per-connection ports
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// A second service reusing another service's gateway port could
    /// never run its gateway (and its clients would see a permanently
    /// unreachable endpoint while the first service looks healthy).
    /// Setup must reject that loudly instead.
    /// </summary>
    [Fact(Timeout = 120000)]
    public async Task Setup_SiblingGatewayPortCollision_Rejected()
    {
        var root = NewTempDir("ssp-gwcol-");
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);
        try
        {
            var rdp = await SetupAppAsync(servicesRoot, "RDP", "Client01");

            var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
                SetupAppAsync(servicesRoot, "Web", "Client01",
                    gatewayPort: rdp.GatewayPort));
            Assert.Contains("GatewayPort", ex.Message);
            Assert.Contains("RDP", ex.Message);
            Assert.Contains(rdp.GatewayPort.ToString(), ex.Message);
        }
        finally
        {
            Delete(root);
        }
    }

    /// <summary>
    /// Two connections of the SAME client cannot share the client's
    /// local tunnel port; a different client name may (different
    /// machine, different installation folder).
    /// </summary>
    [Fact(Timeout = 120000)]
    public async Task Setup_SiblingTunnelPortCollision_SameClientRejected_OtherClientAllowed()
    {
        var root = NewTempDir("ssp-tpcol-");
        var servicesRoot = Path.Combine(root, "services");
        Directory.CreateDirectory(servicesRoot);
        try
        {
            var rdp = await SetupAppAsync(servicesRoot, "RDP", "Client01");

            var sameClient = await Assert.ThrowsAsync<ArgumentException>(() =>
                SetupAppAsync(servicesRoot, "Web", "Client01",
                    clientTunnelPort: rdp.ClientTunnelPort));
            Assert.Contains("ClientTunnelPort", sameClient.Message);
            Assert.Contains("RDP", sameClient.Message);

            // A different client name = a different installation: no
            // shared local port, provisioning succeeds.
            var otherClient = await SetupAppAsync(servicesRoot, "SSH", "Client02",
                clientTunnelPort: rdp.ClientTunnelPort);
            Assert.True(otherClient.Success);
        }
        finally
        {
            Delete(root);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers - mirror Program.Main exactly
    // ────────────────────────────────────────────────────────────────

    private static bool Earlier(string[] order, string candidate, string current) =>
        Array.IndexOf(order, candidate) < Array.IndexOf(order, current);

    /// <summary>
    /// Start one connection exactly the way its generated executable
    /// does in Program.Main (single-connection mode): resolve the whole
    /// installation, pin + select THIS executable's connection, prepare
    /// ITS identity directory, load ITS runtime, then run the tunnel
    /// loop (which performs the startup enrollment before binding the
    /// local listener). The Authentication Code is fed back from the
    /// captured server console output.
    /// </summary>
    private static async Task<(ClientRuntime Runtime, StringWriter Output, CancellationTokenSource Cts, Task RunTask)>
        StartConnectionLikeMainAsync(string installDir, SetupResult setup, int enrollTimeoutSeconds)
    {
        var exePath = Path.Combine(installDir, Path.GetFileName(setup.ClientExecutablePath));
        var launchedBytes = await File.ReadAllBytesAsync(exePath);
        var patched = ClientTemplate.ReadPatchSlot(launchedBytes);

        var resolved = (await ClientServiceBundle.ResolveAsync(installDir, patched, launchedBytes)).ToList();
        ClientServiceBundle.ApplyLaunchedConnection(resolved, patched);
        var processConnections = ClientServiceBundle.SelectProcessConnections(resolved, patched).ToList();
        Assert.Single(processConnections);

        var connectionDir = ClientServiceBundle.PrepareIdentityDirectory(
            installDir, processConnections[0], processConnections.Count, patched);
        var runtime = await ClientRuntime.LoadOrCreateAsync(connectionDir, processConnections[0]);

        var output = new StringWriter();
        var originalOut = Console.Out;
        Console.SetOut(output);
        try
        {
            var cts = new CancellationTokenSource();
            var tunnel = new ClientTunnelRuntime(runtime, async () =>
            {
                while (true)
                {
                    if (EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out var code))
                        return code;
                    await Task.Delay(20);
                }
            });
            var runTask = Task.Run(() => tunnel.RunAsync(cts.Token));

            var deadline = DateTime.UtcNow.AddSeconds(enrollTimeoutSeconds);
            while (DateTime.UtcNow < deadline)
            {
                if (IsPortListening(runtime.Config.ClientTunnelPort))
                    return (runtime, output, cts, runTask);
                await Task.Delay(50);
            }

            cts.Cancel();
            await Task.WhenAny(runTask, Task.Delay(2000));
            throw new TimeoutException(
                $"Connection {runtime.ConnectionId} never completed enrollment + tunnel binding. Output:\n{output}");
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    private static async Task EnrollViaStartupPathAsync(ClientRuntime runtime, StringWriter output)
    {
        var originalOut = Console.Out;
        Console.SetOut(output);
        try
        {
            var protocol = new ClientProtocol(runtime, async () =>
            {
                while (true)
                {
                    if (EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out var code))
                        return code;
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

    /// <summary>A config for replaying an already-consumed OTT against its own service.</summary>
    private static ClientConfig ReplayConfig(SetupResult setup)
    {
        var patched = ClientTemplate.ReadPatchSlot(File.ReadAllBytes(setup.ClientExecutablePath));
        return new ClientConfig
        {
            ApplicationName = patched.ApplicationName,
            ServerPublicKeyPem = patched.ServerPublicKeyPem,
            ServerFingerprint = patched.ServerFingerprint,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = patched.GatewayPort,
            LocalApplicationPort = patched.LocalApplicationPort,
            ClientTunnelPort = FreePort(),
            OneTimeToken = patched.OneTimeToken,   // consumed already
            ClientName = "ReplayClient",
        };
    }

    private static async Task<SetupResult> SetupAppAsync(
        string servicesRoot, string appName, string clientName,
        int? gatewayPort = null, int? clientTunnelPort = null)
    {
        var engine = new SetupEngine();
        await engine.RunAsync(new SetupParameters
        {
            ApplicationName = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = gatewayPort ?? FreePort(),
            LocalApplicationPort = FreePort(),
            ClientTunnelPort = clientTunnelPort ?? FreePort(),
            ServiceDirectory = Path.Combine(servicesRoot, appName),
            InstallWindowsService = false,
            ClientName = clientName,
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
        var deadline = DateTime.UtcNow.AddSeconds(10);
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
