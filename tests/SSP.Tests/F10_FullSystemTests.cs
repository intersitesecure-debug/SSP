// File: tests/SSP.Tests/F10_FullSystemTests.cs
//
// F10 - Full System Integration functional tests.
//
// Spins up the *real* server (via SetupEngine -> --run-once style) and
// the *real* client stack (via ClientTunnelRuntime) and verifies that
// traffic flows end-to-end with no errors.

using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Server.Setup;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class F10_FullSystemTests
{
    /// <summary>
    /// End-to-end integration:
    ///   1. SetupEngine creates a real service directory with all artifacts.
    ///   2. A fake "protected application" TCP echo server is started.
    ///   3. The SSP.Server gateway is started in-process.
    ///   4. A patched SSP.Client binary is launched as a subprocess.
    ///   5. A test TCP client connects to the client's tunnel port,
    ///      sends a payload, and verifies the echo round-trip.
    /// </summary>
    [Fact]
    public async Task FullSystem_EndToEnd_TrafficFlowsThroughTunnel()
    {
        // Step 1: create the service via SetupEngine.
        var baseDir = Path.Combine(System.IO.Path.GetTempPath(), "ssp-f10-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseDir);

        try
        {
            // We need a real local app port and a real gateway port.
            var gatewayPort = FreeTcpPort();
            var localAppPort = FreeTcpPort();
            var clientTunnelPort = FreeTcpPort();

            var parameters = new SetupParameters
            {
                ApplicationName        = "RDP",
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = gatewayPort,
                LocalApplicationPort   = localAppPort,
                ClientTunnelPort       = clientTunnelPort,
                ServiceDirectory       = baseDir,
                // This test deliberately hosts the gateway in-process in
                // Step 3. Do not also bind the same port through SCM when
                // the test runner happens to be elevated on Windows.
                InstallWindowsService  = false,
            };

            var engine = new SetupEngine(UnlicensedTestGate.Instance);
            await engine.RunAsync(parameters);
            var ott = engine.Result.OneTimeToken;

            // Step 2: start a fake protected app (echo server) that accepts
            // multiple connections (the enrollment connection also triggers
            // a short-lived relay to the local app).
            var echoListener = new TcpListener(System.Net.IPAddress.Loopback, localAppPort);
            echoListener.Start();
            var echoCts = new CancellationTokenSource();
            var echoTask = Task.Run(async () =>
            {
                while (!echoCts.Token.IsCancellationRequested)
                {
                    TcpClient c;
                    try { c = await echoListener.AcceptTcpClientAsync(echoCts.Token); }
                    catch (OperationCanceledException) { break; }

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using var s = c.GetStream();
                            var buf = new byte[4096];
                            int n;
                            while ((n = await s.ReadAsync(buf.AsMemory(0, buf.Length))) > 0)
                                await s.WriteAsync(buf.AsMemory(0, n));
                        }
                        catch { }
                    });
                }
            });

            // Step 3: start the gateway in-process.
            var cfg = await SSP.Core.IO.ServiceConfigStore.LoadAsync(engine.Result.ServerConfigPath);
            using var serverRsa = RsaCrypto.ImportPrivateKeyPem(
                await PemStore.LoadPrivateKeyAsync(engine.Result.ServerPrivateKeyPath));
            var serverPubPem = await PemStore.LoadPublicKeyAsync(engine.Result.ServerPublicKeyPath);
            // F10 is a pre-existing end-to-end traffic test, not a licensing
            // test. The gateway now requires an explicit, non-nullable
            // ISspLicenseGate (production fail-closed invariant), so this legacy
            // integration declares the test-only allow-all seam explicitly; the
            // licensing behavior itself is covered by the Activation/Runtime
            // suites with a real SspRuntimeLicense.
            var gateway = new SSP.Server.Runtime.ServerGateway(
                cfg, serverRsa, serverPubPem, baseDir, SSP.Tests.Helpers.UnlicensedTestGate.Instance);

            using var cts = new CancellationTokenSource();
            var gatewayTask = Task.Run(() => gateway.RunAsync(cts.Token));
            await Task.Delay(200);

            // Step 4: build a ClientRuntime manually (we skip the subprocess
            // dance here and use the in-process client; this is the same
            // code path the patched exe would execute).
            var clientDir = Path.Combine(baseDir, "client");
            Directory.CreateDirectory(clientDir);
            var clientCfg = new SSP.Core.Models.ClientConfig
            {
                ApplicationName        = "RDP",
                ServerPublicKeyPem     = serverPubPem,
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = gatewayPort,
                LocalApplicationPort   = localAppPort,
                ClientTunnelPort       = clientTunnelPort,
                OneTimeToken           = ott,
            };
            var runtime = await ClientRuntime.LoadOrCreateAsync(clientDir, clientCfg);

            // 5a. Enroll the client (interactive AuthenticationCode flow).
            await EnrollmentHelper.EnrollAsync(runtime);

            // 5b. Reload runtime with enrolled keys, then run the tunnel.
            var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, clientCfg);
            Assert.True(runtime2.IsEnrolled);

            var tunnelRuntime = new ClientTunnelRuntime(runtime2);
            var tunnelTask = Task.Run(() => tunnelRuntime.RunAsync(cts.Token));
            await Task.Delay(300);

            // 5c. Connect a test client to the tunnel port and echo a payload.
            using var testClient = new TcpClient();
            await testClient.ConnectAsync(System.Net.IPAddress.Loopback, clientTunnelPort);
            using var testStream = testClient.GetStream();

            var payload = Encoding.UTF8.GetBytes("F10 full-system integration payload");
            await testStream.WriteAsync(payload);
            await testStream.FlushAsync();

            var recv = new byte[payload.Length];
            var off = 0;
            while (off < recv.Length)
            {
                var read = await testStream.ReadAsync(recv.AsMemory(off, recv.Length - off));
                if (read == 0) break;
                off += read;
            }

            Assert.Equal(payload.Length, off);
            Assert.Equal(payload, recv);

            cts.Cancel();
            echoCts.Cancel();
            echoListener.Stop();
            await Task.WhenAny(gatewayTask, Task.Delay(500));
            await Task.WhenAny(tunnelTask, Task.Delay(500));
        }
        finally
        {
            try { Directory.Delete(baseDir, true); } catch { }
        }
    }

    /// <summary>
    /// The patched client binary produced by SetupEngine is executable
    /// and contains a valid ClientConfig that can be read back.
    /// </summary>
    [Fact]
    public async Task FullSystem_PatchedClientBinaryIsValid()
    {
        var baseDir = Path.Combine(System.IO.Path.GetTempPath(), "ssp-f10-patch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseDir);

        try
        {
            var parameters = new SetupParameters
            {
                ApplicationName        = "WEB",
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = 4444,
                LocalApplicationPort   = 80,
                ClientTunnelPort       = 8080,
                ServiceDirectory       = baseDir,
                InstallWindowsService  = false,
            };

            var engine = new SetupEngine(UnlicensedTestGate.Instance);
            await engine.RunAsync(parameters);

            var clientPath = engine.Result.ClientExecutablePath;
            Assert.True(File.Exists(clientPath));

            var bytes = await File.ReadAllBytesAsync(clientPath);
            var cfg = SSP.Core.Util.ClientTemplate.ReadPatchSlot(bytes);
            Assert.Equal("WEB", cfg.ApplicationName);
            Assert.Equal("127.0.0.1", cfg.GatewayPublicIpAddress);
            Assert.Equal(4444, cfg.GatewayPort);
            Assert.Equal(80, cfg.LocalApplicationPort);
            Assert.Equal(8080, cfg.ClientTunnelPort);
            Assert.Equal(engine.Result.OneTimeToken, cfg.OneTimeToken);
        }
        finally
        {
            try { Directory.Delete(baseDir, true); } catch { }
        }
    }

    private static int FreeTcpPort()
    {
        var l = new TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
