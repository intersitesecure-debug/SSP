// File: tests/SSP.Tests/ClientLifecycleTests.cs
//
// Regression for the production single-file client lifecycle:
//
//   The tunnel port (127.0.0.1:ClientTunnelPort) must NOT accept
//   connections until enrollment has succeeded. Automated F4/F7/F10
//   tests never caught this because they call EnrollmentHelper first
//   and only then construct ClientTunnelRuntime.

using System.Net.NetworkInformation;
using System.Net.Sockets;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class ClientLifecycleTests
{
    /// <summary>
    /// While the client is blocked on the Authentication Code, the
    /// local tunnel port must still be closed. After the code is
    /// accepted the port must start listening, and a subsequent local
    /// connect must use future-authorization (the reader is not
    /// invoked again).
    /// </summary>
    [Fact(Timeout = 20000)]
    public async Task RunAsync_DoesNotBindTunnelPort_UntilEnrollmentSucceeds()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        Assert.False(runtime.IsEnrolled);

        var originalOut = Console.Out;
        var output = new StringWriter();
        Console.SetOut(output);

        var authCalls = 0;
        var codeEntered = new TaskCompletionSource<string>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var tunnel = new ClientTunnelRuntime(runtime, async () =>
            {
                Interlocked.Increment(ref authCalls);
                return await codeEntered.Task;
            });

            using var cts = new CancellationTokenSource();
            var runTask = Task.Run(() => tunnel.RunAsync(cts.Token));

            string? code = null;
            for (var i = 0; i < 200 && code == null; i++)
            {
                if (EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out var extracted))
                    code = extracted;
                else
                    await Task.Delay(25);
            }

            Assert.False(string.IsNullOrEmpty(code),
                "Server never printed the Authentication Code. Output:\n" + output);

            // THE production assertion: mstsc must not be able to connect
            // (and therefore must not be able to trigger enrollment).
            Assert.False(IsPortListening(runtime.Config.ClientTunnelPort),
                "Tunnel port was listening before enrollment succeeded.");
            Assert.False(runtime.IsEnrolled);

            codeEntered.TrySetResult(code!);

            var listening = false;
            for (var i = 0; i < 200 && !listening; i++)
            {
                listening = IsPortListening(runtime.Config.ClientTunnelPort);
                if (!listening)
                    await Task.Delay(25);
            }

            Assert.True(listening, "Tunnel port did not start after enrollment.");
            Assert.True(runtime.IsEnrolled);
            Assert.Equal(1, authCalls);

            // A local connect (mstsc-equivalent) must NOT ask for the
            // Authentication Code again.
            using (var probe = new TcpClient())
            {
                await probe.ConnectAsync(System.Net.IPAddress.Loopback, runtime.Config.ClientTunnelPort);
                await Task.Delay(300);
            }

            Assert.Equal(1, authCalls);

            cts.Cancel();
            await Task.WhenAny(runTask, Task.Delay(2000));
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    /// <summary>
    /// An already-enrolled client must bind the tunnel listener without
    /// talking to the gateway first. A down server must not block the
    /// "Tunnel ready" state.
    /// </summary>
    [Fact(Timeout = 15000)]
    public async Task RunAsync_WhenAlreadyEnrolled_BindsListenerWithoutGateway()
    {
        var clientDir = Path.Combine(Path.GetTempPath(), "ssp-enrolled-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(clientDir);

        try
        {
            using var rsa = RsaCrypto.GenerateKeyPair();
            // Legacy-plaintext .cache.dat / .index.dat (pre-encryption
            // layout). ClientRuntime loads them via PemStore, which
            // decrypts/migrates them into the encrypted-at-rest envelope.
            await AtomicFile.WriteTextAsync(
                Path.Combine(clientDir, ".cache.dat"),
                RsaCrypto.ExportPrivateKeyPem(rsa));
            await AtomicFile.WriteTextAsync(
                Path.Combine(clientDir, ".index.dat"),
                RsaCrypto.ExportPublicKeyPem(rsa));

            var port = FreeTcpPort();
            var cfg = new ClientConfig
            {
                ApplicationName        = "RDP",
                ServerPublicKeyPem     = RsaCrypto.ExportPublicKeyPem(rsa),
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = FreeTcpPort(),
                LocalApplicationPort   = 3389,
                ClientTunnelPort       = port,
            };

            var runtime = await ClientRuntime.LoadOrCreateAsync(clientDir, cfg);
            Assert.True(runtime.IsEnrolled);

            var authCalls = 0;
            var tunnel = new ClientTunnelRuntime(runtime, () =>
            {
                Interlocked.Increment(ref authCalls);
                return Task.FromResult("should-not-be-called");
            });

            using var cts = new CancellationTokenSource();
            var runTask = Task.Run(() => tunnel.RunAsync(cts.Token));

            var listening = false;
            for (var i = 0; i < 200 && !listening; i++)
            {
                listening = IsPortListening(port);
                if (!listening)
                    await Task.Delay(25);
            }

            Assert.True(listening, "Already-enrolled client did not bind the tunnel port.");
            Assert.Equal(0, authCalls);

            cts.Cancel();
            await Task.WhenAny(runTask, Task.Delay(2000));
        }
        finally
        {
            try { Directory.Delete(clientDir, true); } catch { }
        }
    }

    /// <summary>
    /// EnsureEnrolledAsync is a no-op when the runtime is already
    /// enrolled — it must not open a TCP connection.
    /// </summary>
    [Fact]
    public async Task EnsureEnrolledAsync_WhenAlreadyEnrolled_DoesNotConnect()
    {
        var clientDir = Path.Combine(Path.GetTempPath(), "ssp-ensured-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(clientDir);

        try
        {
            using var rsa = RsaCrypto.GenerateKeyPair();
            // Legacy-plaintext .cache.dat / .index.dat (pre-encryption
            // layout). ClientRuntime loads them via PemStore, which
            // decrypts/migrates them into the encrypted-at-rest envelope.
            await AtomicFile.WriteTextAsync(
                Path.Combine(clientDir, ".cache.dat"),
                RsaCrypto.ExportPrivateKeyPem(rsa));
            await AtomicFile.WriteTextAsync(
                Path.Combine(clientDir, ".index.dat"),
                RsaCrypto.ExportPublicKeyPem(rsa));

            var cfg = new ClientConfig
            {
                ApplicationName        = "RDP",
                ServerPublicKeyPem     = RsaCrypto.ExportPublicKeyPem(rsa),
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = 1, // nothing listens here
                LocalApplicationPort   = 3389,
                ClientTunnelPort       = 3390,
            };

            var runtime = await ClientRuntime.LoadOrCreateAsync(clientDir, cfg);
            Assert.True(runtime.IsEnrolled);

            var protocol = new ClientProtocol(runtime);
            await protocol.EnsureEnrolledAsync();
        }
        finally
        {
            try { Directory.Delete(clientDir, true); } catch { }
        }
    }

    private static bool IsPortListening(int port)
    {
        return IPGlobalProperties.GetIPGlobalProperties()
            .GetActiveTcpListeners()
            .Any(endpoint => endpoint.Port == port);
    }

    private static int FreeTcpPort()
    {
        var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
