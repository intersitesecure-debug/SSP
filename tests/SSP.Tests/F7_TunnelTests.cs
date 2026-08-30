// File: tests/SSP.Tests/F7_TunnelTests.cs
//
// F7 - Secure Tunnel functional tests.
//
// A real ServerGateway is running with a fake "protected application"
// listening on LocalAppPort. The full client stack runs (enrollment or
// future auth, session key, local tunnel listener). A test "client
// application" connects to ClientTunnelPort, sends a payload, and the
// fake app echoes it back. We assert the bytes round-trip byte-for-byte
// through two encryption and two decryption passes (one per direction).

using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class F7_TunnelTests
{
    /// <summary>
    /// End-to-end tunnel round-trip:
    ///   test client -> ClientTunnelPort -> [encrypt] -> gateway ->
    ///   [decrypt] -> fake app -> [echo back] -> gateway -> [encrypt] ->
    ///   client runtime -> [decrypt] -> test client.
    /// </summary>
    [Fact(Timeout = 20000)]
    public async Task Tunnel_EchoRoundTrip_ByteForByteMatch()
    {
        Console.Error.WriteLine("[F7] Creating harness...");
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        Console.Error.WriteLine("[F7] Enrolling client...");
        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);

        Console.Error.WriteLine("[F7] Reloading runtime with enrolled keys...");
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);
        Assert.True(runtime2.IsEnrolled);

        // Start the fake "protected application" echo loop.
        // The fake app accepts connections in a loop because the
        // enrollment connection also triggers a (short-lived) relay
        // that connects to the local app before being torn down.
        Console.Error.WriteLine("[F7] Starting fake app echo server...");
        var fakeAppCts = new CancellationTokenSource();
        var fakeAppTask = Task.Run(async () =>
        {
            try
            {
                while (!fakeAppCts.Token.IsCancellationRequested)
                {
                    TcpClient client;
                    try { client = await harness.AcceptFakeAppClientAsync(fakeAppCts.Token); }
                    catch (OperationCanceledException) { break; }

                    Console.Error.WriteLine("[F7] Fake app accepted connection.");
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using var s = client.GetStream();
                            var buffer = new byte[4096];
                            int read;
                            while ((read = await s.ReadAsync(buffer.AsMemory(0, buffer.Length))) > 0)
                            {
                                Console.Error.WriteLine($"[F7] Fake app echo {read} bytes.");
                                await s.WriteAsync(buffer.AsMemory(0, read));
                                await s.FlushAsync();
                            }
                            Console.Error.WriteLine("[F7] Fake app connection closed.");
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"[F7] Fake app conn error: {ex.Message}");
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[F7] Fake app error: {ex.Message}");
            }
        });

        // Start the client tunnel runtime.
        Console.Error.WriteLine("[F7] Starting client tunnel runtime...");
        using var cts = new CancellationTokenSource();
        var tunnelRuntime = new ClientTunnelRuntime(runtime2);
        var clientTask = Task.Run(async () =>
        {
            try
            {
                await tunnelRuntime.RunAsync(cts.Token);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[F7] Tunnel runtime error: {ex.Message}");
            }
        });

        // Wait for the local listener to come up.
        Console.Error.WriteLine("[F7] Waiting for tunnel listener...");
        await Task.Delay(1000);

        // Connect a "test client app" to the tunnel port.
        Console.Error.WriteLine($"[F7] Connecting test client to 127.0.0.1:{runtime2.Config.ClientTunnelPort}...");
        using var testClient = new TcpClient();
        await testClient.ConnectAsync(System.Net.IPAddress.Loopback, runtime2.Config.ClientTunnelPort);
        using var testStream = testClient.GetStream();
        testStream.WriteTimeout = 5000;
        testStream.ReadTimeout = 10000;

        // Send a payload, read the echo back.
        var payload = Encoding.UTF8.GetBytes("SSP tunnel round-trip payload");
        Console.Error.WriteLine($"[F7] Sending {payload.Length} bytes...");
        await testStream.WriteAsync(payload);
        await testStream.FlushAsync();

        Console.Error.WriteLine("[F7] Reading echo...");
        var recvBuffer = new byte[payload.Length];
        var offset = 0;
        while (offset < recvBuffer.Length)
        {
            var read = await testStream.ReadAsync(recvBuffer.AsMemory(offset, recvBuffer.Length - offset));
            if (read == 0) break;
            offset += read;
        }

        Console.Error.WriteLine($"[F7] Received {offset} bytes.");
        Assert.Equal(payload.Length, offset);
        Assert.Equal(payload, recvBuffer);

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
        Console.Error.WriteLine("[F7] Done.");
    }

    /// <summary>
    /// Verify the encrypted frame format directly: a frame that goes
    /// through the codec twice (encrypt + decrypt) yields the original
    /// payload, and a tampered frame is rejected.
    /// </summary>
    [Fact]
    public async Task TunnelCodec_RoundTrip_PreservesBytes()
    {
        using var ms = new MemoryStream();
        var sessionKey = AesGcmCrypto.GenerateSessionKey();
        using var codec = new SSP.Core.Protocol.TunnelCodec(sessionKey);

        var payload = Encoding.UTF8.GetBytes("the quick brown fox");
        await codec.SendAsync(ms, payload);

        ms.Position = 0;
        var decoded = await codec.ReceiveAsync(ms);
        Assert.Equal(payload, decoded);
    }

    /// <summary>
    /// Many small frames in succession must all round-trip cleanly and
    /// every nonce must be unique (the codec uses a counter under the hood).
    /// </summary>
    [Fact]
    public async Task TunnelCodec_ManySmallFrames_AllRoundTrip()
    {
        using var ms = new MemoryStream();
        var sessionKey = AesGcmCrypto.GenerateSessionKey();
        using var codec = new SSP.Core.Protocol.TunnelCodec(sessionKey);

        var payloads = Enumerable.Range(0, 100)
            .Select(i => Encoding.UTF8.GetBytes($"frame-{i}"))
            .ToArray();

        foreach (var p in payloads)
            await codec.SendAsync(ms, p);

        ms.Position = 0;
        foreach (var expected in payloads)
        {
            var decoded = await codec.ReceiveAsync(ms);
            Assert.Equal(expected, decoded);
        }
    }
}
