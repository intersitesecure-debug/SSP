// File: tests/SSP.Tests/TunnelLargeBurstTests.cs
//
// RDP does TLS negotiation inside the tunnel. TLS handshake messages
// can be several KB (certificates, key exchange). If the tunnel
// corrupts a single byte, TLS fails and RDP hangs.
//
// These tests send large bursts (simulating TLS handshakes and RDP
// bitmap updates) and verify byte-for-byte integrity.

using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class TunnelLargeBurstTests
{
    /// <summary>
    /// Send a 16 KB burst (typical TLS certificate message size) and
    /// verify it arrives byte-for-byte. Then send another 16 KB burst
    /// in the reverse direction. This mimics the TLS handshake phase
    /// of RDP.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_16KBurstBidirectional_ByteForByte()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        // Fake app: on the SECOND connection (first is enrollment relay),
        // read exactly 16384 bytes, then send exactly 16384 bytes back.
        var fakeAppCts = new CancellationTokenSource();
        var connectionIndex = 0;
        var fakeAppTask = Task.Run(async () =>
        {
            while (!fakeAppCts.Token.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await harness.AcceptFakeAppClientAsync(fakeAppCts.Token); }
                catch (OperationCanceledException) { break; }
                var idx = System.Threading.Interlocked.Increment(ref connectionIndex);
                if (idx == 1) { _ = Task.Run(async () => { try { using var s = c.GetStream(); var b = new byte[1024]; while (await s.ReadAsync(b.AsMemory(0, b.Length)) > 0) { } } catch { } }); continue; }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var s = c.GetStream();
                        c.NoDelay = true;

                        // Read 16384 bytes from client.
                        var recv = new byte[16384];
                        var off = 0;
                        while (off < 16384)
                        {
                            var r = await s.ReadAsync(recv.AsMemory(off, 16384 - off));
                            if (r == 0) break;
                            off += r;
                        }
                        Assert.Equal(16384, off);

                        // Send 16384 bytes to client.
                        var send = new byte[16384];
                        for (var i = 0; i < send.Length; i++) send[i] = (byte)(i & 0xFF);
                        await s.WriteAsync(send);
                        await s.FlushAsync();
                    }
                    catch (Exception ex) { Console.Error.WriteLine($"[fakeapp] {ex.Message}"); }
                });
            }
        });

        using var cts = new CancellationTokenSource();
        var tunnelRuntime = new ClientTunnelRuntime(runtime2);
        var clientTask = Task.Run(() => tunnelRuntime.RunAsync(cts.Token));
        await Task.Delay(800);

        using var testClient = new TcpClient();
        await testClient.ConnectAsync(System.Net.IPAddress.Loopback, runtime2.Config.ClientTunnelPort);
        using var testStream = testClient.GetStream();
        testClient.NoDelay = true;
        testStream.WriteTimeout = 10000;
        testStream.ReadTimeout = 15000;

        // Send 16384 bytes.
        var payload = new byte[16384];
        for (var i = 0; i < payload.Length; i++) payload[i] = (byte)((i * 7) & 0xFF);
        await testStream.WriteAsync(payload);
        await testStream.FlushAsync();

        // Read 16384 bytes back.
        var recvBuf = new byte[16384];
        var off = 0;
        while (off < 16384)
        {
            var r = await testStream.ReadAsync(recvBuf.AsMemory(off, 16384 - off));
            if (r == 0) break;
            off += r;
        }

        Assert.Equal(16384, off);

        // Verify byte-for-byte.
        var expected = new byte[16384];
        for (var i = 0; i < expected.Length; i++) expected[i] = (byte)(i & 0xFF);
        for (var i = 0; i < 16384; i++)
        {
            if (recvBuf[i] != expected[i])
            {
                Assert.Fail($"Byte corruption at offset {i}: expected {expected[i]}, got {recvBuf[i]}");
            }
        }

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }

    /// <summary>
    /// Send a 64 KB burst (typical RDP bitmap update size) in ONE write
    /// and verify it arrives byte-for-byte. This tests that the relay's
    /// 16 KB read buffer doesn't lose data when the app writes more than
    /// 16 KB in a single send() call.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_64KBSingleWrite_ByteForByte()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        var fakeAppCts = new CancellationTokenSource();
        var connectionIndex = 0;
        var fakeAppTask = Task.Run(async () =>
        {
            while (!fakeAppCts.Token.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await harness.AcceptFakeAppClientAsync(fakeAppCts.Token); }
                catch (OperationCanceledException) { break; }
                var idx = System.Threading.Interlocked.Increment(ref connectionIndex);
                if (idx == 1) { _ = Task.Run(async () => { try { using var s = c.GetStream(); var b = new byte[1024]; while (await s.ReadAsync(b.AsMemory(0, b.Length)) > 0) { } } catch { } }); continue; }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var s = c.GetStream();
                        c.NoDelay = true;
                        var recv = new byte[65536];
                        var off = 0;
                        while (off < 65536)
                        {
                            var r = await s.ReadAsync(recv.AsMemory(off, 65536 - off));
                            if (r == 0) break;
                            off += r;
                        }
                        Assert.Equal(65536, off);
                        await s.WriteAsync(recv);
                        await s.FlushAsync();
                    }
                    catch (Exception ex) { Console.Error.WriteLine($"[fakeapp] {ex.Message}"); }
                });
            }
        });

        using var cts = new CancellationTokenSource();
        var tunnelRuntime = new ClientTunnelRuntime(runtime2);
        var clientTask = Task.Run(() => tunnelRuntime.RunAsync(cts.Token));
        await Task.Delay(800);

        using var testClient = new TcpClient();
        await testClient.ConnectAsync(System.Net.IPAddress.Loopback, runtime2.Config.ClientTunnelPort);
        using var testStream = testClient.GetStream();
        testClient.NoDelay = true;
        testStream.WriteTimeout = 10000;
        testStream.ReadTimeout = 15000;

        // Send 64 KB in ONE write.
        var payload = new byte[65536];
        new Random(42).NextBytes(payload);
        await testStream.WriteAsync(payload);
        await testStream.FlushAsync();

        // Read 64 KB back.
        var recvBuf = new byte[65536];
        var off = 0;
        while (off < 65536)
        {
            var r = await testStream.ReadAsync(recvBuf.AsMemory(off, 65536 - off));
            if (r == 0) break;
            off += r;
        }
        Assert.Equal(65536, off);
        Assert.Equal(payload, recvBuf);

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }
}
