// File: tests/SSP.Tests/TunnelTimingTests.cs
//
// Test the timing scenario that causes RDP to hang:
//   1. Client authenticates (tunnel established)
//   2. Server-side relay immediately connects to local app
//   3. Local app sends initial data (like RDP X.224 handshake)
//   4. Client's mstsc has NOT connected yet
//   5. After a delay, mstsc connects
//   6. mstsc should receive the buffered initial data
//
// If the tunnel drops the buffered data or closes the connection
// before mstsc connects, this test fails.

using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class TunnelTimingTests
{
    /// <summary>
    /// The server-side relay connects to the local app immediately
    /// after authentication. The local app sends data right away.
    /// The client's mstsc connects AFTER a delay. The client must
    /// receive ALL the data the local app sent before mstsc connected,
    /// plus any data sent after.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_DataSentBeforeClientConnects_IsDeliveredWhenClientConnects()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        // Fake app: on the SECOND connection (first is enrollment relay),
        // immediately send a burst of data, then keep the connection open.
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

                        // Immediately send data (like RDP X.224 handshake).
                        var burst = Encoding.UTF8.GetBytes("PRE_CONNECT_BURST_DATA_1234567890");
                        await s.WriteAsync(burst);
                        await s.FlushAsync();

                        // Then echo loop.
                        var buf = new byte[4096];
                        int n;
                        while ((n = await s.ReadAsync(buf.AsMemory(0, buf.Length))) > 0)
                        {
                            await s.WriteAsync(buf.AsMemory(0, n));
                            await s.FlushAsync();
                        }
                    }
                    catch (Exception ex) { Console.Error.WriteLine($"[fakeapp] {ex.Message}"); }
                });
            }
        });

        using var cts = new CancellationTokenSource();
        var tunnelRuntime = new ClientTunnelRuntime(runtime2);
        var clientTask = Task.Run(() => tunnelRuntime.RunAsync(cts.Token));

        // Wait for the client's local listener to start.
        await Task.Delay(800);

        // Now wait ANOTHER 2 seconds BEFORE connecting mstsc.
        // During this time, the server-side relay has already connected
        // to the fake app, and the fake app has sent "PRE_CONNECT_BURST...".
        // That data is sitting in the client's TCP receive buffer.
        Console.Error.WriteLine("[DIAG] Waiting 2s before mstsc connects...");
        await Task.Delay(2000);

        using var testClient = new TcpClient();
        await testClient.ConnectAsync(System.Net.IPAddress.Loopback, runtime2.Config.ClientTunnelPort);
        using var testStream = testClient.GetStream();
        testClient.NoDelay = true;
        testStream.WriteTimeout = 5000;
        testStream.ReadTimeout = 10000;

        // Read the pre-connect burst.
        var expected = Encoding.UTF8.GetBytes("PRE_CONNECT_BURST_DATA_1234567890");
        var recv = new byte[expected.Length];
        var off = 0;
        while (off < expected.Length)
        {
            var r = await testStream.ReadAsync(recv.AsMemory(off, recv.Length - off));
            if (r == 0)
            {
                Console.Error.WriteLine($"[DIAG] FAIL: EOF after {off} bytes, expected {expected.Length}");
                Assert.Fail("Tunnel closed before delivering data that was sent before mstsc connected. " +
                            "The server-side relay's connection to the local app was torn down while " +
                            "data was still buffered.");
            }
            off += r;
        }

        var got = Encoding.UTF8.GetString(recv);
        Console.Error.WriteLine($"[DIAG] Received pre-connect burst: {got}");
        Assert.Equal(expected, recv);

        // Now send data and verify echo works.
        var payload = Encoding.UTF8.GetBytes("AFTER_CONNECT");
        await testStream.WriteAsync(payload);
        await testStream.FlushAsync();

        var echo = new byte[payload.Length];
        off = 0;
        while (off < echo.Length)
        {
            var r = await testStream.ReadAsync(echo.AsMemory(off, echo.Length - off));
            if (r == 0) break;
            off += r;
        }
        Assert.Equal(payload, echo);

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }
}
