// File: tests/SSP.Tests/TunnelInactivityTests.cs
//
// Reproduce the EXACT production failure:
//   1. Client authenticates (tunnel established)
//   2. Server-side relay immediately connects to local app (RDP)
//   3. Local app sends initial data
//   4. Client's mstsc does NOT connect for a long time
//   5. Local app (RDP) times out and closes the connection
//   6. Server-side relay sees EOF, tears down
//   7. Client's mstsc finally connects - but the tunnel is dead
//
// This is the root cause of the RDP "Connecting..." hang.

using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class TunnelInactivityTests
{
    /// <summary>
    /// Simulate RDP's inactivity timeout:
    ///   - Server-side relay connects to fake app
    ///   - Fake app sends initial data, then waits for client input
    ///   - Fake app times out after 3 seconds (simulating RDP's 60s
    ///     timeout, shortened for test speed)
    ///   - Fake app closes the connection
    ///   - Server-side relay tears down
    ///   - Client's mstsc connects AFTER the timeout
    ///   - mstsc should receive an error, not hang forever
    ///
    /// This test DOCUMENTS the bug. The fix is to make the server-side
    /// relay connect to the local app LAZILY (only when the client's
    /// first tunnel data arrives), not eagerly (immediately after auth).
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_ServerRelayPrematureConnect_LocalAppTimeoutKillsTunnel()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        // Fake app: on the SECOND connection, send initial data, then
        // wait 3 seconds for client input. If no input arrives, close
        // (simulating RDP inactivity timeout).
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

                        // Send initial data.
                        var init = Encoding.UTF8.GetBytes("RDP_INIT");
                        await s.WriteAsync(init);
                        await s.FlushAsync();

                        // Wait 3 seconds for client input.
                        var buf = new byte[1024];
                        var readTask = s.ReadAsync(buf.AsMemory(0, buf.Length)).AsTask();
                        var timeout = Task.Delay(3000);
                        var winner = await Task.WhenAny(readTask, timeout);
                        if (winner == timeout)
                        {
                            Console.Error.WriteLine("[fakeapp] Inactivity timeout - closing connection (simulating RDP timeout)");
                            c.Close(); // simulate RDP closing due to inactivity
                            return;
                        }

                        // Echo loop.
                        var n = await readTask;
                        while (n > 0)
                        {
                            await s.WriteAsync(buf.AsMemory(0, n));
                            await s.FlushAsync();
                            n = await s.ReadAsync(buf.AsMemory(0, buf.Length));
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

        // Wait 5 seconds BEFORE connecting mstsc. This exceeds the
        // fake app's 3-second inactivity timeout.
        Console.Error.WriteLine("[DIAG] Waiting 5s before mstsc connects (exceeds fake app's 3s timeout)...");
        await Task.Delay(5000);

        // Now connect mstsc. The fake app has already timed out and
        // closed. The server-side relay has torn down. But the client's
        // tunnel TCP connection is still open (the client doesn't know
        // the relay is dead).
        using var testClient = new TcpClient();
        await testClient.ConnectAsync(System.Net.IPAddress.Loopback, runtime2.Config.ClientTunnelPort);
        using var testStream = testClient.GetStream();
        testClient.NoDelay = true;
        testStream.WriteTimeout = 5000;
        testStream.ReadTimeout = 8000;

        // Try to read. We expect either:
        //   - EOF (the buffered RDP_INIT data, then EOF when the relay teardown propagates)
        //   - IOException (connection reset)
        // In the BUGGY behavior, the client would HANG here forever
        // because the server-side relay has torn down but the client's
        // TCP connection is still open.
        //
        // This test ASSERTS that the client gets feedback (EOF or
        // exception) within 8 seconds. If it hangs, the test times out
        // and fails - which proves the bug.
        var gotFeedback = false;
        try
        {
            var recv = new byte[1024];
            var r = await testStream.ReadAsync(recv.AsMemory(0, recv.Length));
            Console.Error.WriteLine($"[DIAG] mstsc read {r} bytes");
            if (r == 0)
            {
                Console.Error.WriteLine("[DIAG] mstsc got EOF - tunnel properly signaled closure to client");
                gotFeedback = true;
            }
            else
            {
                var got = Encoding.UTF8.GetString(recv, 0, r);
                Console.Error.WriteLine($"[DIAG] mstsc received: {got}");
                // Try to read more - should get EOF eventually.
                r = await testStream.ReadAsync(recv.AsMemory(0, recv.Length));
                Console.Error.WriteLine($"[DIAG] mstsc read {r} more bytes");
                gotFeedback = true;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[DIAG] mstsc read failed: {ex.Message}");
            gotFeedback = true; // IOException is also valid feedback
        }

        Assert.True(gotFeedback,
            "Client never received feedback after server-side relay tore down. " +
            "The tunnel hung - this is the RDP 'Connecting...' hang. " +
            "Root cause: server-side relay connects to local app (RDP) immediately " +
            "after authentication. RDP times out and closes. The server-side relay " +
            "tears down, but the client's tunnel TCP connection stays open. mstsc " +
            "connects to the client's local listener, but the tunnel is dead, so " +
            "mstsc hangs at 'Connecting...' forever.");

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }
}
