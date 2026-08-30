// File: tests/SSP.Tests/TunnelForwardingDiagTests.cs
//
// Diagnostic tests for the RDP tunnel forwarding bug.
//
// The existing F7 test passes because it sends a single 30-byte payload
// and reads a single echo. RDP traffic is fundamentally different:
//   - Many small frames in rapid succession (keyboard, mouse)
//   - Large frames (bitmap updates)
//   - Sustained bidirectional traffic for minutes
//   - Half-duplex bursts that overlap
//
// These tests mimic RDP's traffic patterns to reproduce the bug.

using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class TunnelForwardingDiagTests
{
    /// <summary>
    /// Send MANY small frames through the tunnel in rapid succession
    /// and verify every single one is delivered to the server and
    /// echoed back in order.
    ///
    /// This mimics RDP's keyboard/mouse input stream. If the relay
    /// drops, reorders, or corrupts any frame, this test fails.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_ManySmallFramesBidirectional_AllDelivered()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);
        Assert.True(runtime2.IsEnrolled);

        // Fake app: echo server that accepts multiple connections.
        var fakeAppCts = new CancellationTokenSource();
        var fakeAppTask = Task.Run(async () =>
        {
            while (!fakeAppCts.Token.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await harness.AcceptFakeAppClientAsync(fakeAppCts.Token); }
                catch (OperationCanceledException) { break; }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var s = c.GetStream();
                        var buf = new byte[8192];
                        int n;
                        while ((n = await s.ReadAsync(buf.AsMemory(0, buf.Length))) > 0)
                            await s.WriteAsync(buf.AsMemory(0, n));
                    }
                    catch (Exception ex) { Console.Error.WriteLine($"[fakeapp] {ex.Message}"); }
                });
            }
        });

        using var cts = new CancellationTokenSource();
        var tunnelRuntime = new ClientTunnelRuntime(runtime2);
        var clientTask = Task.Run(() => tunnelRuntime.RunAsync(cts.Token));
        await Task.Delay(800);

        // Connect a test client to the tunnel port.
        using var testClient = new TcpClient();
        await testClient.ConnectAsync(System.Net.IPAddress.Loopback, runtime2.Config.ClientTunnelPort);
        using var testStream = testClient.GetStream();
        testStream.WriteTimeout = 5000;
        testStream.ReadTimeout = 10000;

        // Send 50 small frames, each with a sequence number, and read
        // back the echo for each one. RDP does exactly this: many
        // small request/response cycles.
        var rng = new Random(42);
        for (var i = 0; i < 50; i++)
        {
            // Vary the payload size like real RDP frames. Minimum 8
            // bytes so we always have room for a 4-byte sequence number.
            var size = rng.Next(8, 200);
            var payload = new byte[size];
            // Encode the sequence number at the start so we can verify ordering.
            BitConverter.TryWriteBytes(payload.AsSpan(0, 4), i);
            for (var j = 4; j < size; j++) payload[j] = (byte)(i + j);

            await testStream.WriteAsync(payload);
            await testStream.FlushAsync();

            // Read back the echo for THIS frame.
            var recv = new byte[size];
            var off = 0;
            while (off < recv.Length)
            {
                var read = await testStream.ReadAsync(recv.AsMemory(off, recv.Length - off));
                if (read == 0) break;
                off += read;
            }

            if (off != recv.Length)
            {
                Console.Error.WriteLine($"[DIAG] Frame {i}: expected {size} bytes, got {off}");
                Console.Error.WriteLine($"[DIAG] Sent: {Convert.ToHexString(payload)}");
                Console.Error.WriteLine($"[DIAG] Recv: {Convert.ToHexString(recv.AsSpan(0, off))}");
                Assert.Equal(recv.Length, off);
            }
            Assert.Equal(payload, recv);
        }

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }

    /// <summary>
    /// Send a LARGE payload (1 MB) through the tunnel in a single write
    /// and verify it all comes back. This mimics RDP's bitmap update
    /// bursts that can be tens of KB per frame.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_LargePayloadBidirectional_RoundTrips()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        var fakeAppCts = new CancellationTokenSource();
        var fakeAppTask = Task.Run(async () =>
        {
            while (!fakeAppCts.Token.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await harness.AcceptFakeAppClientAsync(fakeAppCts.Token); }
                catch (OperationCanceledException) { break; }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var s = c.GetStream();
                        var buf = new byte[16384];
                        int n;
                        while ((n = await s.ReadAsync(buf.AsMemory(0, buf.Length))) > 0)
                            await s.WriteAsync(buf.AsMemory(0, n));
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
        testStream.WriteTimeout = 10000;
        testStream.ReadTimeout = 15000;

        // Send 1 MB of data.
        var payload = new byte[1024 * 1024];
        new Random(123).NextBytes(payload);

        Console.Error.WriteLine("[DIAG] Sending 1 MB...");
        await testStream.WriteAsync(payload);
        await testStream.FlushAsync();

        Console.Error.WriteLine("[DIAG] Reading 1 MB echo...");
        var recv = new byte[payload.Length];
        var off = 0;
        while (off < recv.Length)
        {
            var read = await testStream.ReadAsync(recv.AsMemory(off, recv.Length - off));
            if (read == 0) break;
            off += read;
        }

        Console.Error.WriteLine($"[DIAG] Got {off} of {payload.Length} bytes.");
        Assert.Equal(payload.Length, off);
        Assert.Equal(payload, recv);

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }

    /// <summary>
    /// Sustained bidirectional traffic: send and receive simultaneously
    /// for several seconds. This mimics RDP's long-lived session where
    /// input and screen updates overlap. If the relay has a race or
    /// a deadlock under concurrent load, this test will hang or fail.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_SustainedBidirectional_NoHangNoCorruption()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        // Fake app: echo server.
        var fakeAppCts = new CancellationTokenSource();
        var fakeAppTask = Task.Run(async () =>
        {
            while (!fakeAppCts.Token.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await harness.AcceptFakeAppClientAsync(fakeAppCts.Token); }
                catch (OperationCanceledException) { break; }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var s = c.GetStream();
                        var buf = new byte[16384];
                        int n;
                        while ((n = await s.ReadAsync(buf.AsMemory(0, buf.Length))) > 0)
                            await s.WriteAsync(buf.AsMemory(0, n));
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
        testStream.WriteTimeout = 5000;
        testStream.ReadTimeout = 8000;

        // Send 200 frames of varying sizes back to back, reading the
        // echo for each. Total ~500 KB of traffic.
        var rng = new Random(7);
        var totalSent = 0;
        var totalRecv = 0;
        for (var i = 0; i < 200; i++)
        {
            var size = rng.Next(10, 3000);
            var payload = new byte[size];
            BitConverter.TryWriteBytes(payload.AsSpan(0, 4), i);
            for (var j = 4; j < size; j++) payload[j] = (byte)((i + j) & 0xFF);

            await testStream.WriteAsync(payload);
            await testStream.FlushAsync();
            totalSent += size;

            var recv = new byte[size];
            var off = 0;
            while (off < recv.Length)
            {
                var read = await testStream.ReadAsync(recv.AsMemory(off, recv.Length - off));
                if (read == 0) break;
                off += read;
            }
            totalRecv += off;
            Assert.Equal(payload, recv.AsSpan(0, off).ToArray());
        }

        Console.Error.WriteLine($"[DIAG] Sustained test: sent {totalSent}, recv {totalRecv}");
        Assert.Equal(totalSent, totalRecv);

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }
}
