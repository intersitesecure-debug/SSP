// File: tests/SSP.Tests/TunnelConcurrentPressureTests.cs
//
// Isolate the concurrent bidirectional failure with a SIMPLE, fixed
// protocol so we can see exactly what breaks.
//
// IMPORTANT: The enrollment connection on the server side ALSO creates
// a relay to the local app (this is by design - the server doesn't
// know if the client will keep the connection as a tunnel or close it).
// So the fake app will see TWO connections:
//   1. Enrollment relay connection (short-lived - client closes after enroll)
//   2. Real tunnel connection (future auth, long-lived)
// We must only assert on the SECOND connection.

using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class TunnelConcurrentPressureTests
{
    [Fact(Timeout = 30000)]
    public async Task Tunnel_ConcurrentFixedFrames_BothDirectionsDeliverAll()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);  // closes the enrollment tcp
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        const int FrameSize = 100;
        const int NumFrames = 30;

        // Fake app: only the SECOND connection is the real tunnel.
        // The first connection (enrollment relay) will be torn down
        // immediately. We use a signal to know when the second
        // connection arrives, and only count frames on that one.
        var fakeAppCts = new CancellationTokenSource();
        var realConnectionReady = new TaskCompletionSource<TcpClient>();
        var serverReceivedCount = 0;
        var serverSentCount = 0;
        var connectionIndex = 0;
        var fakeAppTask = Task.Run(async () =>
        {
            while (!fakeAppCts.Token.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await harness.AcceptFakeAppClientAsync(fakeAppCts.Token); }
                catch (OperationCanceledException) { break; }

                var idx = System.Threading.Interlocked.Increment(ref connectionIndex);
                if (idx == 1)
                {
                    // Enrollment relay connection - drain and let it die.
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using var s = c.GetStream();
                            var buf = new byte[1024];
                            while (await s.ReadAsync(buf.AsMemory(0, buf.Length)) > 0) { }
                        }
                        catch { }
                    });
                    continue;
                }

                // Real tunnel connection.
                realConnectionReady.TrySetResult(c);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var s = c.GetStream();
                        c.NoDelay = true;

                        var readerTask = Task.Run(async () =>
                        {
                            var buf = new byte[FrameSize];
                            for (var i = 0; i < NumFrames; i++)
                            {
                                var off = 0;
                                while (off < FrameSize)
                                {
                                    var r = await s.ReadAsync(buf.AsMemory(off, FrameSize - off));
                                    if (r == 0) { Console.Error.WriteLine($"[fakeapp-reader] EOF at frame {i}"); return; }
                                    off += r;
                                }
                                System.Threading.Interlocked.Increment(ref serverReceivedCount);
                            }
                        });

                        var writerTask = Task.Run(async () =>
                        {
                            var buf = new byte[FrameSize];
                            for (var i = 0; i < NumFrames; i++)
                            {
                                for (var j = 0; j < FrameSize; j++) buf[j] = (byte)(i + j);
                                try
                                {
                                    await s.WriteAsync(buf);
                                    await s.FlushAsync();
                                    System.Threading.Interlocked.Increment(ref serverSentCount);
                                    await Task.Delay(30);
                                }
                                catch (Exception ex)
                                {
                                    Console.Error.WriteLine($"[fakeapp-writer] frame {i}: {ex.Message}");
                                    return;
                                }
                            }
                        });

                        await Task.WhenAll(readerTask, writerTask);
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
        testStream.WriteTimeout = 5000;
        testStream.ReadTimeout = 10000;

        var clientReceivedCount = 0;
        var clientSentCount = 0;

        var clientReaderTask = Task.Run(async () =>
        {
            var buf = new byte[FrameSize];
            for (var i = 0; i < NumFrames; i++)
            {
                var off = 0;
                while (off < FrameSize)
                {
                    var r = await testStream.ReadAsync(buf.AsMemory(off, FrameSize - off));
                    if (r == 0) { Console.Error.WriteLine($"[client-reader] EOF at frame {i}"); return; }
                    off += r;
                }
                for (var j = 0; j < FrameSize; j++)
                {
                    if (buf[j] != (byte)(i + j))
                    {
                        Console.Error.WriteLine($"[client-reader] frame {i} byte {j}: expected {(byte)(i+j)}, got {buf[j]}");
                        Assert.Fail($"Frame corruption at frame {i} byte {j}");
                    }
                }
                System.Threading.Interlocked.Increment(ref clientReceivedCount);
            }
        });

        var clientWriterTask = Task.Run(async () =>
        {
            var buf = new byte[FrameSize];
            for (var i = 0; i < NumFrames; i++)
            {
                for (var j = 0; j < FrameSize; j++) buf[j] = (byte)(0xFF - i - j);
                try
                {
                    await testStream.WriteAsync(buf);
                    await testStream.FlushAsync();
                    System.Threading.Interlocked.Increment(ref clientSentCount);
                    await Task.Delay(40);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[client-writer] frame {i}: {ex.Message}");
                    return;
                }
            }
        });

        var timeout = Task.Delay(15000);
        var finished = await Task.WhenAny(Task.WhenAll(clientReaderTask, clientWriterTask), timeout);
        if (finished == timeout)
        {
            Assert.Fail($"DEADLOCK: client sent {clientSentCount}/{NumFrames}, " +
                        $"client received {clientReceivedCount}/{NumFrames}, " +
                        $"server received {serverReceivedCount}/{NumFrames}, " +
                        $"server sent {serverSentCount}/{NumFrames}");
        }

        await Task.Delay(1000);

        Console.Error.WriteLine($"[DIAG] client sent {clientSentCount}, client received {clientReceivedCount}");
        Console.Error.WriteLine($"[DIAG] server sent {serverSentCount}, server received {serverReceivedCount}");

        Assert.Equal(NumFrames, clientSentCount);
        Assert.Equal(NumFrames, clientReceivedCount);
        Assert.Equal(NumFrames, serverSentCount);
        Assert.Equal(NumFrames, serverReceivedCount);

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }
}
