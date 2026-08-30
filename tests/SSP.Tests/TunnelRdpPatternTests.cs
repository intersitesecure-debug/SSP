// File: tests/SSP.Tests/TunnelRdpPatternTests.cs
//
// Tests that reproduce the RDP tunnel forwarding failure pattern:
// concurrent bidirectional traffic with unsolicited server-to-client
// updates (screen updates) overlapping client-to-server input.
//
// The fake "RDP server" sends fixed-size screen-update frames so the
// client reader can parse them unambiguously.

using System.Net.Sockets;
using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class TunnelRdpPatternTests
{
    /// <summary>
    /// Mimic an RDP-like server: it sends UNSOLICITED fixed-size data
    /// to the client (screen updates) AND echoes client input. Both
    /// directions run concurrently. If the relay cannot handle
    /// concurrent send+receive on the same tunnel, this test will hang
    /// or deadlock.
    ///
    /// The fake RDP server sends 256-byte frames (4-byte seq + 252-byte
    /// body) so the client reader can parse them without framing
    /// ambiguity.
    /// </summary>
    [Fact(Timeout = 30000)]
    public async Task Tunnel_ConcurrentBidirectional_RdpPattern_Works()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        const int ServerFrameSize = 256;
        const int NumServerFrames = 20;
        const int ClientFrameSize = 64;
        const int NumClientFrames = 20;

        // Fake "RDP server": on the SECOND connection (first is
        // enrollment relay), run TWO concurrent loops:
        //   - reader: reads client input (fixed-size frames)
        //   - writer: sends fixed-size screen-update frames
        var fakeAppCts = new CancellationTokenSource();
        var connectionIndex = 0;
        var serverReceivedCount = 0;
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

                        var readerTask = Task.Run(async () =>
                        {
                            var buf = new byte[ClientFrameSize];
                            for (var i = 0; i < NumClientFrames; i++)
                            {
                                var off = 0;
                                while (off < ClientFrameSize)
                                {
                                    var r = await s.ReadAsync(buf.AsMemory(off, ClientFrameSize - off));
                                    if (r == 0) return;
                                    off += r;
                                }
                                System.Threading.Interlocked.Increment(ref serverReceivedCount);
                            }
                        });

                        var writerTask = Task.Run(async () =>
                        {
                            for (var i = 0; i < NumServerFrames; i++)
                            {
                                var frame = new byte[ServerFrameSize];
                                BitConverter.TryWriteBytes(frame.AsSpan(0, 4), i);
                                for (var j = 4; j < ServerFrameSize; j++) frame[j] = (byte)(i + j);
                                try
                                {
                                    await s.WriteAsync(frame);
                                    await s.FlushAsync();
                                    await Task.Delay(50);
                                }
                                catch { return; }
                            }
                        });

                        await Task.WhenAll(readerTask, writerTask);
                    }
                    catch (Exception ex) { Console.Error.WriteLine($"[fakerdp] {ex.Message}"); }
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

        var clientReceivedFrames = new System.Collections.Concurrent.ConcurrentBag<int>();
        var clientSentCount = 0;

        var readerTask = Task.Run(async () =>
        {
            try
            {
                for (var i = 0; i < NumServerFrames; i++)
                {
                    var frame = new byte[ServerFrameSize];
                    var off = 0;
                    while (off < ServerFrameSize)
                    {
                        var r = await testStream.ReadAsync(frame.AsMemory(off, ServerFrameSize - off));
                        if (r == 0) return;
                        off += r;
                    }
                    var seq = BitConverter.ToInt32(frame, 0);
                    clientReceivedFrames.Add(seq);
                    // Verify body integrity.
                    for (var j = 4; j < ServerFrameSize; j++)
                    {
                        if (frame[j] != (byte)(seq + j))
                        {
                            Assert.Fail($"Frame {seq} body corruption at byte {j}: expected {(byte)(seq+j)}, got {frame[j]}");
                        }
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[client-reader] {ex.Message}"); }
        });

        var writerTask = Task.Run(async () =>
        {
            try
            {
                for (var i = 0; i < NumClientFrames; i++)
                {
                    var input = new byte[ClientFrameSize];
                    BitConverter.TryWriteBytes(input.AsSpan(0, 4), i);
                    await testStream.WriteAsync(input);
                    await testStream.FlushAsync();
                    System.Threading.Interlocked.Increment(ref clientSentCount);
                    await Task.Delay(60);
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[client-writer] {ex.Message}"); }
        });

        var timeout = Task.Delay(15000);
        var finished = await Task.WhenAny(Task.WhenAll(readerTask, writerTask), timeout);
        if (finished == timeout)
        {
            Assert.Fail($"DEADLOCK: client sent {clientSentCount}/{NumClientFrames}, " +
                        $"client received {clientReceivedFrames.Count}/{NumServerFrames}, " +
                        $"server received {serverReceivedCount}/{NumClientFrames}");
        }

        await Task.Delay(1000);

        Console.Error.WriteLine($"[DIAG] client sent {clientSentCount}, client received {clientReceivedFrames.Count}");
        Console.Error.WriteLine($"[DIAG] server received {serverReceivedCount}");

        Assert.Equal(NumClientFrames, clientSentCount);
        Assert.Equal(NumServerFrames, clientReceivedFrames.Count);
        Assert.Equal(NumClientFrames, serverReceivedCount);

        cts.Cancel();
        fakeAppCts.Cancel();
        await Task.WhenAny(clientTask, Task.Delay(2000));
    }
}
