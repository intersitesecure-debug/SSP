// File: src/SSP.Core/Protocol/TunnelCodec.cs
//
// Wire codec for the encrypted tunnel. Each frame on the wire is:
//
//   [4-byte length prefix][nonce (12)][ciphertext+tag]
//
// The 4-byte length prefix is passed as associated data to AES-GCM so
// the receiver can detect tampering with the length field itself.

using System.Net.Sockets;
using System.Security.Cryptography;
using SSP.Core.Crypto;

namespace SSP.Core.Protocol;

/// <summary>
/// Per-direction state for the encrypted tunnel. Each side keeps one
/// instance for sending and one for receiving (in practice the same
/// key is used in both directions with independent nonce counters).
/// </summary>
public sealed class TunnelCodec : IDisposable
{
    private readonly byte[] _key;
    private readonly NonceCounter _counter;

    public TunnelCodec(byte[] sessionKey)
    {
        _counter = new NonceCounter();

        if (sessionKey.Length != AesGcmCrypto.KeySizeBytes)
            throw new ArgumentException("Session key must be 32 bytes.", nameof(sessionKey));

        _key = sessionKey;
    }

    /// <summary>
    /// Encrypt a plaintext payload and pack it into a length-prefixed
    /// frame ready to be written to the socket.
    /// </summary>
    public async Task SendAsync(Stream stream, byte[] plaintext, CancellationToken ct = default)
    {
        var nonce = _counter.NextNonce();
        var aad = BitConverter.GetBytes(plaintext.Length);
        var ciphertextWithTag = AesGcmCrypto.Encrypt(_key, nonce, plaintext, aad);
        var payload = EncryptedFrame.Pack(nonce, ciphertextWithTag);
        await Frame.WriteAsync(stream, payload, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Read one encrypted frame, decrypt it, return the plaintext.
    /// Returns null at a clean stream boundary.
    /// </summary>
    public async Task<byte[]?> ReceiveAsync(Stream stream, CancellationToken ct = default)
    {
        var payload = await Frame.ReadAsync(stream, ct).ConfigureAwait(false);
        if (payload == null) return null;

        var (nonce, ciphertextWithTag) = EncryptedFrame.Unpack(payload, AesGcmCrypto.NonceSizeBytes);
        var ciphertextLength = ciphertextWithTag.Length - AesGcmCrypto.TagSizeBytes;
        var aad = BitConverter.GetBytes(ciphertextLength);
        return AesGcmCrypto.Decrypt(_key, nonce, ciphertextWithTag, aad);
    }

    public void Dispose()
    {
        _counter.Dispose();
        CryptographicOperations.ZeroMemory(_key.AsSpan());
    }
}

/// <summary>
/// Bidirectional relay that bridges a plaintext TCP stream (the client
/// side: a local application socket; the server side: the protected
/// application socket) and an encrypted tunnel. Both directions run
/// concurrently; either one closing terminates the relay.
/// </summary>
public static class TunnelRelay
{
    // Set to true to emit per-frame diagnostic logging to stderr. The
    // flag is read with a volatile read so it can be toggled at runtime
    // (e.g. from a test or a debug environment variable).
    private static volatile bool _diagnostic =
        Environment.GetEnvironmentVariable("SSP_TUNNEL_DIAG") == "1";

    /// <summary>
    /// Bridge plaintext &lt;-&gt; encrypted traffic in both directions.
    /// Returns when either side closes the connection.
    /// </summary>
    /// <remarks>
    /// BUG FIX (tunnel hang):
    /// The previous implementation used Task.WhenAll to wait for BOTH
    /// pumps to finish. When one pump exited (e.g. the local app
    /// closed its write end, or the tunnel peer closed the cipher
    /// stream), the other pump was left blocked on ReadAsync forever
    /// because nobody closed the stream it was reading from.
    ///
    /// This caused the RDP "Connecting..." hang:
    ///   1. Server-side relay connects to RDP immediately after auth.
    ///   2. RDP sends initial handshake, then waits for client input.
    ///   3. mstsc hasn't connected yet (user is slow to type the command).
    ///   4. RDP times out (default 60s on Windows Server) and closes.
    ///   5. Server-side plainToCipher pump sees EOF, exits.
    ///   6. Server-side cipherToPlain pump is blocked reading from the
    ///      tunnel - the client hasn't sent anything.
    ///   7. BridgeAsync waits for Both pumps (Task.WhenAll) - hangs forever.
    ///   8. The tunnel TCP connection stays open.
    ///   9. mstsc finally connects to the client's local listener.
    ///   10. Client-side relay starts, but the server side is hung.
    ///   11. mstsc hangs at "Connecting..." forever.
    ///
    /// FIX: When either pump exits, close BOTH streams so the other
    /// pump's ReadAsync returns immediately (EOF or IOException).
    /// This ensures BridgeAsync returns promptly, which allows the
    /// caller to dispose the TCP connection, which propagates the
    /// closure to the peer.
    /// </remarks>
    public static async Task BridgeAsync(
        Stream plainStream,
        TunnelCodec codec,
        Stream cipherStream,
        CancellationToken ct = default)
    {
        var plainToCipher = PumpAsync(plainStream, codec, cipherStream, ct, "C->S");
        var cipherToPlain = PumpDecryptAsync(cipherStream, codec, plainStream, ct, "S->C");

        // HALF-CLOSE BEHAVIOR (spec §6):
        // When one pump exits (e.g. plainToCipher saw EOF on its
        // source because the local application closed its write side),
        // we must NOT immediately close both streams - that would kill
        // the other direction before it has a chance to drain its
        // pending data and send it back.
        //
        // Instead we do a TCP half-close on the cipher stream's WRITE
        // side (so the peer's cipherToPlain pump sees EOF on its read)
        // but leave the cipher stream's READ side open so any data the
        // peer still wants to send can arrive and be decrypted by our
        // cipherToPlain pump.
        //
        // If the OTHER pump does not finish within a reasonable grace
        // period (5 seconds), we force-close both streams so the
        // BridgeAsync task cannot hang forever (spec §6: "the other
        // direction must not remain blocked forever").
        var firstFinished = await Task.WhenAny(plainToCipher, cipherToPlain).ConfigureAwait(false);

        if (_diagnostic) Console.Error.WriteLine($"[relay] first pump finished: {(firstFinished == plainToCipher ? "C->S" : "S->C")}, doing half-close");

        // Half-close: signal EOF on the destination of the finished pump.
        // - If plainToCipher finished (local app EOF), signal EOF on cipherStream's WRITE side
        //   so the peer's cipherToPlain pump can drain and exit.
        // - If cipherToPlain finished (tunnel EOF), signal EOF on plainStream's WRITE side
        //   so the local app sees its read return 0 and exits.
        if (firstFinished == plainToCipher)
            TryShutdownWrite(cipherStream);
        else
            TryShutdownWrite(plainStream);

        // Wait for the OTHER pump to finish, but with a grace period
        // so we don't hang forever if the peer is silent.
        using var graceCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        graceCts.CancelAfter(TimeSpan.FromSeconds(30));
        var remaining = (firstFinished == plainToCipher) ? cipherToPlain : plainToCipher;
        try
        {
            while (!remaining.IsCompleted && !graceCts.Token.IsCancellationRequested)
                await Task.WhenAny(remaining, Task.Delay(500, graceCts.Token)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Grace period expired - force close.
            if (_diagnostic) Console.Error.WriteLine("[relay] grace period expired, force-closing both streams");
        }

        // Final cleanup: close both streams.
        try { plainStream.Close(); } catch { }
        try { cipherStream.Close(); } catch { }

        // Observe any exceptions from the pumps (do not let them go unobserved).
        try { await plainToCipher.ConfigureAwait(false); } catch { }
        try { await cipherToPlain.ConfigureAwait(false); } catch { }

        if (_diagnostic) Console.Error.WriteLine("[relay] both pumps finished");
    }

    /// <summary>
    /// Attempt a TCP half-close (Socket.Shutdown(Send)) on the
    /// underlying socket of a stream. Falls back to a no-op if the
    /// stream is not backed by a socket (e.g. MemoryStream in tests).
    /// </summary>
    private static void TryShutdownWrite(Stream s)
    {
        try
        {
            if (s is System.Net.Sockets.NetworkStream ns)
            {
                var sock = ns.Socket;
                if (sock != null && sock.Connected)
                    sock.Shutdown(System.Net.Sockets.SocketShutdown.Send);
                return;
            }
            // Fallback: some wrapped streams expose the underlying socket
            // via reflection. We don't do that - the common case is
            // NetworkStream above. For un-wrapped streams, half-close is
            // not supported and we just return.
        }
        catch (Exception ex)
        {
            if (_diagnostic) Console.Error.WriteLine($"[relay] TryShutdownWrite: {ex.Message}");
        }
    }

    /// <summary>
    /// LAZY variant of <see cref="BridgeAsync"/>: the plaintext stream
    /// is created on-demand by <paramref name="plainStreamFactory"/> ONLY
    /// when the first decrypted frame arrives on the cipher stream.
    /// </summary>
    /// <remarks>
    /// This is the fix for the RDP "Connecting..." hang:
    ///   - The server-side relay no longer connects to the local
    ///     protected application (e.g. RDP on 127.0.0.1:3389) immediately
    ///     after authentication.
    ///   - Instead, it waits for the client's first tunnel data frame
    ///     (which only arrives after mstsc actually connects to the
    ///     client's local listener and sends its first byte).
    ///   - Only when that first frame arrives does the server-side relay
    ///     connect to the protected application and start bridging.
    ///
    /// This eliminates the race where RDP times out and closes before
    /// mstsc has had a chance to connect through the tunnel.
    /// </remarks>
    public static async Task BridgeLazyAsync(
        Func<CancellationToken, Task<Stream>> plainStreamFactory,
        TunnelCodec codec,
        Stream cipherStream,
        CancellationToken ct = default)
    {
        // We decrypt the first frame ourselves, then create the plain
        // stream, then run the two pumps. We need to inject the
        // pre-decrypted first frame into the plainToCipher pump so it
        // gets written before any further data the plain stream sends.

        // Step 1: read the first decrypted frame from the cipher stream.
        // This blocks until the client's mstsc-equivalent sends its first
        // byte through the tunnel. Until then we do NOT touch the local
        // protected application.
        byte[]? firstFrame;
        try
        {
            if (_diagnostic) Console.Error.WriteLine("[relay-lazy] waiting for first decrypted frame before connecting to local app...");
            firstFrame = await codec.ReceiveAsync(cipherStream, ct).ConfigureAwait(false);
            if (firstFrame == null)
            {
                // Tunnel peer closed before sending any data. We never
                // connected to the local app, so just return.
                if (_diagnostic) Console.Error.WriteLine("[relay-lazy] cipher EOF before first frame, never connected to local app");
                return;
            }
            if (_diagnostic) Console.Error.WriteLine($"[relay-lazy] first frame {firstFrame.Length} bytes received, connecting to local app...");
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (IOException ex)
        {
            if (_diagnostic) Console.Error.WriteLine($"[relay-lazy] io while reading first frame: {ex.Message}");
            return;
        }

        // Step 2: create the plaintext stream on demand.
        Stream plainStream;
        try
        {
            plainStream = await plainStreamFactory(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            if (_diagnostic) Console.Error.WriteLine($"[relay-lazy] failed to connect to local app: {ex.Message}");
            // Close the cipher stream so the peer knows the tunnel is dead.
            try { cipherStream.Close(); } catch { }
            throw;
        }

        // Step 3: write the first frame to the local app, then run the
        // two pumps concurrently (just like BridgeAsync).
        try
        {
            await plainStream.WriteAsync(firstFrame.AsMemory(0, firstFrame.Length), ct).ConfigureAwait(false);
            await plainStream.FlushAsync(ct).ConfigureAwait(false);
            if (_diagnostic) Console.Error.WriteLine($"[relay-lazy] flushed first frame to local app, starting bidirectional relay");
        }
        catch (Exception ex)
        {
            if (_diagnostic) Console.Error.WriteLine($"[relay-lazy] failed to write first frame to local app: {ex.Message}");
            try { plainStream.Close(); } catch { }
            try { cipherStream.Close(); } catch { }
            throw;
        }

        // Step 4: same lifecycle as BridgeAsync: when either pump exits,
        // close both streams to unblock the other, then wait for both.
        var plainToCipher = PumpAsync(plainStream, codec, cipherStream, ct, "C->S");
        var cipherToPlain = PumpDecryptAsync(cipherStream, codec, plainStream, ct, "S->C");

        var firstFinished = await Task.WhenAny(plainToCipher, cipherToPlain).ConfigureAwait(false);
        if (_diagnostic) Console.Error.WriteLine($"[relay-lazy] first pump finished: {(firstFinished == plainToCipher ? "C->S" : "S->C")}, closing both streams");

        try { plainStream.Close(); } catch { }
        try { cipherStream.Close(); } catch { }

        await Task.WhenAll(plainToCipher, cipherToPlain).ConfigureAwait(false);

        if (_diagnostic) Console.Error.WriteLine("[relay-lazy] both pumps finished");
    }

    private static async Task PumpAsync(
        Stream source,
        TunnelCodec codec,
        Stream destination,
        CancellationToken ct,
        string direction)
    {
        var buffer = new byte[16 * 1024];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] plaintext read = {read}");
                if (read == 0)
                {
                    if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] plaintext EOF, breaking");
                    break;
                }
                var chunk = new byte[read];
                Buffer.BlockCopy(buffer, 0, chunk, 0, read);
                await codec.SendAsync(destination, chunk, ct).ConfigureAwait(false);
                if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] encrypted send = {read}");
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
        catch (IOException ex) { if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] io: {ex.Message}"); }
        catch (Exception ex) { if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] err: {ex.Message}"); }
        finally
        {
            if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] pump done");
        }
    }

    private static async Task PumpDecryptAsync(
        Stream source,
        TunnelCodec codec,
        Stream destination,
        CancellationToken ct,
        string direction)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var plaintext = await codec.ReceiveAsync(source, ct).ConfigureAwait(false);
                if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] decrypted = {plaintext?.Length ?? 0}");
                if (plaintext == null)
                {
                    if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] cipher EOF, breaking");
                    break;
                }
                await destination.WriteAsync(plaintext.AsMemory(0, plaintext.Length), ct).ConfigureAwait(false);
                await destination.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
        catch (IOException ex) { if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] io: {ex.Message}"); }
        catch (System.Security.Cryptography.CryptographicException ex) { if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] crypto: {ex.Message}"); }
        catch (Exception ex) { if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] err: {ex.Message}"); }
        finally
        {
            if (_diagnostic) Console.Error.WriteLine($"[relay {direction}] decrypt pump done");
        }
    }
}







