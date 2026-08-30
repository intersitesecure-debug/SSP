// File: src/SSP.Core/Protocol/Frame.cs
//
// Length-prefixed binary framing used on every SSP TCP connection.
//
// Wire format (little-endian):
//
//   [0..3]   uint32 length          (number of bytes that follow)
//   [4..N]   payload                (raw bytes, may be encrypted)
//
// For the encrypted tunnel the payload layout is:
//
//   [0..11]  12-byte AES-GCM nonce
//   [12..M]  ciphertext
//   [M..M+16]16-byte GCM authentication tag
//
// The 4-byte length prefix is also passed as associated data to AES-GCM
// so an attacker cannot silently truncate or extend a frame.

using System.IO;
using System.Net.Sockets;

namespace SSP.Core.Protocol;

/// <summary>
/// Static helpers for reading and writing length-prefixed frames on a
/// TCP stream. Every method performs full reads - if the connection
/// closes mid-frame an <see cref="EndOfStreamException"/> is thrown.
/// </summary>
public static class Frame
{
    /// <summary>Maximum frame payload size (16 MiB). Larger frames are rejected.</summary>
    public const int MaxPayloadSize = 16 * 1024 * 1024;

    /// <summary>Write a single frame: 4-byte length prefix + payload.</summary>
    public static async Task WriteAsync(Stream stream, byte[] payload, CancellationToken ct = default)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));
        if (payload.Length > MaxPayloadSize)
            throw new InvalidOperationException($"Frame payload exceeds {MaxPayloadSize} bytes.");

        var header = new byte[4];
        header[0] = (byte)(payload.Length & 0xFF);
        header[1] = (byte)((payload.Length >> 8) & 0xFF);
        header[2] = (byte)((payload.Length >> 16) & 0xFF);
        header[3] = (byte)((payload.Length >> 24) & 0xFF);

        await stream.WriteAsync(header.AsMemory(0, 4), ct).ConfigureAwait(false);
        await stream.WriteAsync(payload.AsMemory(0, payload.Length), ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Read a single frame. Returns null when the peer has cleanly
    /// closed the connection before sending any bytes (i.e. at a frame
    /// boundary). Throws <see cref="EndOfStreamException"/> if the
    /// connection closes mid-frame.
    /// </summary>
    public static async Task<byte[]?> ReadAsync(Stream stream, CancellationToken ct = default)
    {
        var header = await ReadExactAsync(stream, 4, ct).ConfigureAwait(false);
        if (header == null) return null;

        var length = header[0]
                   | (header[1] << 8)
                   | (header[2] << 16)
                   | (header[3] << 24);

        if (length < 0 || length > MaxPayloadSize)
            throw new InvalidDataException($"Frame length {length} is out of range.");

        if (length == 0)
            return Array.Empty<byte>();

        var payload = await ReadExactAsync(stream, length, ct).ConfigureAwait(false);
        if (payload == null)
            throw new EndOfStreamException("Connection closed mid-frame.");
        return payload;
    }

    /// <summary>
    /// Read exactly <paramref name="count"/> bytes. Returns null if the
    /// stream is closed before any byte is read.
    /// </summary>
    public static async Task<byte[]?> ReadExactAsync(Stream stream, int count, CancellationToken ct = default)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), ct).ConfigureAwait(false);
            if (read == 0)
            {
                if (offset == 0) return null;
                throw new EndOfStreamException($"Stream closed after {offset} of {count} expected bytes.");
            }
            offset += read;
        }
        return buffer;
    }

    /// <summary>Write a frame to a NetworkStream (sync wrapper).</summary>
    public static void Write(Stream stream, byte[] payload)
    {
        WriteAsync(stream, payload).GetAwaiter().GetResult();
    }

    /// <summary>Read a frame from a NetworkStream (sync wrapper).</summary>
    public static byte[]? Read(Stream stream)
    {
        return ReadAsync(stream).GetAwaiter().GetResult();
    }
}

/// <summary>
/// Convenience wrapper that bundles a nonce with its ciphertext payload
/// when sending an encrypted frame over the tunnel.
/// </summary>
public static class EncryptedFrame
{
    /// <summary>Build the on-wire payload: nonce || ciphertext||tag.</summary>
    public static byte[] Pack(byte[] nonce, byte[] ciphertextWithTag)
    {
        var output = new byte[nonce.Length + ciphertextWithTag.Length];
        Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
        Buffer.BlockCopy(ciphertextWithTag, 0, output, nonce.Length, ciphertextWithTag.Length);
        return output;
    }

    /// <summary>Split a payload produced by <see cref="Pack"/> back into its parts.</summary>
    public static (byte[] nonce, byte[] ciphertextWithTag) Unpack(byte[] payload, int nonceSize)
    {
        if (payload.Length < nonceSize)
            throw new InvalidDataException("Encrypted frame too short to contain a nonce.");

        var nonce = new byte[nonceSize];
        Buffer.BlockCopy(payload, 0, nonce, 0, nonceSize);
        var ciphertextWithTag = new byte[payload.Length - nonceSize];
        Buffer.BlockCopy(payload, nonceSize, ciphertextWithTag, 0, ciphertextWithTag.Length);
        return (nonce, ciphertextWithTag);
    }
}
