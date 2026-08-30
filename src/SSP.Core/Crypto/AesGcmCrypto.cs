// File: src/SSP.Core/Crypto/AesGcmCrypto.cs
//
// AES-GCM helpers used by the secure tunnel.
//
// Design constraints mandated by the specification:
//   - Every encrypted frame MUST use a unique nonce.
//   - Nonces are 96 bits (12 bytes), the optimal length for GCM.
//   - Frames are authenticated with the associated data passed by the caller
//     (typically the 4-byte length prefix) so the receiver can reject
//     truncated/rewritten frames before decrypting.
//
// Nonce uniqueness strategy:
//   The caller is responsible for providing a unique nonce per call.
//   <see cref="NonceCounter"/> offers a deterministic counter-based
//   generator which is the recommended pattern when a single key is in
//   use on one side of a conversation. The counter is 64 bits, the
//   remaining 32 bits are randomly chosen at construction time to
//   reduce the chance of collision across reboots / re-keying.

using System.Security.Cryptography;

namespace SSP.Core.Crypto;

/// <summary>
/// Stateless AES-GCM encryption helper. The session key is held by the
/// caller; this class never stores any state.
/// </summary>
public static class AesGcmCrypto
{
    /// <summary>AES-256 key length in bytes.</summary>
    public const int KeySizeBytes = 32;

    /// <summary>GCM nonce length in bytes (96 bits).</summary>
    public const int NonceSizeBytes = 12;

    /// <summary>GCM authentication tag length in bytes (128 bits).</summary>
    public const int TagSizeBytes = 16;

    /// <summary>
    /// Generate a cryptographically random AES-256 session key.
    /// </summary>
    public static byte[] GenerateSessionKey()
    {
        return RandomNumberGenerator.GetBytes(KeySizeBytes);
    }

    /// <summary>
    /// Encrypt a plaintext buffer with the given key and nonce.
    /// The returned buffer layout is: [ciphertext (== plaintext length)][tag].
    /// </summary>
    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[]? associatedData = null)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"AES key must be {KeySizeBytes} bytes.", nameof(key));
        if (nonce.Length != NonceSizeBytes)
            throw new ArgumentException($"Nonce must be {NonceSizeBytes} bytes.", nameof(nonce));

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];
        using var gcm = new AesGcm(key, TagSizeBytes);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var output = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, output, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, output, ciphertext.Length, tag.Length);
        return output;
    }

    /// <summary>
    /// Decrypt a buffer produced by <see cref="Encrypt"/>. Throws
    /// <see cref="CryptographicException"/> if the tag does not verify.
    /// </summary>
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[]? associatedData = null)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"AES key must be {KeySizeBytes} bytes.", nameof(key));
        if (nonce.Length != NonceSizeBytes)
            throw new ArgumentException($"Nonce must be {NonceSizeBytes} bytes.", nameof(nonce));
        if (ciphertextWithTag.Length < TagSizeBytes)
            throw new ArgumentException("Ciphertext too short to contain a tag.", nameof(ciphertextWithTag));

        var ciphertextLength = ciphertextWithTag.Length - TagSizeBytes;
        var ciphertext = new byte[ciphertextLength];
        var tag = new byte[TagSizeBytes];
        Buffer.BlockCopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(ciphertextWithTag, ciphertextLength, tag, 0, TagSizeBytes);

        var plaintext = new byte[ciphertextLength];
        using var gcm = new AesGcm(key, TagSizeBytes);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }
}

/// <summary>
/// Deterministic nonce generator built around a 64-bit counter. The high
/// 32 bits of the 96-bit nonce are randomly seeded at construction so two
/// sessions that share a key (which should never happen in SSP, but we
/// still defend against it) cannot reuse each other's nonces.
/// </summary>
public sealed class NonceCounter : IDisposable
{
    private readonly byte[] _prefix = new byte[4];
    private long _counter;
    private readonly object _lock = new();

    public NonceCounter(long startCounter = 0)
    {
        RandomNumberGenerator.Fill(_prefix);
        _counter = startCounter;
    }

    /// <summary>
    /// Return the next unique 12-byte nonce. Thread-safe.
    /// </summary>
    public byte[] NextNonce()
    {
        lock (_lock)
        {
            if (_counter < 0)
                throw new InvalidOperationException("Nonce counter exhausted.");

            var nonce = new byte[AesGcmCrypto.NonceSizeBytes];
            Buffer.BlockCopy(_prefix, 0, nonce, 0, 4);
            var counterBytes = BitConverter.GetBytes(_counter);
            // Write counter in big-endian so the low bytes are at the end.
            nonce[4]  = counterBytes[7];
            nonce[5]  = counterBytes[6];
            nonce[6]  = counterBytes[5];
            nonce[7]  = counterBytes[4];
            nonce[8]  = counterBytes[3];
            nonce[9]  = counterBytes[2];
            nonce[10] = counterBytes[1];
            nonce[11] = counterBytes[0];
            _counter++;
            return nonce;
        }
    }

    public void Dispose()
    {
        // No unmanaged resources, but we implement IDisposable so callers
        // can use 'using' and so future versions can zero the prefix.
    }
}
