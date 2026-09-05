// File: tests/SSP.Tests/F3_CryptoTests.cs
//
// F3 - Cryptography Layer functional tests.
//
// These tests do NOT exercise the network. They validate every
// cryptographic primitive required by the spec:
//   - RSA key pair generation
//   - RSA signature over a nonce
//   - RSA signature verification (positive + negative)
//   - RSA-OAEP encrypt / decrypt round-trip
//   - AES-256-GCM session key generation
//   - AES-GCM encrypt / decrypt round-trip
//   - Nonce uniqueness across many calls
//   - Frame length-prefixed round-trip

using SSP.Core.Crypto;
using SSP.Core.Protocol;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace SSP.Tests;

public class F3_CryptoTests
{
    // ─── RSA ──────────────────────────────────────────────────────

    [Fact]
    public void Rsa_GenerateKeyPair_ProducesNonEmptyPem()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var priv = RsaCrypto.ExportPrivateKeyPem(rsa);
        var pub  = RsaCrypto.ExportPublicKeyPem(rsa);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", priv);
        Assert.Contains("-----BEGIN PUBLIC KEY-----", pub);
        Assert.True(priv.Length > 400);
        Assert.True(pub.Length > 200);
    }

    [Fact]
    public void Rsa_SignAndVerify_Nonce_RoundTrips()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var nonce = TokenGenerator.GenerateNonce(32);
        var sig = RsaCrypto.Sign(rsa, nonce);
        Assert.True(RsaCrypto.Verify(rsa, nonce, sig));
    }

    [Fact]
    public void Rsa_Verify_RejectsTamperedNonce()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var nonce = TokenGenerator.GenerateNonce(32);
        var sig = RsaCrypto.Sign(rsa, nonce);

        var tampered = (byte[])nonce.Clone();
        tampered[0] ^= 0xFF;

        Assert.False(RsaCrypto.Verify(rsa, tampered, sig));
    }

    [Fact]
    public void Rsa_Verify_RejectsTamperedSignature()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var nonce = TokenGenerator.GenerateNonce(32);
        var sig = RsaCrypto.Sign(rsa, nonce);

        sig[0] ^= 0xFF;
        Assert.False(RsaCrypto.Verify(rsa, nonce, sig));
    }

    [Fact]
    public void Rsa_ImportExport_RoundTrip()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var privPem = RsaCrypto.ExportPrivateKeyPem(rsa);
        var pubPem  = RsaCrypto.ExportPublicKeyPem(rsa);

        using var rsa2 = RsaCrypto.ImportPrivateKeyPem(privPem);
        using var rsa3 = RsaCrypto.ImportPublicKeyPem(pubPem);

        var nonce = TokenGenerator.GenerateNonce(32);
        var sig = RsaCrypto.Sign(rsa2, nonce);
        Assert.True(RsaCrypto.Verify(rsa3, nonce, sig));
    }

    [Fact]
    public void Rsa_PublicKeyFingerprint_IsDeterministic()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var fp1 = RsaCrypto.ComputePublicKeyFingerprint(rsa);
        var fp2 = RsaCrypto.ComputePublicKeyFingerprint(rsa);
        Assert.Equal(fp1, fp2);
        Assert.Equal(64, fp1.Length); // SHA-256 hex
    }

    [Fact]
    public void Rsa_DifferentKeys_HaveDifferentFingerprints()
    {
        using var a = RsaCrypto.GenerateKeyPair();
        using var b = RsaCrypto.GenerateKeyPair();
        Assert.NotEqual(
            RsaCrypto.ComputePublicKeyFingerprint(a),
            RsaCrypto.ComputePublicKeyFingerprint(b));
    }

    // ─── RSA-OAEP ─────────────────────────────────────────────────

    [Fact]
    public void Rsa_Oaep_RoundTrips_AESKey()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var sessionKey = AesGcmCrypto.GenerateSessionKey();
        var wrapped = RsaCrypto.EncryptOaep(rsa, sessionKey);
        var unwrapped = RsaCrypto.DecryptOaep(rsa, wrapped);
        Assert.Equal(sessionKey, unwrapped);
    }

    [Fact]
    public void Rsa_Oaep_Decrypt_WithWrongKey_Throws()
    {
        using var rsa1 = RsaCrypto.GenerateKeyPair();
        using var rsa2 = RsaCrypto.GenerateKeyPair();
        var sessionKey = AesGcmCrypto.GenerateSessionKey();
        var wrapped = RsaCrypto.EncryptOaep(rsa1, sessionKey);
        Assert.ThrowsAny<CryptographicException>(
            () => RsaCrypto.DecryptOaep(rsa2, wrapped));
    }

    // ─── AES-GCM ──────────────────────────────────────────────────

    [Fact]
    public void AesGcm_GenerateSessionKey_Is32Bytes()
    {
        var key = AesGcmCrypto.GenerateSessionKey();
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void AesGcm_GenerateSessionKey_IsRandom()
    {
        var a = AesGcmCrypto.GenerateSessionKey();
        var b = AesGcmCrypto.GenerateSessionKey();
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void AesGcm_EncryptDecrypt_RoundTrips()
    {
        var key   = AesGcmCrypto.GenerateSessionKey();
        var nonce = TokenGenerator.GenerateNonce(12);
        var plain = Encoding.UTF8.GetBytes("hello SSP tunnel world");

        var ct = AesGcmCrypto.Encrypt(key, nonce, plain);
        var pt = AesGcmCrypto.Decrypt(key, nonce, ct);

        Assert.Equal(plain, pt);
    }

    [Fact]
    public void AesGcm_Encrypt_OutputIncludesTag()
    {
        var key   = AesGcmCrypto.GenerateSessionKey();
        var nonce = TokenGenerator.GenerateNonce(12);
        var plain = Encoding.UTF8.GetBytes("payload");

        var ct = AesGcmCrypto.Encrypt(key, nonce, plain);
        Assert.Equal(plain.Length + AesGcmCrypto.TagSizeBytes, ct.Length);
    }

    [Fact]
    public void AesGcm_Decrypt_RejectsTamperedCiphertext()
    {
        var key   = AesGcmCrypto.GenerateSessionKey();
        var nonce = TokenGenerator.GenerateNonce(12);
        var plain = Encoding.UTF8.GetBytes("payload");

        var ct = AesGcmCrypto.Encrypt(key, nonce, plain);
        ct[0] ^= 0xFF; // tamper

        Assert.ThrowsAny<CryptographicException>(
            () => AesGcmCrypto.Decrypt(key, nonce, ct));
    }

    [Fact]
    public void AesGcm_Decrypt_RejectsWrongKey()
    {
        var key1 = AesGcmCrypto.GenerateSessionKey();
        var key2 = AesGcmCrypto.GenerateSessionKey();
        var nonce = TokenGenerator.GenerateNonce(12);
        var plain = Encoding.UTF8.GetBytes("payload");

        var ct = AesGcmCrypto.Encrypt(key1, nonce, plain);
        Assert.ThrowsAny<CryptographicException>(
            () => AesGcmCrypto.Decrypt(key2, nonce, ct));
    }

    // ─── Nonce uniqueness ─────────────────────────────────────────

    [Fact]
    public void NonceCounter_ReturnsUniqueNonces_10000Iterations()
    {
        using var counter = new NonceCounter();
        var seen = new HashSet<string>();
        for (var i = 0; i < 10_000; i++)
        {
            var nonce = counter.NextNonce();
            Assert.Equal(12, nonce.Length);
            var key = Convert.ToHexString(nonce);
            Assert.True(seen.Add(key), $"Nonce reuse at iteration {i}: {key}");
        }
    }

    [Fact]
    public async Task NonceCounter_IsThreadSafe()
    {
        using var counter = new NonceCounter();
        var seen = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>();
        var parallel = Enumerable.Range(0, 10_000)
            .Select(_ => Task.Run(() =>
            {
                var n = counter.NextNonce();
                Assert.True(seen.TryAdd(Convert.ToHexString(n), 0),
                    $"Nonce reuse detected: {Convert.ToHexString(n)}");
            }));

        // Awaited rather than Task.WaitAll: blocking a test thread can
        // deadlock the run, and await also surfaces a failing assertion
        // inside any of the tasks directly.
        await Task.WhenAll(parallel);
        Assert.Equal(10_000, seen.Count);
    }

    // ─── Token Generator ──────────────────────────────────────────

    [Fact]
    public void OneTimeToken_IsBase64Url_NoPadding()
    {
        var token = TokenGenerator.GenerateOneTimeToken();
        Assert.DoesNotContain("+", token);
        Assert.DoesNotContain("/", token);
        Assert.DoesNotContain("=", token);
        // 32 raw bytes -> ~43 base64url chars
        Assert.True(token.Length >= 42 && token.Length <= 44);
    }

    [Fact]
    public void OneTimeToken_HashIsDeterministic()
    {
        var token = TokenGenerator.GenerateOneTimeToken();
        var h1 = TokenGenerator.HashOneTimeToken(token);
        var h2 = TokenGenerator.HashOneTimeToken(token);
        Assert.Equal(h1, h2);
        Assert.Equal(64, h1.Length); // SHA-256 hex
    }

    [Fact]
    public void AuthenticationCode_Is10Digits_FirstNonZero()
    {
        for (var i = 0; i < 100; i++)
        {
            var code = TokenGenerator.GenerateAuthenticationCode();
            Assert.Equal(10, code.Length);
            Assert.NotEqual('0', code[0]);
            Assert.All(code, c => Assert.True(c >= '0' && c <= '9'));
        }
    }

    [Fact]
    public void AuthenticationCode_RemainingDigitsIncludeZero_AndFirstDigitNeverZero()
    {
        var sawZeroAfterFirst = false;
        for (var i = 0; i < 5_000; i++)
        {
            var code = TokenGenerator.GenerateAuthenticationCode();
            Assert.Equal(10, code.Length);
            Assert.InRange(code[0], '1', '9');
            if (code.IndexOf('0', 1) >= 0)
                sawZeroAfterFirst = true;
        }

        Assert.True(sawZeroAfterFirst,
            "Unbiased generation must be able to produce 0 in digits 2-10.");
    }

    [Fact]
    public void AuthenticationCode_FirstDigitCoversOneThroughNine()
    {
        var seen = new HashSet<char>();
        for (var i = 0; i < 5_000 && seen.Count < 9; i++)
            seen.Add(TokenGenerator.GenerateAuthenticationCode()[0]);

        Assert.Equal(9, seen.Count);
        Assert.DoesNotContain('0', seen);
    }

    [Fact]
    public void ConstantTimeEquals_HandlesEqualAndDifferent()
    {
        Assert.True(TokenGenerator.ConstantTimeEquals("abc", "abc"));
        Assert.False(TokenGenerator.ConstantTimeEquals("abc", "abd"));
        Assert.False(TokenGenerator.ConstantTimeEquals("abc", "abcd"));
    }

    // ─── Frame ────────────────────────────────────────────────────

    [Fact]
    public async Task Frame_WriteRead_RoundTrips()
    {
        using var ms = new MemoryStream();
        var payload = Encoding.UTF8.GetBytes("hello frame");
        await Frame.WriteAsync(ms, payload);
        ms.Position = 0;
        var read = await Frame.ReadAsync(ms);
        Assert.Equal(payload, read);
    }

    [Fact]
    public async Task Frame_ReadReturnsNull_OnCleanClose()
    {
        using var ms = new MemoryStream();
        var read = await Frame.ReadAsync(ms);
        Assert.Null(read);
    }

    [Fact]
    public async Task Frame_ReadThrows_OnTruncatedFrame()
    {
        // Header says 100 bytes but stream has 0 bytes after header.
        using var ms = new MemoryStream();
        ms.Write(new byte[] { 100, 0, 0, 0 }, 0, 4);
        ms.Position = 0;
        await Assert.ThrowsAsync<EndOfStreamException>(() => Frame.ReadAsync(ms));
    }

    [Fact]
    public async Task Frame_RejectsOversizedPayload()
    {
        using var ms = new MemoryStream();
        var huge = new byte[Frame.MaxPayloadSize + 1];
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Frame.WriteAsync(ms, huge));
    }

    /// <summary>
    /// Purely synchronous (Pack/Unpack are plain byte manipulation), so this
    /// is a plain void test rather than an async one without an await.
    /// </summary>
    [Fact]
    public void EncryptedFrame_PackUnpack_RoundTrips()
    {
        var nonce = TokenGenerator.GenerateNonce(12);
        var ct = new byte[] { 1, 2, 3, 4, 5 };
        var packed = EncryptedFrame.Pack(nonce, ct);
        var (n, c) = EncryptedFrame.Unpack(packed, 12);
        Assert.Equal(nonce, n);
        Assert.Equal(ct, c);
    }
}
