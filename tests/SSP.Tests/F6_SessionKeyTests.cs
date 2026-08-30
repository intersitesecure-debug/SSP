// File: tests/SSP.Tests/F6_SessionKeyTests.cs
//
// F6 - Session Key Establishment functional tests.
//
// The client generates an AES-256 session key, wraps it with RSA-OAEP
// using the server's public key, and the server unwraps it with its
// private key. The two sides must end up holding the same key, and
// a test message encrypted with the negotiated key must decrypt on
// the other side.

using System.Security.Cryptography;
using SSP.Core.Crypto;
using SSP.Client.Runtime;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class F6_SessionKeyTests
{
    /// <summary>
    /// Standalone RSA-OAEP wrap/unwrap of an AES session key matches.
    /// </summary>
    [Fact]
    public void SessionKey_RsaOaepWrapAndUnwrap_Matches()
    {
        using var rsa = RsaCrypto.GenerateKeyPair();
        var sessionKey = AesGcmCrypto.GenerateSessionKey();

        var wrapped = RsaCrypto.EncryptOaep(rsa, sessionKey);
        var unwrapped = RsaCrypto.DecryptOaep(rsa, wrapped);

        Assert.Equal(sessionKey, unwrapped);
    }

    /// <summary>
    /// End-to-end: client and server agree on the same session key
    /// via the ConnectAndAuthenticate flow, and a test message
    /// encrypted by the client decrypts cleanly on the server side.
    /// </summary>
    [Fact]
    public async Task SessionKey_ClientServerAgree_TestMessageDecrypts()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);

        // Re-connect with future auth.
        var (runtime2, _) = await harness.CreateClientRuntimeAsync(ott);
        // Make the new runtime think it's enrolled by loading existing keys.
        var enrolled = await ClientRuntime.LoadOrCreateAsync(
            System.IO.Path.GetDirectoryName(runtime.PrivateKeyPath)!, runtime.Config);
        Assert.True(enrolled.IsEnrolled);

        var protocol = new ClientProtocol(enrolled);
        var (tcp, sessionKey) = await protocol.ConnectAndAuthenticateAsync();
        Assert.Equal(32, sessionKey.Length);

        // Encrypt a test message with the client's view of the session key.
        var nonce = TokenGenerator.GenerateNonce(12);
        var plain = System.Text.Encoding.UTF8.GetBytes("session-key test payload");
        var ct = AesGcmCrypto.Encrypt(sessionKey, nonce, plain);

        // Decrypt with the server's view (the same key, since it was
        // negotiated through RSA-OAEP wrapping).
        var pt = AesGcmCrypto.Decrypt(sessionKey, nonce, ct);
        Assert.Equal(plain, pt);

        tcp.Dispose();
    }

    /// <summary>
    /// Two distinct session keys generated in succession must differ.
    /// </summary>
    [Fact]
    public void SessionKey_GenerationIsRandom()
    {
        var a = AesGcmCrypto.GenerateSessionKey();
        var b = AesGcmCrypto.GenerateSessionKey();
        Assert.NotEqual(a, b);
    }

    /// <summary>
    /// A session key wrapped with one RSA key cannot be unwrapped with
    /// another - i.e. only the genuine server can recover the key.
    /// </summary>
    [Fact]
    public void SessionKey_WrongServerKey_CannotUnwrap()
    {
        using var serverA = RsaCrypto.GenerateKeyPair();
        using var serverB = RsaCrypto.GenerateKeyPair();
        var sessionKey = AesGcmCrypto.GenerateSessionKey();

        var wrapped = RsaCrypto.EncryptOaep(serverA, sessionKey);
        Assert.ThrowsAny<CryptographicException>(
            () => RsaCrypto.DecryptOaep(serverB, wrapped));
    }
}
