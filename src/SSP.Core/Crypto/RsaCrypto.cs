// File: src/SSP.Core/Crypto/RsaCrypto.cs
//
// RSA cryptography helpers used by both SSP.Server and SSP.Client.
// Provides:
//   - RSA key pair generation (PEM serializable)
//   - Signing and verification (RSA-SHA256)
//   - RSA-OAEP encryption / decryption (used to wrap AES session keys)
//
// All operations use a 3072-bit key by default which is the current
// NIST recommendation for RSA keys used beyond 2030.

using System.Security.Cryptography;
using System.Text;

namespace SSP.Core.Crypto;

/// <summary>
/// Stateless helper around <see cref="RSA"/>. Every method creates its own
/// RSA instance and disposes it when finished so the caller never has to
/// think about lifetime.
/// </summary>
public static class RsaCrypto
{
    /// <summary>Default RSA key size in bits.</summary>
    public const int DefaultKeySizeBits = 3072;

    /// <summary>SHA-256 hash algorithm used for signing.</summary>
    public static readonly HashAlgorithmName SigningHash = HashAlgorithmName.SHA256;

    /// <summary>
    /// Generate a new RSA key pair and return it as a disposable instance.
    /// Caller is responsible for disposing the returned object.
    /// </summary>
    public static RSA GenerateKeyPair(int keySizeBits = DefaultKeySizeBits)
    {
        if (keySizeBits < 2048)
            throw new ArgumentOutOfRangeException(nameof(keySizeBits),
                "RSA key size must be at least 2048 bits.");

        var rsa = RSA.Create(keySizeBits);
        return rsa;
    }

    /// <summary>Export the private key in PKCS#8 PEM format.</summary>
    public static string ExportPrivateKeyPem(RSA rsa)
    {
        var bytes = rsa.ExportPkcs8PrivateKey();
        return PemEncoder.Encode("PRIVATE KEY", bytes);
    }

    /// <summary>Export the public key in SubjectPublicKeyInfo PEM format.</summary>
    public static string ExportPublicKeyPem(RSA rsa)
    {
        var bytes = rsa.ExportSubjectPublicKeyInfo();
        return PemEncoder.Encode("PUBLIC KEY", bytes);
    }

    /// <summary>Load an RSA instance from a PEM-encoded private key.</summary>
    public static RSA ImportPrivateKeyPem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    /// <summary>Load an RSA instance from a PEM-encoded public key.</summary>
    public static RSA ImportPublicKeyPem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    /// <summary>Sign a byte buffer using RSA-SHA256 with PKCS#1 v1.5 padding.</summary>
    public static byte[] Sign(RSA rsa, byte[] data)
    {
        return rsa.SignData(data, SigningHash, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Verify an RSA-SHA256 signature.</summary>
    public static bool Verify(RSA rsa, byte[] data, byte[] signature)
    {
        return rsa.VerifyData(data, signature, SigningHash, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Encrypt a small buffer (e.g. an AES session key) using RSA-OAEP
    /// with SHA-256. Input length must be smaller than the RSA modulus
    /// size minus 2 * hash length - 2.
    /// </summary>
    public static byte[] EncryptOaep(RSA rsa, byte[] data)
    {
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>Decrypt a buffer previously encrypted with <see cref="EncryptOaep"/>.</summary>
    public static byte[] DecryptOaep(RSA rsa, byte[] ciphertext)
    {
        return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>
    /// Compute the SHA-256 fingerprint of a public key. The fingerprint is
    /// taken over the DER-encoded SubjectPublicKeyInfo bytes, returned as
    /// a lowercase hex string. This is the value stored on the server
    /// when a client is enrolled.
    /// </summary>
    public static string ComputePublicKeyFingerprint(RSA rsa)
    {
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spki);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Compute the SHA-256 fingerprint of a public key directly from its
    /// PEM representation. Used by the server when it receives a public
    /// key from a client and needs to look it up.
    /// </summary>
    public static string ComputePublicKeyFingerprintFromPem(string publicKeyPem)
    {
        using var rsa = ImportPublicKeyPem(publicKeyPem);
        return ComputePublicKeyFingerprint(rsa);
    }
}

/// <summary>
/// Minimal RFC 7468 PEM encoder. .NET 8 ships with ImportFromPem but
/// does not provide a public encoder, so we implement one here.
/// </summary>
internal static class PemEncoder
{
    public static string Encode(string label, byte[] bytes)
    {
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).AppendLine("-----");
        var base64 = Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks);
        sb.AppendLine(base64);
        sb.Append("-----END ").Append(label).AppendLine("-----");
        return sb.ToString();
    }
}
