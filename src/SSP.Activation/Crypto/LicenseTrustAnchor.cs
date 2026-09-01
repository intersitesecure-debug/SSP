using System.Security.Cryptography;

namespace SSP.Activation;

/// <summary>
/// The trusted public key of the SSP Licensing Authority — the only key material held by
/// the relying-party library. The private signing key never exists inside SSP.Activation.
/// The anchor imports a copy of the supplied public key; callers keep ownership of any
/// key objects they pass in. Minimum accepted RSA key size is 2048 bits (3072+ recommended).
/// </summary>
public sealed class LicenseTrustAnchor : IDisposable
{
    /// <summary>Minimum trusted public key size in bits.</summary>
    public const int MinimumKeySizeBits = 2048;

    private readonly RSA _publicKey;

    private LicenseTrustAnchor(RSA publicKey) => _publicKey = publicKey;

    /// <summary>Creates a trust anchor from an RSA public key (a copy is imported; the caller keeps ownership).</summary>
    /// <remarks>
    /// The parameter is deliberately nullable: null input is part of the method's contract and
    /// fails closed with an <see cref="ArgumentNullException"/> (never an accidental pass).
    /// </remarks>
    public static LicenseTrustAnchor FromPublicKey(RSA? publicKey)
    {
        if (publicKey is null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        return Import(publicKey.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Creates a trust anchor from DER-encoded SubjectPublicKeyInfo (SPKI) bytes.</summary>
    public static LicenseTrustAnchor FromSpkiDer(ReadOnlyMemory<byte> subjectPublicKeyInfo)
        => Import(subjectPublicKeyInfo.Span);

    /// <summary>Creates a trust anchor from a PEM "PUBLIC KEY" block.</summary>
    public static LicenseTrustAnchor FromPem(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            throw new ArgumentException("PEM input must not be null or empty.", nameof(pem));
        }

        if (!PemEncoding.TryFind(pem, out var fields))
        {
            throw new ArgumentException("No PEM block found.", nameof(pem));
        }

        var label = pem[fields.Label];
        if (!label.SequenceEqual("PUBLIC KEY"))
        {
            throw new ArgumentException($"Expected a 'PUBLIC KEY' PEM block, found '{label.ToString()}'.", nameof(pem));
        }

        var base64Builder = new System.Text.StringBuilder();
        foreach (var ch in pem[fields.Base64Data])
        {
            if (char.IsAsciiLetterOrDigit(ch) || ch == '+' || ch == '/')
            {
                base64Builder.Append(ch);
            }
        }

        var base64 = base64Builder.ToString();
        base64 += new string('=', (4 - (base64.Length % 4)) % 4);

        byte[] spki;
        try
        {
            spki = Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("PEM contents are not valid base64.", nameof(pem), ex);
        }

        return Import(spki);
    }

    private static LicenseTrustAnchor Import(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var consumed);
            if (consumed != subjectPublicKeyInfo.Length)
            {
                throw new ArgumentException("Public key encoding contains trailing data.", nameof(subjectPublicKeyInfo));
            }

            if (rsa.KeySize < MinimumKeySizeBits)
            {
                throw new ArgumentException(
                    $"Licensing trust anchor key must be at least {MinimumKeySizeBits} bits (got {rsa.KeySize}).",
                    nameof(subjectPublicKeyInfo));
            }

            return new LicenseTrustAnchor(rsa);
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>Exports the anchored public key as DER SubjectPublicKeyInfo (for diagnostics/deployment).</summary>
    public byte[] ExportSpkiDer() => _publicKey.ExportSubjectPublicKeyInfo();

    /// <summary>Exported key size in bits.</summary>
    public int KeySizeBits => _publicKey.KeySize;

    internal bool Verify(byte[] data, byte[] signature)
        => _publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public void Dispose() => _publicKey.Dispose();
}
