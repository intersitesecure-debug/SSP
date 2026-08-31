using System.Security.Cryptography;

namespace SSP.Activation;

/// <summary>
/// Registry of supported license signature algorithms. Only algorithms listed here can
/// ever verify a license; anything else fails closed with
/// <see cref="LicenseReasons.UnsupportedSignatureAlgorithm"/>.
///
/// Selected algorithm: RSA-PSS over SHA-256 (salt length = digest size, MGF1/SHA-256).
/// Rationale: natively and uniformly supported by .NET 8 on every target platform
/// (Windows CNG, Linux/macOS OpenSSL); FIPS-approved (unlike Ed25519); no additional
/// dependencies; mature tooling; and the artifact size penalty of RSA is irrelevant for
/// a license file. See docs/ARCHITECTURE.md §3 for the full evaluation.
/// </summary>
public static class SignatureAlgorithms
{
    /// <summary>RSA-PSS (salt length = digest size) over SHA-256, MGF1 with SHA-256.</summary>
    public const string RsaPssSha256 = "RSA-PSS-SHA256";

    /// <summary>All signature algorithms this library understands.</summary>
    public static IReadOnlyList<string> Supported { get; } = new[] { RsaPssSha256 };

    /// <summary>Determines whether the named algorithm can be verified by this library (exact ordinal match).</summary>
    public static bool IsSupported(string? algorithm)
        => string.Equals(algorithm, RsaPssSha256, StringComparison.Ordinal);

    internal static byte[] Sign(string algorithm, RSA privateKey, byte[] data)
    {
        if (!IsSupported(algorithm))
        {
            throw new ArgumentException($"Unsupported signature algorithm '{algorithm}'.", nameof(algorithm));
        }

        if (privateKey.KeySize < LicenseTrustAnchor.MinimumKeySizeBits)
        {
            throw new ArgumentException(
                $"License signing key must be at least {LicenseTrustAnchor.MinimumKeySizeBits} bits (got {privateKey.KeySize}).",
                nameof(privateKey));
        }

        return privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    internal static bool Verify(string algorithm, LicenseTrustAnchor trustAnchor, byte[] data, byte[] signature)
    {
        if (!IsSupported(algorithm))
        {
            return false;
        }

        return trustAnchor.Verify(data, signature);
    }
}
