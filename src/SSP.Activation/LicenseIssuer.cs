using System.Security.Cryptography;

namespace SSP.Activation;

/// <summary>
/// AUTHORITY-SIDE issuing API: creates signed license artifacts. This type lives in the
/// same assembly so issuance and verification share exactly one canonicalization
/// implementation, but the authority's private key is supplied by the caller on every
/// call and is never stored, persisted, cached or logged by the library.
///
/// Relying-party code (SSP.Core) never calls this type and never possesses a private key.
/// </summary>
public static class LicenseIssuer
{
    /// <summary>
    /// Serializes the payload canonically, signs the canonical bytes with the authority key
    /// and returns the complete LEGACY (version 1) artifact JSON. This is the single-level
    /// format the SSP Licensing Authority has always produced; it remains valid and is the
    /// compatibility format for existing licenses. New two-level issuance goes through
    /// <see cref="LicenseCertificationIssuer.EncodeCertifiedLicenseArtifact"/>.
    /// </summary>
    /// <param name="payload">The license payload to issue.</param>
    /// <param name="authoritySigningKey">The licensing authority's RSA private key (caller-owned; never retained).</param>
    /// <param name="signatureAlgorithm">Defaults to <see cref="SignatureAlgorithms.RsaPssSha256"/>.</param>
    public static string EncodeLicenseArtifact(
        LicensePayload payload,
        RSA authoritySigningKey,
        string? signatureAlgorithm = null)
    {
        if (payload is null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        if (authoritySigningKey is null)
        {
            throw new ArgumentNullException(nameof(authoritySigningKey));
        }

        var algorithm = signatureAlgorithm ?? SignatureAlgorithms.RsaPssSha256;
        var canonical = LicenseCanonicalJson.Serialize(payload);
        var signature = SignatureAlgorithms.Sign(algorithm, authoritySigningKey, canonical);
        return LicenseArtifactCodec.Encode(payload, algorithm, LicenseArtifactCodec.LegacyArtifactVersion, signature);
    }
}
