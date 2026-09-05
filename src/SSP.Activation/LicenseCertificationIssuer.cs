using System.Security.Cryptography;

namespace SSP.Activation;

/// <summary>
/// AUTHORITY-SIDE issuing API for the two-level (certified) licensing chain. It creates
/// version-2 artifacts: the root authority signs the per-license key certification, and
/// the per-license (leaf) private key signs the license payload.
///
/// Like <see cref="LicenseIssuer"/> this type lives in the same assembly so issuance and
/// verification share exactly one canonicalization implementation, but the authority's
/// private key and the per-license private key are supplied by the caller on every call
/// and are never stored, persisted, cached or logged by the library.
///
/// Relying-party code (SSP.Server and the rest of SSP.Core) never calls this type and
/// never possesses a private key. The leaf private key must never be embedded in
/// SSP.Server or the license artifact.
/// </summary>
public static class LicenseCertificationIssuer
{
    /// <summary>
    /// Signs the certification with the root authority key and the payload with the
    /// per-license leaf key, then returns the complete version-2 artifact JSON.
    /// </summary>
    /// <param name="payload">The license payload (signed by the leaf key).</param>
    /// <param name="certification">
    /// The key certification binding <paramref name="payload"/>'s identity to the leaf
    /// public key (signed by the root key). Its <see cref="LicenseKeyCertification.PublicKeySpkiDer"/>
    /// must be the SubjectPublicKeyInfo of <paramref name="licenseSigningKey"/>.
    /// </param>
    /// <param name="authoritySigningKey">The Licensing Authority's RSA private key (root; caller-owned, never retained).</param>
    /// <param name="licenseSigningKey">The per-license RSA private key (leaf; caller-owned, never retained).</param>
    /// <param name="signatureAlgorithm">Defaults to <see cref="SignatureAlgorithms.RsaPssSha256"/>.</param>
    public static string EncodeCertifiedLicenseArtifact(
        LicensePayload payload,
        LicenseKeyCertification certification,
        RSA authoritySigningKey,
        RSA licenseSigningKey,
        string? signatureAlgorithm = null)
    {
        if (payload is null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        if (certification is null)
        {
            throw new ArgumentNullException(nameof(certification));
        }

        if (authoritySigningKey is null)
        {
            throw new ArgumentNullException(nameof(authoritySigningKey));
        }

        if (licenseSigningKey is null)
        {
            throw new ArgumentNullException(nameof(licenseSigningKey));
        }

        var algorithm = signatureAlgorithm ?? SignatureAlgorithms.RsaPssSha256;

        var certificationCanonical = LicenseKeyCertificationCanonicalJson.Serialize(certification);
        var certificationSignature = SignatureAlgorithms.Sign(algorithm, authoritySigningKey, certificationCanonical);

        var payloadCanonical = LicenseCanonicalJson.Serialize(payload);
        var payloadSignature = SignatureAlgorithms.Sign(algorithm, licenseSigningKey, payloadCanonical);

        return LicenseArtifactCodec.EncodeCertified(
            payload,
            certification,
            certificationSignature,
            payloadSignature,
            algorithm);
    }
}
