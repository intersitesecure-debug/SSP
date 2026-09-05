using System.Security.Cryptography;
using System.Text;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Crypto;

/// <summary>
/// Two-level trust chain tests: the root authority certifies a per-license leaf key, and
/// the leaf key signs the payload. These tests pin the security boundary of the
/// certification — a public key inside a license is NEVER trusted by itself; only a key
/// whose certification verifies against the root anchor may sign a payload.
/// </summary>
public class LicenseKeyCertificationTests
{
    [Fact]
    public void RootCertifiedLeafKey_ValidatesEndToEnd()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var certification = authority.Certify(payload, leaf);
        var artifact = authority.IssueCertified(payload, certification, leaf);

        var validator = ValidatorFactory.Create(authority);
        var result = validator.Validate(artifact);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, result.State);
        Assert.NotNull(result.License!.Certification);
        Assert.Equal(payload.LicenseId, result.License.Certification!.LicenseId);
    }

    [Fact]
    public void UnauthorizedLeafKey_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var certifiedLeaf = TestAuthority.CreateLeafKey();
        var certification = authority.Certify(payload, certifiedLeaf);

        // The payload is signed by a DIFFERENT leaf key than the one the certification
        // carries. The root certification is intact, but the payload signature does not
        // verify under the certified key.
        using var attackerLeaf = TestAuthority.CreateLeafKey();
        var artifact = authority.IssueCertified(payload, certification, attackerLeaf);

        var result = ValidatorFactory.Create(authority).Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
        Assert.Equal(LicenseReasons.InvalidSignature, result.ReasonCode);
    }

    [Fact]
    public void CertificationSignedByWrongRoot_IsRejected()
    {
        using var rootAuthority = new TestAuthority();
        using var attackerAuthority = new TestAuthority();

        var payload = LicensePayloadFactory.For(rootAuthority).Build();
        using var leaf = TestAuthority.CreateLeafKey();

        // Certification signed by the ATTACKER authority (root), payload signed by the
        // leaf. The validation anchor is the real root, so the certification fails.
        var certification = attackerAuthority.Certify(payload, leaf);
        var artifact = attackerAuthority.IssueCertified(payload, certification, leaf);

        var result = ValidatorFactory.Create(rootAuthority).Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidCertification, result.State);
        Assert.Equal(LicenseReasons.InvalidCertificationSignature, result.ReasonCode);
    }

    [Fact]
    public void TamperedCertification_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var certification = authority.Certify(payload, leaf);
        var artifact = authority.IssueCertified(payload, certification, leaf);

        // Rebuild the artifact with a mutated certification (customer id changed) but the
        // original root signature. The certification signature must fail.
        var mutatedCertJson = ArtifactTestHelper.MutatePayloadJson(
            ArtifactTestHelper.GetCertificationJson(artifact),
            node => node["customerId"] = Guid.NewGuid().ToString("D"));
        var tampered = ArtifactTestHelper.MakeCertifiedArtifact(
            ArtifactTestHelper.GetPayloadJson(artifact),
            ArtifactTestHelper.GetSignatureBytes(artifact),
            mutatedCertJson,
            ArtifactTestHelper.GetCertificationSignatureBytes(artifact));

        var result = ValidatorFactory.Create(authority).Validate(tampered);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidCertification, result.State);
        Assert.Equal(LicenseReasons.InvalidCertificationSignature, result.ReasonCode);
    }

    [Fact]
    public void PublicKeySubstitution_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var certification = authority.Certify(payload, leaf);
        var artifact = authority.IssueCertified(payload, certification, leaf);

        // Substitute the certified public key with an attacker key while keeping the root
        // signature. The root signature no longer covers the certification, so it fails.
        using var attackerLeaf = TestAuthority.CreateLeafKey();
        var substitutedJson = ArtifactTestHelper.MutatePayloadJson(
            ArtifactTestHelper.GetCertificationJson(artifact),
            node => node["publicKeySpkiDer"] = ArtifactTestHelper.EncodeBase64Url(attackerLeaf.ExportSubjectPublicKeyInfo()));
        var substituted = ArtifactTestHelper.MakeCertifiedArtifact(
            ArtifactTestHelper.GetPayloadJson(artifact),
            ArtifactTestHelper.GetSignatureBytes(artifact),
            substitutedJson,
            ArtifactTestHelper.GetCertificationSignatureBytes(artifact));

        var result = ValidatorFactory.Create(authority).Validate(substituted);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidCertification, result.State);
        Assert.Equal(LicenseReasons.InvalidCertificationSignature, result.ReasonCode);
    }

    [Fact]
    public void CertificationForAnotherLicense_IsRejected_AsBindingMismatch()
    {
        using var authority = new TestAuthority();
        var payloadA = LicensePayloadFactory.For(authority).Build();
        var payloadB = LicensePayloadFactory.For(authority).Build(); // different LicenseId
        Assert.NotEqual(payloadA.LicenseId, payloadB.LicenseId);

        using var leaf = TestAuthority.CreateLeafKey();

        // A valid root certification for license A, embedded with a payload for license B
        // signed by the same leaf. The certification signature and the payload signature
        // both verify, but the certification does not bind to this payload.
        var certificationA = authority.Certify(payloadA, leaf);
        var artifact = authority.IssueCertified(payloadB, certificationA, leaf);

        var result = ValidatorFactory.Create(authority).Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidCertification, result.State);
        Assert.Equal(LicenseReasons.CertificationBindingMismatch, result.ReasonCode);
    }

    [Fact]
    public void CertificationNotYetValid_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();

        var certification = new LicenseKeyCertification
        {
            LicenseId = payload.LicenseId,
            ProductId = payload.ProductId,
            CustomerId = payload.CustomerId,
            NotBefore = LicensePayloadFactory.BaseTime.AddDays(1), // future
            ExpiresAt = payload.ExpiresAt,
            PublicKeySpkiDer = leaf.ExportSubjectPublicKeyInfo()
        };

        var artifact = authority.IssueCertified(payload, certification, leaf);
        var result = ValidatorFactory.Create(authority).Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.NotYetValid, result.State);
        Assert.Equal(LicenseReasons.CertificationNotYetValid, result.ReasonCode);
    }

    [Fact]
    public void ExpiredCertification_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();

        var certification = new LicenseKeyCertification
        {
            LicenseId = payload.LicenseId,
            ProductId = payload.ProductId,
            CustomerId = payload.CustomerId,
            NotBefore = payload.IssuedAt,
            ExpiresAt = LicensePayloadFactory.BaseTime.AddDays(-1), // already expired
            PublicKeySpkiDer = leaf.ExportSubjectPublicKeyInfo()
        };

        var artifact = authority.IssueCertified(payload, certification, leaf);
        var result = ValidatorFactory.Create(authority).Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Expired, result.State);
        Assert.Equal(LicenseReasons.CertificationExpired, result.ReasonCode);
    }

    [Fact]
    public void UnusableCertifiedKey_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();

        // A certification whose "public key" is not a valid RSA SubjectPublicKeyInfo.
        // The root signature over it is valid (authority-signed), but the key cannot be
        // imported, so the chain fails closed.
        var certification = new LicenseKeyCertification
        {
            LicenseId = payload.LicenseId,
            ProductId = payload.ProductId,
            CustomerId = payload.CustomerId,
            NotBefore = payload.IssuedAt,
            ExpiresAt = payload.ExpiresAt,
            PublicKeySpkiDer = Encoding.ASCII.GetBytes("not an rsa public key")
        };

        var artifact = authority.IssueCertified(payload, certification, leaf);
        var result = ValidatorFactory.Create(authority).Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidCertification, result.State);
        Assert.Equal(LicenseReasons.InvalidCertificationKey, result.ReasonCode);
    }

    [Fact]
    public void LicenseAKey_CannotForgeLicenseB()
    {
        using var authority = new TestAuthority();
        var payloadA = LicensePayloadFactory.For(authority).Build();
        var payloadB = LicensePayloadFactory.For(authority).Build();

        using var leafA = TestAuthority.CreateLeafKey();
        var artifactA = authority.IssueCertified(payloadA, authority.Certify(payloadA, leafA), leafA);

        // License A's artifact (and its certification) is valid...
        var validator = ValidatorFactory.Create(authority);
        Assert.True(validator.Validate(artifactA).IsValid);

        // ...but the holder of license A's key cannot mint a valid license B: signing B's
        // payload with A's key and carrying A's certification fails the binding check.
        var forged = authority.IssueCertified(payloadB, authority.Certify(payloadA, leafA), leafA);
        var forgedResult = validator.Validate(forged);

        Assert.False(forgedResult.IsValid);
        Assert.Equal(LicenseState.InvalidCertification, forgedResult.State);
        Assert.Equal(LicenseReasons.CertificationBindingMismatch, forgedResult.ReasonCode);
    }

    [Fact]
    public void UndersizedCertifiedKey_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var tinyLeaf = RSA.Create(1024); // below the 2048-bit floor
        var certification = authority.Certify(payload, tinyLeaf);

        // The authority-side issuer refuses to sign with a sub-floor leaf key
        // (SignatureAlgorithms.Sign throws), so a weak-key artifact cannot be
        // produced through IssueCertified. Craft it with raw RSA signatures to
        // exercise the VALIDATOR's floor: the root certification signature is
        // genuine and the payload signature verifies under the certified key,
        // but the certified key itself is unusable (< 2048 bits).
        var certificationCanonical = LicenseKeyCertificationCanonicalJson.Serialize(certification);
        var certificationSignature = authority.SignCanonicalForTest(certificationCanonical);
        var payloadCanonical = LicenseCanonicalJson.Serialize(payload);
        var payloadSignature = tinyLeaf.SignData(
            payloadCanonical, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var artifact = LicenseArtifactCodec.EncodeCertified(
            payload,
            certification,
            certificationSignature,
            payloadSignature,
            SignatureAlgorithms.RsaPssSha256);

        var result = ValidatorFactory.Create(authority).Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidCertification, result.State);
        Assert.Equal(LicenseReasons.InvalidCertificationKey, result.ReasonCode);
    }
}
