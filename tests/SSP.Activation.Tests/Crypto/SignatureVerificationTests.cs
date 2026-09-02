using System.Security.Cryptography;
using System.Text.Json.Nodes;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Crypto;

/// <summary>Cryptography tests: valid signature, invalid signature, wrong key, modified payload, modified signature, unsupported algorithm, missing signature.</summary>
public class SignatureVerificationTests
{
    [Fact]
    public void ValidSignature_IsAccepted()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var result = validator.Validate(artifact);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, result.State);
    }

    [Fact]
    public void ModifiedPayload_WithOriginalSignature_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var payload = LicensePayloadFactory.For(authority).WithFeatures("rdp").Build();
        var artifact = authority.Issue(payload);

        var mutatedPayloadJson = ArtifactTestHelper.MutatePayloadJson(
            ArtifactTestHelper.GetPayloadJson(artifact),
            node => node["customerName"] = "Evil Corp");
        var tampered = ArtifactTestHelper.MakeArtifact(
            mutatedPayloadJson,
            ArtifactTestHelper.GetSignatureBytes(artifact));

        var result = validator.Validate(tampered);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
        Assert.Equal(LicenseReasons.InvalidSignature, result.ReasonCode);
    }

    [Fact]
    public void ModifiedSignature_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        // Flip the FIRST signature character: the top 6 bits of the first byte always change.
        var node = JsonNode.Parse(artifact)!.AsObject();
        var signature = node["signature"]!.GetValue<string>();
        var flipped = signature[0] == 'A' ? 'B' : 'A';
        node["signature"] = flipped + signature[1..];
        var tampered = node.ToJsonString();

        var result = validator.Validate(tampered);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
    }

    [Fact]
    public void WrongSigningKey_IsRejected()
    {
        using var authorityA = new TestAuthority();
        using var authorityB = new TestAuthority();

        // Payload claims product A but is signed by authority B's key.
        var payload = LicensePayloadFactory.For(authorityB).WithProductId(authorityA.ProductId).Build();
        var artifact = authorityB.Issue(payload);

        var validator = ValidatorFactory.Create(authorityA);
        var result = validator.Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
    }

    [Fact]
    public void UnsupportedSignatureAlgorithm_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var payload = LicensePayloadFactory.For(authority).Build();
        var artifact = authority.Issue(payload);

        // Re-label the artifact with a plausible but unsupported algorithm name; the
        // signature bytes are untouched, so only the algorithm registry check can reject.
        var node = JsonNode.Parse(artifact)!.AsObject();
        node["signatureAlgorithm"] = "RSA-PKCS1-SHA256";

        var result = validator.Validate(node.ToJsonString());

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
        Assert.Equal(LicenseReasons.UnsupportedSignatureAlgorithm, result.ReasonCode);
    }

    [Fact]
    public void UnknownAlgorithmWithValidSignature_IsStillRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var payload = LicensePayloadFactory.For(authority).Build();

        // Even a genuinely valid signature over the canonical bytes must be rejected when
        // the artifact declares an unsupported algorithm (fail closed on the registry).
        var canonical = LicenseCanonicalJson.Serialize(payload);
        var artifact = ArtifactTestHelper.MakeArtifact(
            System.Text.Encoding.UTF8.GetString(canonical),
            ArtifactTestHelper.GetSignatureBytes(authority.Issue(payload)),
            signatureAlgorithm: "ED25519");

        var result = validator.Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.UnsupportedSignatureAlgorithm, result.ReasonCode);
    }

    [Fact]
    public void MissingSignature_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var node = JsonNode.Parse(artifact)!.AsObject();
        node.Remove("signature");

        var result = validator.Validate(node.ToJsonString());

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Malformed, result.State);
        Assert.Equal(LicenseReasons.MalformedArtifact, result.ReasonCode);
    }

    [Fact]
    public void TruncatedSignature_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var node = JsonNode.Parse(artifact)!.AsObject();
        var signature = ArtifactTestHelper.GetSignatureBytes(artifact);
        node["signature"] = ArtifactTestHelper.EncodeBase64Url(signature[..(signature.Length / 2)]);

        var result = validator.Validate(node.ToJsonString());

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
    }

    [Fact]
    public void RandomSignatureOfCorrectLength_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var node = JsonNode.Parse(artifact)!.AsObject();
        var signatureLength = ArtifactTestHelper.GetSignatureBytes(artifact).Length;
        node["signature"] = ArtifactTestHelper.EncodeBase64Url(RandomNumberGenerator.GetBytes(signatureLength));

        var result = validator.Validate(node.ToJsonString());

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
    }

    [Fact]
    public void SignatureCoversCanonicalBytes_ReformattedPayloadStillVerifies()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var payload = LicensePayloadFactory.For(authority).Build();
        var canonical = LicenseCanonicalJson.Serialize(payload);

        // Sign the canonical bytes manually, but embed a PRETTY-PRINTED payload JSON.
        // The validator re-canonicalizes the parsed payload, so verification must succeed.
        var signature = authority.SignCanonicalForTest(canonical);
        var prettyPayload = ArtifactTestHelper.PrettyPrint(System.Text.Encoding.UTF8.GetString(canonical));
        var artifact = ArtifactTestHelper.MakeArtifact(prettyPayload, signature);

        var result = validator.Validate(artifact);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, result.State);
    }
}
