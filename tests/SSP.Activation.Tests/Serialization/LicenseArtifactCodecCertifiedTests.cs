using System.Text;
using System.Text.Json.Nodes;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Serialization;

/// <summary>
/// Codec tests for the version-2 (certified) artifact envelope: the certification
/// fields exist only in version 2 and are strictly validated; version 1 has none.
/// </summary>
public class LicenseArtifactCodecCertifiedTests
{
    [Fact]
    public void CertifiedRoundTrip_PreservesPayloadAndCertification()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority)
            .WithOrganizationOrPersonName("Contoso R&D")
            .WithComputerName("TUNNEL-01")
            .Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var certification = authority.Certify(payload, leaf);
        var artifact = authority.IssueCertified(payload, certification, leaf);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out var licenseArtifact, out var error);

        Assert.True(decoded, error?.Detail);
        Assert.Equal(LicenseArtifactCodec.CurrentArtifactVersion, licenseArtifact!.ArtifactVersion);
        Assert.Equal(payload, licenseArtifact.Payload);
        Assert.NotNull(licenseArtifact.Certification);
        Assert.NotNull(licenseArtifact.CertificationSignature);
        Assert.Equal(certification.LicenseId, licenseArtifact.Certification!.LicenseId);
        Assert.Equal(certification.PublicKeySpkiDer, licenseArtifact.Certification.PublicKeySpkiDer);
        Assert.NotEmpty(licenseArtifact.Signature);
    }

    [Fact]
    public void CertifiedArtifact_RejectsCertificationFieldsOnVersion1()
    {
        using var authority = new TestAuthority();
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var node = JsonNode.Parse(artifact)!.AsObject();
        // A version 1 artifact that smuggles certification fields must fail closed.
        node["keyCertification"] = ArtifactTestHelper.EncodeBase64Url(Encoding.UTF8.GetBytes("{}"));
        node["keyCertificationSignature"] = ArtifactTestHelper.EncodeBase64Url(new byte[64]);

        var decoded = LicenseArtifactCodec.TryDecode(node.ToJsonString(), out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.UnknownField, error!.Code);
    }

    [Fact]
    public void CertifiedArtifact_RequiresCertificationFields()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var artifact = authority.IssueCertified(payload, authority.Certify(payload, leaf), leaf);

        foreach (var field in new[] { "keyCertification", "keyCertificationSignature" })
        {
            var node = JsonNode.Parse(artifact)!.AsObject();
            node.Remove(field);

            var decoded = LicenseArtifactCodec.TryDecode(node.ToJsonString(), out _, out var error);

            Assert.False(decoded);
            Assert.Equal(ArtifactDecodeErrorCode.MissingField, error!.Code);
        }
    }

    [Fact]
    public void CertifiedArtifact_RejectsMalformedCertification()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var artifact = authority.IssueCertified(payload, authority.Certify(payload, leaf), leaf);

        var node = JsonNode.Parse(artifact)!.AsObject();
        node["keyCertification"] = ArtifactTestHelper.EncodeBase64Url(Encoding.UTF8.GetBytes("{ \"licenseId\": \"not-a-guid\" }"));

        var decoded = LicenseArtifactCodec.TryDecode(node.ToJsonString(), out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadSchema, error!.Code);
    }

    [Fact]
    public void CertifiedArtifact_RejectsUnknownCertificationField()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var artifact = authority.IssueCertified(payload, authority.Certify(payload, leaf), leaf);

        var certificationJson = ArtifactTestHelper.GetCertificationJson(artifact);
        var mutated = ArtifactTestHelper.MutatePayloadJson(certificationJson, node => node["attackerField"] = "x");
        var replaced = ArtifactTestHelper.MakeCertifiedArtifact(
            ArtifactTestHelper.GetPayloadJson(artifact),
            ArtifactTestHelper.GetSignatureBytes(artifact),
            mutated,
            ArtifactTestHelper.GetCertificationSignatureBytes(artifact));

        var decoded = LicenseArtifactCodec.TryDecode(replaced, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.UnknownField, error!.Code);
    }
}
