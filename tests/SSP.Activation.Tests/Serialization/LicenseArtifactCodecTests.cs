using System.Text;
using System.Text.Json.Nodes;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Serialization;

/// <summary>Artifact envelope tests: round-trip, malformed input, missing fields, unknown versions, invalid encodings.</summary>
public class LicenseArtifactCodecTests
{
    [Fact]
    public void EncodeDecode_RoundTrip_PreservesPayload()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).WithInstallationId("INSTALL-1").Build();
        var artifact = authority.Issue(payload);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out var licenseArtifact, out var error);

        Assert.True(decoded, error?.Detail);
        Assert.Equal(payload, licenseArtifact!.Payload);
        Assert.Equal(SignatureAlgorithms.RsaPssSha256, licenseArtifact.SignatureAlgorithm);
        // TestAuthority.Issue uses the legacy (version 1, root-signed) issuer; the
        // certified (version 2) round-trip is covered by LicenseArtifactCodecCertifiedTests.
        Assert.Equal(LicenseArtifactCodec.LegacyArtifactVersion, licenseArtifact.ArtifactVersion);
        Assert.Null(licenseArtifact.Certification);
        Assert.NotEmpty(licenseArtifact.Signature);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Decode_NullOrWhitespace_ReturnsInvalidJson(string? artifactJson)
    {
        var decoded = LicenseArtifactCodec.TryDecode(artifactJson, out var artifact, out var error);

        Assert.False(decoded);
        Assert.Null(artifact);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidJson, error!.Code);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("[1, 2, 3]")]
    [InlineData("\"a string\"")]
    [InlineData("{\"format\": \"ssp-license\",}")]
    public void Decode_MalformedJson_ReturnsInvalidJson(string artifactJson)
    {
        var decoded = LicenseArtifactCodec.TryDecode(artifactJson, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidJson, error!.Code);
    }

    [Fact]
    public void Decode_OversizedArtifact_ReturnsInvalidJson()
    {
        var oversized = new string('a', LicenseArtifactCodec.MaxArtifactCharacters + 1);

        var decoded = LicenseArtifactCodec.TryDecode(oversized, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidJson, error!.Code);
        Assert.Contains("maximum size", error!.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_DuplicateEnvelopeField_ReturnsDuplicateField()
    {
        // Raw JSON with a duplicated field (JsonNode would silently deduplicate).
        var raw = "{\"format\":\"ssp-license\",\"format\":\"ssp-license\",\"artifactVersion\":1," +
                  "\"signatureAlgorithm\":\"RSA-PSS-SHA256\",\"payload\":\"e30\",\"signature\":\"e30\"}";

        var decoded = LicenseArtifactCodec.TryDecode(raw, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.DuplicateField, error!.Code);
    }

    [Fact]
    public void Decode_UnknownEnvelopeField_ReturnsUnknownField()
    {
        using var authority = new TestAuthority();
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var node = JsonNode.Parse(artifact)!.AsObject();
        node["attackerControlled"] = "x";

        var decoded = LicenseArtifactCodec.TryDecode(node.ToJsonString(), out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.UnknownField, error!.Code);
    }

    [Theory]
    [InlineData("format")]
    [InlineData("artifactVersion")]
    [InlineData("signatureAlgorithm")]
    [InlineData("payload")]
    [InlineData("signature")]
    public void Decode_MissingRequiredEnvelopeField_ReturnsMissingField(string field)
    {
        using var authority = new TestAuthority();
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var node = JsonNode.Parse(artifact)!.AsObject();
        node.Remove(field);

        var decoded = LicenseArtifactCodec.TryDecode(node.ToJsonString(), out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.MissingField, error!.Code);
    }

    [Fact]
    public void Decode_UnknownFormat_ReturnsUnsupportedFormat()
    {
        var artifact = MakeEnvelope(format: "some-other-product-license");

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.UnsupportedFormat, error!.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(99)]
    public void Decode_UnknownArtifactVersion_ReturnsUnknownArtifactVersion(int version)
    {
        var artifact = MakeEnvelope(artifactVersion: version);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.UnknownArtifactVersion, error!.Code);
    }

    [Fact]
    public void Decode_NonIntegerArtifactVersion_ReturnsInvalidEncoding()
    {
        var artifact = MakeEnvelopeRaw("\"artifactVersion\": 1.0");

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidEncoding, error!.Code);
    }

    [Fact]
    public void Decode_StringArtifactVersion_ReturnsInvalidEncoding()
    {
        var artifact = MakeEnvelopeRaw("\"artifactVersion\": \"1\"");

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidEncoding, error!.Code);
    }

    [Fact]
    public void Decode_EmptySignatureAlgorithm_ReturnsUnknownSignatureAlgorithm()
    {
        var artifact = MakeEnvelopeRaw("\"artifactVersion\":1,\"signatureAlgorithm\":\"\"");

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.UnknownSignatureAlgorithm, error!.Code);
    }

    [Fact]
    public void Decode_InvalidBase64Payload_ReturnsInvalidEncoding()
    {
        var artifact = MakeEnvelopeRaw("\"artifactVersion\":1,\"signatureAlgorithm\":\"RSA-PSS-SHA256\"", "###not-base64###");

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidEncoding, error!.Code);
    }

    [Fact]
    public void Decode_PayloadNotJson_ReturnsInvalidPayloadJson()
    {
        var payloadBytes = Encoding.UTF8.GetBytes("hello, this is not json");
        var artifact = MakeEnvelopeRaw("\"artifactVersion\":1,\"signatureAlgorithm\":\"RSA-PSS-SHA256\"", ArtifactTestHelper.EncodeBase64Url(payloadBytes));

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadJson, error!.Code);
    }

    [Fact]
    public void Decode_PayloadRootNotObject_ReturnsInvalidPayloadSchema()
    {
        var payloadBytes = Encoding.UTF8.GetBytes("[1, 2, 3]");
        var artifact = MakeEnvelopeRaw("\"artifactVersion\":1,\"signatureAlgorithm\":\"RSA-PSS-SHA256\"", ArtifactTestHelper.EncodeBase64Url(payloadBytes));

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadSchema, error!.Code);
    }

    [Theory]
    [InlineData("licenseId")]
    [InlineData("productId")]
    [InlineData("productName")]
    [InlineData("customerId")]
    [InlineData("customerName")]
    [InlineData("edition")]
    [InlineData("licenseVersion")]
    [InlineData("issuedAt")]
    [InlineData("notBefore")]
    [InlineData("expiresAt")]
    [InlineData("featureSet")]
    [InlineData("limits")]
    [InlineData("status")]
    public void Decode_MissingRequiredPayloadField_ReturnsInvalidPayloadSchema(string field)
    {
        using var authority = new TestAuthority();
        var payloadJson = CanonicalPayloadJson(authority);

        var mutated = ArtifactTestHelper.MutatePayloadJson(payloadJson, node => node.Remove(field));
        var artifact = ArtifactTestHelper.MakeArtifact(mutated, new byte[64]);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadSchema, error!.Code);
        Assert.Contains(field, error!.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Decode_UnknownPayloadField_ReturnsInvalidPayloadSchema()
    {
        using var authority = new TestAuthority();
        var payloadJson = CanonicalPayloadJson(authority);

        var mutated = ArtifactTestHelper.MutatePayloadJson(payloadJson, node => node["hiddenField"] = "x");
        var artifact = ArtifactTestHelper.MakeArtifact(mutated, new byte[64]);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadSchema, error!.Code);
    }

    [Fact]
    public void Decode_DuplicatePayloadField_ReturnsDuplicateField()
    {
        using var authority = new TestAuthority();
        var payloadJson = CanonicalPayloadJson(authority);
        // Remove exactly the root-closing brace and append a duplicate member.
        var withDuplicate = payloadJson[..^1] + ",\"customerName\":\"duplicate\"}";

        var artifact = ArtifactTestHelper.MakeArtifact(withDuplicate, new byte[64]);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.DuplicateField, error!.Code);
    }

    [Theory]
    [InlineData("\"licenseId\": \"not-a-guid\"")]
    [InlineData("\"licenseId\": \"{}\"")]
    [InlineData("\"productId\": \"00000000-0000-0000-0000-000000000000\"")]
    [InlineData("\"productName\": \"\"")]
    [InlineData("\"edition\": \"\"")]
    [InlineData("\"status\": \"unknown-status\"")]
    [InlineData("\"status\": 1")]
    [InlineData("\"sequenceNumber\": -1")]
    [InlineData("\"sequenceNumber\": 1.5")]
    [InlineData("\"issuedAt\": \"2030-01-01\"")]
    [InlineData("\"expiresAt\": \"not-a-date\"")]
    [InlineData("\"featureSet\": \"rdp\"")]
    [InlineData("\"featureSet\": [\"has space\"]")]
    [InlineData("\"featureSet\": [1]")]
    [InlineData("\"limits\": []")]
    [InlineData("\"limits\": {\"max_users\": -5}")]
    [InlineData("\"limits\": {\"max_users\": 1.5}")]
    [InlineData("\"limits\": {\"max users\": 5}")]
    [InlineData("\"installationId\": \"\"")]
    public void Decode_InvalidPayloadSchemaValues_ReturnsInvalidPayloadSchema(string overrideField)
    {
        using var authority = new TestAuthority();
        var payloadJson = CanonicalPayloadJson(authority);

        var mutated = ArtifactTestHelper.MutatePayloadJson(payloadJson, node =>
        {
            var parts = overrideField.Split(':', 2);
            var name = parts[0].Trim().Trim('"');
            var rawValue = parts[1].Trim();
            node[name] = System.Text.Json.Nodes.JsonNode.Parse(rawValue);
        });
        var artifact = ArtifactTestHelper.MakeArtifact(mutated, new byte[64]);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadSchema, error!.Code);
    }

    [Fact]
    public void Decode_TimeWindowInverted_ReturnsInvalidPayloadSchema()
    {
        using var authority = new TestAuthority();
        var payloadJson = CanonicalPayloadJson(authority);

        var mutated = ArtifactTestHelper.MutatePayloadJson(payloadJson, node =>
        {
            node["notBefore"] = "2030-06-01T00:00:00.0000000Z";
            node["expiresAt"] = "2030-01-01T00:00:00.0000000Z";
        });
        var artifact = ArtifactTestHelper.MakeArtifact(mutated, new byte[64]);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadSchema, error!.Code);
    }

    [Fact]
    public void Decode_IssuedAfterNotBefore_ReturnsInvalidPayloadSchema()
    {
        using var authority = new TestAuthority();
        var payloadJson = CanonicalPayloadJson(authority);

        var mutated = ArtifactTestHelper.MutatePayloadJson(payloadJson, node =>
        {
            node["issuedAt"] = "2030-01-02T00:00:00.0000000Z";
        });
        var artifact = ArtifactTestHelper.MakeArtifact(mutated, new byte[64]);

        var decoded = LicenseArtifactCodec.TryDecode(artifact, out _, out var error);

        Assert.False(decoded);
        Assert.Equal(ArtifactDecodeErrorCode.InvalidPayloadSchema, error!.Code);
    }

    private static string CanonicalPayloadJson(TestAuthority authority)
    {
        var payload = LicensePayloadFactory.For(authority).Build();
        return Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));
    }

    private static string MakeEnvelope(
        string format = "ssp-license",
        int artifactVersion = 1,
        string signatureAlgorithm = "RSA-PSS-SHA256")
    {
        var node = new JsonObject
        {
            ["format"] = format,
            ["artifactVersion"] = artifactVersion,
            ["signatureAlgorithm"] = signatureAlgorithm,
            ["payload"] = ArtifactTestHelper.EncodeBase64Url(Encoding.UTF8.GetBytes("{}")),
            ["signature"] = ArtifactTestHelper.EncodeBase64Url(new byte[64])
        };
        return node.ToJsonString();
    }

    private static string DefaultPayloadBase64Url => ArtifactTestHelper.EncodeBase64Url(Encoding.UTF8.GetBytes("{}"));

    private static string MakeEnvelopeRaw(string fieldsBetweenFormatAndPayload, string? payloadBase64Url = null)
    {
        // Full raw envelope: {"format":"ssp-license", FIELDS, "payload":..., "signature":...}
        return "{\"format\":\"ssp-license\"," + fieldsBetweenFormatAndPayload +
               ",\"payload\":\"" + (payloadBase64Url ?? DefaultPayloadBase64Url) + "\"," +
               "\"signature\":\"" + ArtifactTestHelper.EncodeBase64Url(new byte[64]) + "\"}";
    }
}
