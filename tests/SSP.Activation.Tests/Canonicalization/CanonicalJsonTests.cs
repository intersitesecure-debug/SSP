using System.Text;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Canonicalization;

/// <summary>
/// Canonicalization tests: deterministic output, property-order independence,
/// whitespace independence, stable dates, stable numbers, and the guarantee that any
/// signed-field modification changes the canonical payload.
/// </summary>
public class CanonicalJsonTests
{
    [Fact]
    public void Serialize_IsDeterministic()
    {
        var payload = LicensePayloadFactory.For(new TestAuthority()).WithInstallationId("INSTALL-1").Build();

        var first = LicenseCanonicalJson.Serialize(payload);
        var second = LicenseCanonicalJson.Serialize(payload);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Serialize_WritesKeysInSortedOrdinalOrder()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).WithInstallationId("INSTALL-1").Build();

        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        var expectedOrder = new[]
        {
            "customerId", "customerName", "edition", "expiresAt", "featureSet", "installationId",
            "issuedAt", "licenseId", "licenseVersion", "limits", "notBefore", "productId",
            "productName", "sequenceNumber", "status"
        };

        var lastIndex = -1;
        foreach (var key in expectedOrder)
        {
            var index = canonical.IndexOf($"\"{key}\"", StringComparison.Ordinal);
            Assert.True(index > lastIndex, $"Key '{key}' is out of canonical order: {canonical}");
            lastIndex = index;
        }
    }

    [Fact]
    public void Serialize_OmitsUnsetOptionalMembers()
    {
        using var authority = new TestAuthority();
        var unbound = LicensePayloadFactory.For(authority).WithInstallationId(null).Build();
        var bound = LicensePayloadFactory.For(authority).WithInstallationId("INSTALL-1").Build();

        var unboundJson = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(unbound));
        var boundJson = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(bound));

        Assert.DoesNotContain("installationId", unboundJson, StringComparison.Ordinal);
        Assert.Contains("\"installationId\":\"INSTALL-1\"", boundJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Serialize_PreservesExplicitUnlimitedLimits()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority)
            .WithLimit(LicenseLimitNames.MaxClients, null)
            .Build();

        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        Assert.Contains("\"max_clients\":null", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void Serialize_TimestampsAreRfc3339UtcWithSevenFractionalDigits()
    {
        using var authority = new TestAuthority();
        // Same instant expressed with a non-UTC offset must canonicalize to the Z form.
        var withOffset = new DateTimeOffset(2030, 6, 1, 14, 30, 0, TimeSpan.FromHours(2)); // == 12:30Z
        var payload = LicensePayloadFactory.For(authority)
            .WithIssuedAt(new DateTimeOffset(2030, 6, 1, 12, 30, 0, TimeSpan.Zero))
            .WithNotBefore(withOffset)
            .Build();

        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        Assert.Contains("\"issuedAt\":\"2030-06-01T12:30:00.0000000Z\"", canonical, StringComparison.Ordinal);
        Assert.Contains("\"notBefore\":\"2030-06-01T12:30:00.0000000Z\"", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("+02:00", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void Serialize_NumbersAreStableIntegers()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority)
            .WithSequence(42)
            .WithLimit("max_users", 25)
            .Build();

        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        Assert.Contains("\"sequenceNumber\":42", canonical, StringComparison.Ordinal);
        Assert.Contains("\"max_users\":25", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("42.0", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("25.0", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void Serialize_GuidsAreLowercaseHyphenated()
    {
        using var authority = new TestAuthority();
        var licenseId = Guid.Parse("01234567-89AB-CDEF-0123-456789ABCDEF");
        var payload = LicensePayloadFactory.For(authority).WithLicenseId(licenseId).Build();

        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        Assert.Contains("\"licenseId\":\"01234567-89ab-cdef-0123-456789abcdef\"", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void Serialize_NoWhitespaceBetweenTokens()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();

        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        Assert.DoesNotContain(": ", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain(", ", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("\t", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void ParseAndReserialize_PropertyOrderIndependence()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).WithInstallationId("INSTALL-1").Build();
        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        var reordered = ArtifactTestHelper.ReversePropertyOrder(canonical);
        var reorderedPayload = DecodePayload(reordered);

        Assert.Equal(payload, reorderedPayload);
        Assert.Equal(canonical, Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(reorderedPayload)));
    }

    [Fact]
    public void ParseAndReserialize_WhitespaceIndependence()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        var canonical = Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(payload));

        var pretty = ArtifactTestHelper.PrettyPrint(canonical);
        var prettyPayload = DecodePayload(pretty);

        Assert.Equal(payload, prettyPayload);
        Assert.Equal(canonical, Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(prettyPayload)));
    }

    [Fact]
    public void FeatureSet_IsOrderAndCaseIndependent()
    {
        using var authority = new TestAuthority();
        var factory = LicensePayloadFactory.For(authority).WithFeatures("SSH", "Web", "rdp");
        var canonicalA = LicenseCanonicalJson.Serialize(factory.Build());

        factory.WithFeatures("rdp", "web", "ssh");
        var canonicalB = LicenseCanonicalJson.Serialize(factory.Build());

        Assert.Equal(canonicalA, canonicalB);
        Assert.Contains("\"featureSet\":[\"rdp\",\"ssh\",\"web\"]", System.Text.Encoding.UTF8.GetString(canonicalA), StringComparison.Ordinal);
    }

    [Fact]
    public void FeatureSet_DeduplicatesEquivalentNames()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).WithFeatures("rdp", "RDP", " rdp ", "rdp ").Build();

        Assert.Equal(1, payload.FeatureSet.Count);
        Assert.Equal("rdp", Assert.Single(payload.FeatureSet.Values));
    }

    [Fact]
    public void ModifiedSignedField_ChangesCanonicalBytes()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        var original = LicenseCanonicalJson.Serialize(payload);

        var modified = LicenseCanonicalJson.Serialize(payload with { CustomerName = "Other Customer" });

        Assert.NotEqual(original, modified);
    }

    [Fact]
    public void ModifiedFeatureSet_ChangesCanonicalBytes()
    {
        using var authority = new TestAuthority();
        var factory = LicensePayloadFactory.For(authority).WithFeatures("rdp");
        var original = LicenseCanonicalJson.Serialize(factory.Build());

        factory.WithFeatures("rdp", "ssh");
        var modified = LicenseCanonicalJson.Serialize(factory.Build());

        Assert.NotEqual(original, modified);
    }

    [Fact]
    public void ModifiedLimit_ChangesCanonicalBytes()
    {
        using var authority = new TestAuthority();
        var factory = LicensePayloadFactory.For(authority).WithLimit(LicenseLimitNames.MaxServices, 3);
        var original = LicenseCanonicalJson.Serialize(factory.Build());

        factory.WithLimit(LicenseLimitNames.MaxServices, 10);
        var modified = LicenseCanonicalJson.Serialize(factory.Build());

        Assert.NotEqual(original, modified);
    }

    private static LicensePayload DecodePayload(string payloadJson)
    {
        // Wrap the payload JSON into a minimal artifact (signature content is irrelevant
        // here — we only exercise parse + re-canonicalize).
        var envelope = ArtifactTestHelper.MakeArtifact(payloadJson, new byte[64]);
        var decoded = LicenseArtifactCodec.TryDecode(envelope, out var artifact, out var error);
        Assert.True(decoded, $"Payload should decode: {error?.Detail}");
        return artifact!.Payload;
    }
}
