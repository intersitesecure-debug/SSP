using System.Text;
using System.Text.Json.Nodes;
using SSP.Activation;

namespace SSP.Activation.Tests.Serialization;

/// <summary>Activation-request message codec: round-trip and strict decode.</summary>
public class ActivationRequestCodecTests
{
    private static ActivationRequest Sample() => new()
    {
        LicenseId = Guid.NewGuid(),
        ProductId = Guid.NewGuid(),
        CustomerId = Guid.NewGuid(),
        OrganizationOrPersonName = "Contoso R&D",
        ComputerName = "TUNNEL-01",
        InstallationId = "INSTALLATION-A",
        ActivationOtt = LicenseActivation.GenerateActivationOtt(),
        RequestedAtUtc = new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero)
    };

    [Fact]
    public void RoundTrip_PreservesAllFields()
    {
        var original = Sample();
        var json = ActivationRequestCodec.Encode(original);

        var decoded = ActivationRequestCodec.TryDecode(json, out var request, out var error);

        Assert.True(decoded, error?.Detail);
        Assert.Equal(original, request);
    }

    [Fact]
    public void OptionalFields_AreOmitted_AndReadBackAsNull()
    {
        var original = Sample() with { OrganizationOrPersonName = null, ComputerName = null, InstallationId = null };
        var json = ActivationRequestCodec.Encode(original);

        Assert.DoesNotContain("organizationName", json, StringComparison.Ordinal);
        Assert.DoesNotContain("computerName", json, StringComparison.Ordinal);
        Assert.DoesNotContain("installationId", json, StringComparison.Ordinal);

        Assert.True(ActivationRequestCodec.TryDecode(json, out var request, out _));
        Assert.Null(request!.OrganizationOrPersonName);
        Assert.Null(request.ComputerName);
        Assert.Null(request.InstallationId);
    }

    [Fact]
    public void Decode_RejectsMalformedInput()
    {
        Assert.False(ActivationRequestCodec.TryDecode(null, out _, out _));
        Assert.False(ActivationRequestCodec.TryDecode("", out _, out _));
        Assert.False(ActivationRequestCodec.TryDecode("not json", out _, out _));

        var baseJson = ActivationRequestCodec.Encode(Sample());

        var wrongFormat = JsonNode.Parse(baseJson)!.AsObject();
        wrongFormat["format"] = "something-else";
        Assert.False(ActivationRequestCodec.TryDecode(wrongFormat.ToJsonString(), out _, out _));

        var wrongVersion = JsonNode.Parse(baseJson)!.AsObject();
        wrongVersion["version"] = 99;
        Assert.False(ActivationRequestCodec.TryDecode(wrongVersion.ToJsonString(), out _, out _));

        var badOtt = JsonNode.Parse(baseJson)!.AsObject();
        badOtt["activationOtt"] = "###not-base64url###";
        Assert.False(ActivationRequestCodec.TryDecode(badOtt.ToJsonString(), out _, out _));

        var badGuid = JsonNode.Parse(baseJson)!.AsObject();
        badGuid["licenseId"] = "not-a-guid";
        Assert.False(ActivationRequestCodec.TryDecode(badGuid.ToJsonString(), out _, out _));

        var unknown = JsonNode.Parse(baseJson)!.AsObject();
        unknown["attackerField"] = "x";
        Assert.False(ActivationRequestCodec.TryDecode(unknown.ToJsonString(), out _, out _));

        // Remove the closing brace and duplicate a field.
        var dup = baseJson[..^1] + ",\"customerId\":\"" + Guid.NewGuid().ToString("D") + "\"}";
        Assert.False(ActivationRequestCodec.TryDecode(dup, out _, out _));
    }

    [Fact]
    public void Decode_EmptyOtt_IsRejected()
    {
        var json = ActivationRequestCodec.Encode(Sample());
        var node = JsonNode.Parse(json)!.AsObject();
        node["activationOtt"] = "";

        Assert.False(ActivationRequestCodec.TryDecode(node.ToJsonString(), out _, out _));
    }
}
