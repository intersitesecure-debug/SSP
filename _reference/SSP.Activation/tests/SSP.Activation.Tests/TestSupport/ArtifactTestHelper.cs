using System.Text;
using System.Text.Json.Nodes;

namespace SSP.Activation.Tests.TestSupport;

/// <summary>Helpers for building and mutating raw artifact JSON in tests.</summary>
internal static class ArtifactTestHelper
{
    /// <summary>Replicates the library's base64url encoding for test-side byte embedding.</summary>
    public static string EncodeBase64Url(byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static byte[] DecodeBase64Url(string text)
    {
        var padded = text.Replace('-', '+').Replace('_', '/');
        var padding = (4 - (padded.Length % 4)) % 4;
        padded += padding switch
        {
            2 => "==",
            3 => "=",
            _ => string.Empty
        };
        return Convert.FromBase64String(padded);
    }

    /// <summary>Extracts the decoded canonical payload JSON text from an artifact.</summary>
    public static string GetPayloadJson(string artifactJson)
    {
        var node = JsonNode.Parse(artifactJson)!.AsObject();
        var payloadBase64 = node["payload"]!.GetValue<string>();
        return Encoding.UTF8.GetString(DecodeBase64Url(payloadBase64));
    }

    /// <summary>Extracts the raw signature bytes from an artifact.</summary>
    public static byte[] GetSignatureBytes(string artifactJson)
    {
        var node = JsonNode.Parse(artifactJson)!.AsObject();
        return DecodeBase64Url(node["signature"]!.GetValue<string>());
    }

    /// <summary>Builds an artifact envelope from a raw payload JSON string and signature bytes.</summary>
    public static string MakeArtifact(string payloadJson, byte[] signature, string signatureAlgorithm = "RSA-PSS-SHA256", int artifactVersion = 1)
    {
        var obj = new JsonObject
        {
            ["format"] = "ssp-license",
            ["artifactVersion"] = artifactVersion,
            ["signatureAlgorithm"] = signatureAlgorithm,
            ["payload"] = EncodeBase64Url(Encoding.UTF8.GetBytes(payloadJson)),
            ["signature"] = EncodeBase64Url(signature)
        };
        return obj.ToJsonString();
    }

    /// <summary>Parses a payload JSON text, applies a mutation to the JSON node and returns the new payload JSON text.</summary>
    public static string MutatePayloadJson(string payloadJson, Action<JsonObject> mutation)
    {
        var node = JsonNode.Parse(payloadJson)!.AsObject();
        mutation(node);
        return node.ToJsonString();
    }

    /// <summary>Converts a payload JSON text to a pretty-printed (indented) form, preserving semantics.</summary>
    public static string PrettyPrint(string json)
    {
        var node = JsonNode.Parse(json)!;
        return node.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Returns the payload JSON with object properties in reverse insertion order (property-order independence probe).</summary>
    public static string ReversePropertyOrder(string json)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        var reversed = new JsonObject();
        foreach (var (name, value) in node.Reverse())
        {
            reversed[name] = value?.DeepClone();
        }

        return reversed.ToJsonString();
    }
}
