using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SSP.Activation;

/// <summary>
/// Strict codec for the per-license key certification JSON. The certification's canonical
/// JSON is the exact content the root authority signs
/// (<see cref="LicenseKeyCertificationCanonicalJson"/>); this codec parses and re-emits it
/// under the same strictness rules as the license payload:
///
///   - no comments, no trailing commas, bounded depth;
///   - no unknown fields, no duplicate fields;
///   - GUIDs must be the canonical lowercase "D" form;
///   - timestamps must be RFC 3339 with a 'T' separator, normalized to UTC;
///   - the leaf public key is base64url DER SubjectPublicKeyInfo;
///   - activation material (optional) is a base64url OTT and/or a lowercase-hex SHA-256.
///
/// Decoding never throws for malformed input; it fails closed with an
/// <see cref="ArtifactDecodeError"/>.
/// </summary>
public static class LicenseKeyCertificationCodec
{
    private static readonly string[] Fields =
    {
        "activationCodeHash", "activationOtt", "customerId", "expiresAt",
        "licenseId", "notBefore", "productId", "publicKeySpkiDer",
    };

    /// <summary>Serializes a certification to its canonical JSON text.</summary>
    public static string Encode(LicenseKeyCertification certification)
    {
        ArgumentNullException.ThrowIfNull(certification);
        return Encoding.UTF8.GetString(LicenseKeyCertificationCanonicalJson.Serialize(certification));
    }

    /// <summary>Strictly parses a certification JSON text; returns false with an error for every malformed input.</summary>
    public static bool TryDecode(string? json, out LicenseKeyCertification? certification, out ArtifactDecodeError? error)
    {
        certification = null;
        error = null;

        if (string.IsNullOrWhiteSpace(json))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidJson, "Certification is null, empty or whitespace.");
            return false;
        }

        if (json.Length > LicenseArtifactCodec.MaxArtifactCharacters)
        {
            error = new ArtifactDecodeError(
                ArtifactDecodeErrorCode.InvalidJson,
                $"Certification exceeds the maximum size of {LicenseArtifactCodec.MaxArtifactCharacters} characters.");
            return false;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16
            });
        }
        catch (JsonException ex)
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidJson, $"Certification is not valid JSON: {ex.Message}");
            return false;
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadJson, "Certification root must be a JSON object.");
                return false;
            }

            if (TryGetDuplicateField(root, out var duplicate))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.DuplicateField, $"Certification contains duplicate field '{duplicate}'.");
                return false;
            }

            foreach (var property in root.EnumerateObject())
            {
                if (!Fields.Contains(property.Name))
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.UnknownField, $"Unknown certification field '{property.Name}'.");
                    return false;
                }
            }

            if (!TryParseRequiredGuid(root, "licenseId", out var licenseId, ref error)) return false;
            if (!TryParseRequiredGuid(root, "productId", out var productId, ref error)) return false;
            if (!TryParseRequiredGuid(root, "customerId", out var customerId, ref error)) return false;
            if (!TryParseRequiredTimestamp(root, "notBefore", out var notBefore, ref error)) return false;
            if (!TryParseRequiredTimestamp(root, "expiresAt", out var expiresAt, ref error)) return false;

            if (notBefore > expiresAt)
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadSchema, "Certification field 'notBefore' must not be after 'expiresAt'.");
                return false;
            }

            if (!TryParseRequiredBytes(root, "publicKeySpkiDer", out var spkiDer, ref error)) return false;

            string? activationOtt = null;
            if (root.TryGetProperty("activationOtt", out var ottElement))
            {
                if (ottElement.ValueKind != JsonValueKind.String)
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, "Certification field 'activationOtt' must be a JSON string.");
                    return false;
                }

                activationOtt = ottElement.GetString();
                if (string.IsNullOrEmpty(activationOtt) || !Base64Url.TryDecode(activationOtt, out _))
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, "Certification field 'activationOtt' is not valid base64url.");
                    return false;
                }
            }

            string? activationCodeHash = null;
            if (root.TryGetProperty("activationCodeHash", out var hashElement))
            {
                if (hashElement.ValueKind != JsonValueKind.String)
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, "Certification field 'activationCodeHash' must be a JSON string.");
                    return false;
                }

                activationCodeHash = hashElement.GetString();
                if (!IsLowercaseHexSha256(activationCodeHash))
                {
                    error = new ArtifactDecodeError(
                        ArtifactDecodeErrorCode.InvalidEncoding,
                        "Certification field 'activationCodeHash' must be 64 lowercase hex characters (SHA-256).");
                    return false;
                }
            }

            certification = new LicenseKeyCertification
            {
                LicenseId = licenseId,
                ProductId = productId,
                CustomerId = customerId,
                NotBefore = notBefore,
                ExpiresAt = expiresAt,
                PublicKeySpkiDer = spkiDer,
                ActivationOtt = activationOtt,
                ActivationCodeHash = activationCodeHash
            };

            return true;
        }
    }

    private static bool IsLowercaseHexSha256(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length != 64)
        {
            return false;
        }

        foreach (var ch in text)
        {
            if (ch is < '0' or > 'f' || (ch > '9' && ch < 'a'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryGetDuplicateField(JsonElement element, out string name)
    {
        name = string.Empty;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                name = property.Name;
                return true;
            }
        }

        return false;
    }

    private static bool TryParseRequiredGuid(JsonElement root, string field, out Guid value, ref ArtifactDecodeError? error)
    {
        value = Guid.Empty;
        if (!root.TryGetProperty(field, out var element))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.MissingField, $"Required certification field '{field}' is missing.");
            return false;
        }

        if (element.ValueKind != JsonValueKind.String || !Guid.TryParseExact(element.GetString(), "D", out value))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadSchema, $"Certification field '{field}' must be a GUID in the canonical 'D' form.");
            return false;
        }

        if (value == Guid.Empty)
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadSchema, $"Certification field '{field}' must not be empty.");
            return false;
        }

        return true;
    }

    private static bool TryParseRequiredTimestamp(JsonElement root, string field, out DateTimeOffset value, ref ArtifactDecodeError? error)
    {
        value = default;
        if (!root.TryGetProperty(field, out var element))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.MissingField, $"Required certification field '{field}' is missing.");
            return false;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, $"Certification field '{field}' must be a JSON string.");
            return false;
        }

        var text = element.GetString();
        if (string.IsNullOrEmpty(text) || !text.Contains('T'))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadSchema, $"Certification field '{field}' must be an RFC 3339 date-time containing a 'T' separator.");
            return false;
        }

        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadSchema, $"Certification field '{field}' is not a valid date-time.");
            return false;
        }

        return true;
    }

    private static bool TryParseRequiredBytes(JsonElement root, string field, out byte[] value, ref ArtifactDecodeError? error)
    {
        value = Array.Empty<byte>();
        if (!root.TryGetProperty(field, out var element))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.MissingField, $"Required certification field '{field}' is missing.");
            return false;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, $"Certification field '{field}' must be a JSON string.");
            return false;
        }

        if (!Base64Url.TryDecode(element.GetString(), out var bytes))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, $"Certification field '{field}' is not valid base64url.");
            return false;
        }

        value = bytes;
        return true;
    }
}
