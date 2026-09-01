using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Buffers;

namespace SSP.Activation;

/// <summary>
/// Codec for the license artifact envelope (the "license file" format).
///
/// Envelope (strict JSON object):
/// <code>
/// {
///   "format": "ssp-license",
///   "artifactVersion": 1,
///   "signatureAlgorithm": "RSA-PSS-SHA256",
///   "payload": "&lt;base64url of the canonical payload JSON&gt;",
///   "signature": "&lt;base64url of the signature over the canonical payload bytes&gt;"
/// }
/// </code>
///
/// The payload travels as base64url of its canonical UTF-8 JSON form so the exact signed
/// bytes are unambiguous. Parsing is strict and fails closed: unknown fields, duplicate
/// fields, wrong types, unknown artifact versions and invalid encodings are all rejected.
/// The signature algorithm field is checked for well-formedness here, but checked for
/// SUPPORT at validation time, so a future library understanding more algorithms can
/// still parse artifacts without redesign.
/// </summary>
public static class LicenseArtifactCodec
{
    /// <summary>Format discriminator embedded in every artifact.</summary>
    public const string ArtifactFormat = "ssp-license";

    /// <summary>Artifact envelope version produced by this library.</summary>
    public const int CurrentArtifactVersion = 1;

    /// <summary>
    /// Maximum accepted artifact size in characters. Guards against resource exhaustion
    /// (a maliciously huge license artifact) before the JSON is parsed; oversized input
    /// fails closed as <see cref="ArtifactDecodeErrorCode.InvalidJson"/>.
    /// </summary>
    public const int MaxArtifactCharacters = 256 * 1024;

    private static readonly string[] EnvelopeFields =
    {
        "format", "artifactVersion", "signatureAlgorithm", "payload", "signature"
    };

    private static readonly string[] PayloadFields =
    {
        "licenseId", "productId", "productName", "customerId", "customerName", "edition",
        "licenseVersion", "issuedAt", "notBefore", "expiresAt", "installationId",
        "featureSet", "limits", "status", "sequenceNumber"
    }

    ;

    /// <summary>
    /// Encodes a payload and an already computed signature into the artifact envelope JSON.
    /// The payload is re-canonicalized here, guaranteeing that the embedded payload bytes
    /// are exactly the canonical bytes the signature was computed over.
    /// </summary>
    public static string Encode(LicensePayload payload, string signatureAlgorithm, int artifactVersion, byte[] signature)
    {
        if (payload is null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        if (signature is null)
        {
            throw new ArgumentNullException(nameof(signature));
        }

        if (signature.Length == 0)
        {
            throw new ArgumentException("Signature must not be empty.", nameof(signature));
        }

        if (!SignatureAlgorithms.IsSupported(signatureAlgorithm))
        {
            throw new ArgumentException($"Unsupported signature algorithm '{signatureAlgorithm}'.", nameof(signatureAlgorithm));
        }

        var canonical = LicenseCanonicalJson.Serialize(payload);

        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true });
        writer.WriteStartObject();
        writer.WriteString("format", ArtifactFormat);
        writer.WriteNumber("artifactVersion", artifactVersion);
        writer.WriteString("signatureAlgorithm", signatureAlgorithm);
        writer.WriteString("payload", Base64Url.Encode(canonical));
        writer.WriteString("signature", Base64Url.Encode(signature));
        writer.WriteEndObject();
        writer.Flush();

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>
    /// Strictly decodes an artifact. Returns false with a structured error for every
    /// malformed input; this method never throws for invalid artifacts.
    /// </summary>
    public static bool TryDecode(string? artifactJson, out LicenseArtifact? artifact, out ArtifactDecodeError? error)
    {
        artifact = null;
        error = null;

        if (string.IsNullOrWhiteSpace(artifactJson))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidJson, "Artifact is null, empty or whitespace.");
            return false;
        }

        if (artifactJson.Length > MaxArtifactCharacters)
        {
            error = new ArtifactDecodeError(
                ArtifactDecodeErrorCode.InvalidJson,
                $"Artifact exceeds the maximum size of {MaxArtifactCharacters} characters.");
            return false;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(artifactJson, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16
            });
        }
        catch (JsonException ex)
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidJson, $"Artifact is not valid JSON: {ex.Message}");
            return false;
        }

        using (document)
        {
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidJson, "Artifact root must be a JSON object.");
                return false;
            }

            if (TryGetDuplicateField(root, out var duplicate))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.DuplicateField, $"Artifact contains duplicate field '{duplicate}'.");
                return false;
            }

            foreach (var property in root.EnumerateObject())
            {
                if (!EnvelopeFields.Contains(property.Name))
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.UnknownField, $"Unknown artifact field '{property.Name}'.");
                    return false;
                }
            }

            if (!TryGetStringField(root, "format", out var format, out error))
            {
                return false;
            }

            if (!string.Equals(format, ArtifactFormat, StringComparison.Ordinal))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.UnsupportedFormat, $"Unknown artifact format '{format}'.");
                return false;
            }

            if (!root.TryGetProperty("artifactVersion", out var versionElement))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.MissingField, "Required field 'artifactVersion' is missing.");
                return false;
            }

            if (versionElement.ValueKind != JsonValueKind.Number || !versionElement.TryGetInt32(out var artifactVersion))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, "Field 'artifactVersion' must be an integer.");
                return false;
            }

            if (artifactVersion != CurrentArtifactVersion)
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.UnknownArtifactVersion,
                    $"Unsupported artifact version {artifactVersion} (supported: {CurrentArtifactVersion}).");
                return false;
            }

            if (!TryGetStringField(root, "signatureAlgorithm", out var signatureAlgorithm, out error))
            {
                return false;
            }

            if (string.IsNullOrEmpty(signatureAlgorithm))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.UnknownSignatureAlgorithm, "Field 'signatureAlgorithm' must not be empty.");
                return false;
            }

            if (!TryGetStringField(root, "payload", out var payloadText, out error))
            {
                return false;
            }

            if (!TryGetStringField(root, "signature", out var signatureText, out error))
            {
                return false;
            }

            if (!Base64Url.TryDecode(payloadText, out var payloadBytes))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, "Field 'payload' is not valid base64url.");
                return false;
            }

            if (!Base64Url.TryDecode(signatureText, out var signatureBytes))
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, "Field 'signature' is not valid base64url.");
                return false;
            }

            JsonDocument payloadDocument;
            try
            {
                payloadDocument = JsonDocument.Parse(payloadBytes, new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 16
                });
            }
            catch (JsonException ex)
            {
                error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadJson, $"Payload is not valid JSON: {ex.Message}");
                return false;
            }

            using (payloadDocument)
            {
                var payloadRoot = payloadDocument.RootElement;

                if (payloadRoot.ValueKind != JsonValueKind.Object)
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadSchema, "Payload root must be a JSON object.");
                    return false;
                }

                if (TryGetDuplicateField(payloadRoot, out var payloadDuplicate))
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.DuplicateField, $"Payload contains duplicate field '{payloadDuplicate}'.");
                    return false;
                }

                if (!TryParsePayload(payloadRoot, out var payload, out var schemaError))
                {
                    error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidPayloadSchema, schemaError);
                    return false;
                }

                artifact = new LicenseArtifact
                {
                    Payload = payload,
                    SignatureAlgorithm = signatureAlgorithm,
                    ArtifactVersion = artifactVersion,
                    Signature = signatureBytes
                };

                return true;
            }
        }
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

    private static bool TryGetStringField(JsonElement root, string field, out string? value, [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] out ArtifactDecodeError? error)
    {
        value = null;
        error = null;

        if (!root.TryGetProperty(field, out var element))
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.MissingField, $"Required field '{field}' is missing.");
            return false;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            error = new ArtifactDecodeError(ArtifactDecodeErrorCode.InvalidEncoding, $"Field '{field}' must be a JSON string.");
            return false;
        }

        value = element.GetString();
        return true;
    }

    private static bool TryParsePayload(JsonElement root, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out LicensePayload? payload, [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] out string? error)
    {
        payload = null;
        error = null;

        foreach (var property in root.EnumerateObject())
        {
            if (!PayloadFields.Contains(property.Name))
            {
                error = $"Unknown payload field '{property.Name}'.";
                return false;
            }
        }

        if (!TryParseRequiredGuid(root, "licenseId", out var licenseId, ref error)) return false;
        if (!TryParseRequiredGuid(root, "productId", out var productId, ref error)) return false;
        if (!TryParseRequiredString(root, "productName", LicenseStringLimits.ProductName, out var productName, ref error)) return false;
        if (!TryParseRequiredGuid(root, "customerId", out var customerId, ref error)) return false;
        if (!TryParseRequiredString(root, "customerName", LicenseStringLimits.CustomerName, out var customerName, ref error)) return false;
        if (!TryParseRequiredString(root, "edition", LicenseStringLimits.Edition, out var edition, ref error)) return false;
        if (!TryParseRequiredString(root, "licenseVersion", LicenseStringLimits.LicenseVersion, out var licenseVersion, ref error)) return false;
        if (!TryParseRequiredTimestamp(root, "issuedAt", out var issuedAt, ref error)) return false;
        if (!TryParseRequiredTimestamp(root, "notBefore", out var notBefore, ref error)) return false;
        if (!TryParseRequiredTimestamp(root, "expiresAt", out var expiresAt, ref error)) return false;

        string? installationId = null;
        if (root.TryGetProperty("installationId", out var installationElement))
        {
            if (installationElement.ValueKind != JsonValueKind.String)
            {
                error = "Payload field 'installationId' must be a string when present.";
                return false;
            }

            installationId = installationElement.GetString();
            if (string.IsNullOrEmpty(installationId))
            {
                error = "Payload field 'installationId' must not be empty when present (omit it for unbound licenses).";
                return false;
            }

            if (installationId.Length > LicenseStringLimits.InstallationId)
            {
                error = $"Payload field 'installationId' exceeds {LicenseStringLimits.InstallationId} characters.";
                return false;
            }
        }

        if (!root.TryGetProperty("featureSet", out var featureElement))
        {
            error = "Required payload field 'featureSet' is missing.";
            return false;
        }

        if (featureElement.ValueKind != JsonValueKind.Array)
        {
            error = "Payload field 'featureSet' must be an array.";
            return false;
        }

        var features = new List<string>();
        foreach (var item in featureElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                error = "Payload field 'featureSet' must contain only strings.";
                return false;
            }

            var raw = item.GetString();
            if (!LicenseFeatureSet.TryNormalize(raw, out var normalized))
            {
                error = $"Invalid feature name '{raw}'.";
                return false;
            }

            features.Add(normalized);
        }

        if (!root.TryGetProperty("limits", out var limitsElement))
        {
            error = "Required payload field 'limits' is missing.";
            return false;
        }

        if (limitsElement.ValueKind != JsonValueKind.Object)
        {
            error = "Payload field 'limits' must be an object.";
            return false;
        }

        if (TryGetDuplicateField(limitsElement, out var duplicateLimit))
        {
            error = $"Payload field 'limits' contains duplicate key '{duplicateLimit}'.";
            return false;
        }

        var limitPairs = new List<KeyValuePair<string, long?>>();
        foreach (var property in limitsElement.EnumerateObject())
        {
            if (!LicenseFeatureSet.TryNormalize(property.Name, out var limitName))
            {
                error = $"Invalid limit name '{property.Name}'.";
                return false;
            }

            long? max;
            if (property.Value.ValueKind == JsonValueKind.Null)
            {
                max = null;
            }
            else if (property.Value.ValueKind == JsonValueKind.Number && property.Value.TryGetInt64(out var limit) && limit >= 0)
            {
                max = limit;
            }
            else
            {
                error = $"Payload limit '{property.Name}' must be a non-negative integer or null (unlimited).";
                return false;
            }

            limitPairs.Add(new KeyValuePair<string, long?>(limitName, max));
        }

        if (!root.TryGetProperty("status", out var statusElement))
        {
            error = "Required payload field 'status' is missing.";
            return false;
        }

        if (statusElement.ValueKind != JsonValueKind.String)
        {
            error = "Payload field 'status' must be a string.";
            return false;
        }

        var statusText = statusElement.GetString();
        LicenseStatus status;
        if (string.Equals(statusText, "active", StringComparison.OrdinalIgnoreCase))
        {
            status = LicenseStatus.Active;
        }
        else if (string.Equals(statusText, "revoked", StringComparison.OrdinalIgnoreCase))
        {
            status = LicenseStatus.Revoked;
        }
        else
        {
            error = $"Unknown payload status '{statusText}'.";
            return false;
        }

        long sequenceNumber = 0;
        if (root.TryGetProperty("sequenceNumber", out var sequenceElement))
        {
            if (sequenceElement.ValueKind != JsonValueKind.Number || !sequenceElement.TryGetInt64(out sequenceNumber) || sequenceNumber < 0)
            {
                error = "Payload field 'sequenceNumber' must be a non-negative integer.";
                return false;
            }
        }

        if (notBefore > expiresAt)
        {
            error = "Payload field 'notBefore' must not be after 'expiresAt'.";
            return false;
        }

        if (issuedAt > notBefore)
        {
            error = "Payload field 'issuedAt' must not be after 'notBefore'.";
            return false;
        }

        try
        {
            payload = new LicensePayload
            {
                LicenseId = licenseId,
                ProductId = productId,
                ProductName = productName,
                CustomerId = customerId,
                CustomerName = customerName,
                Edition = edition,
                LicenseVersion = licenseVersion,
                IssuedAt = issuedAt,
                NotBefore = notBefore,
                ExpiresAt = expiresAt,
                InstallationId = installationId,
                FeatureSet = new LicenseFeatureSet(features),
                Limits = new LicenseLimits(limitPairs),
                Status = status,
                SequenceNumber = sequenceNumber
            };

            return true;
        }
        catch (ArgumentException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryParseRequiredGuid(JsonElement root, string field, out Guid value, [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] ref string? error)
    {
        value = Guid.Empty;
        if (!root.TryGetProperty(field, out var element))
        {
            error = $"Required payload field '{field}' is missing.";
            return false;
        }

        if (element.ValueKind != JsonValueKind.String || !Guid.TryParseExact(element.GetString(), "D", out value))
        {
            error = $"Payload field '{field}' must be a GUID in the canonical 'D' form.";
            return false;
        }

        if (value == Guid.Empty)
        {
            error = $"Payload field '{field}' must not be empty.";
            return false;
        }

        return true;
    }

    private static bool TryParseRequiredString(JsonElement root, string field, int maxLength, [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] out string value, [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] ref string? error)
    {
        value = string.Empty;
        if (!root.TryGetProperty(field, out var element))
        {
            error = $"Required payload field '{field}' is missing.";
            return false;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            error = $"Payload field '{field}' must be a string.";
            return false;
        }

        var text = element.GetString();
        if (string.IsNullOrEmpty(text))
        {
            error = $"Payload field '{field}' must not be empty.";
            return false;
        }

        if (text.Length > maxLength)
        {
            error = $"Payload field '{field}' exceeds {maxLength} characters.";
            return false;
        }

        value = text;
        return true;
    }

    private static bool TryParseRequiredTimestamp(JsonElement root, string field, out DateTimeOffset value, [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] ref string? error)
    {
        value = default;
        if (!root.TryGetProperty(field, out var element))
        {
            error = $"Required payload field '{field}' is missing.";
            return false;
        }

        if (element.ValueKind != JsonValueKind.String)
        {
            error = $"Payload field '{field}' must be a string.";
            return false;
        }

        var text = element.GetString();
        if (string.IsNullOrEmpty(text) || !text.Contains('T'))
        {
            error = $"Payload field '{field}' must be an RFC 3339 date-time containing a 'T' separator.";
            return false;
        }

        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value))
        {
            error = $"Payload field '{field}' is not a valid date-time.";
            return false;
        }

        return true;
    }
}

/// <summary>Maximum string lengths enforced by the payload schema.</summary>
internal static class LicenseStringLimits
{
    public const int ProductName = 200;
    public const int CustomerName = 200;
    public const int Edition = 64;
    public const int LicenseVersion = 32;
    public const int InstallationId = 128;
}
