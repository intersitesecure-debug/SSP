using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SSP.Activation;

/// <summary>
/// Strict JSON codec for the <see cref="ActivationRequest"/> message. The wire/file
/// format is:
/// <code>
/// {
///   "format": "ssp-activation-request",
///   "version": 1,
///   "licenseId": "...", "productId": "...", "customerId": "...",
///   "organizationName": "...", "computerName": "...", "installationId": "...",
///   "activationOtt": "...", "requestedAtUtc": "..."
/// }
/// </code>
/// Decoding is strict (no comments/trailing commas, no unknown fields, no duplicates,
/// canonical GUID forms, RFC 3339 timestamp) and fails closed. This codec serializes pure
/// data only; it performs no cryptography and no I/O, so the same message can travel over
/// the offline file transport or a future HTTPS transport unchanged.
/// </summary>
public static class ActivationRequestCodec
{
    /// <summary>Format discriminator for activation-request messages.</summary>
    public const string Format = "ssp-activation-request";

    /// <summary>Message version produced by this library.</summary>
    public const int Version = 1;

    private static readonly string[] Fields =
    {
        "format", "version", "licenseId", "productId", "customerId",
        "organizationName", "computerName", "installationId", "activationOtt", "requestedAtUtc",
    };

    /// <summary>Serializes a request to its strict JSON form (indented for operator readability).</summary>
    public static string Encode(ActivationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("format", Format);
            writer.WriteNumber("version", Version);
            writer.WriteString("licenseId", request.LicenseId.ToString("D"));
            writer.WriteString("productId", request.ProductId.ToString("D"));
            writer.WriteString("customerId", request.CustomerId.ToString("D"));

            if (!string.IsNullOrWhiteSpace(request.OrganizationOrPersonName))
            {
                writer.WriteString("organizationName", request.OrganizationOrPersonName);
            }

            if (!string.IsNullOrWhiteSpace(request.ComputerName))
            {
                writer.WriteString("computerName", request.ComputerName);
            }

            if (!string.IsNullOrWhiteSpace(request.InstallationId))
            {
                writer.WriteString("installationId", request.InstallationId);
            }

            writer.WriteString("activationOtt", request.ActivationOtt);
            writer.WriteString("requestedAtUtc", request.RequestedAtUtc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>Strictly decodes a request message; returns false with an error for every malformed input.</summary>
    public static bool TryDecode(string? json, out ActivationRequest? request, out ActivationRequestDecodeError? error)
    {
        request = null;
        error = null;

        if (string.IsNullOrWhiteSpace(json))
        {
            error = new ActivationRequestDecodeError("Request is null, empty or whitespace.");
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
            error = new ActivationRequestDecodeError($"Request is not valid JSON: {ex.Message}");
            return false;
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                error = new ActivationRequestDecodeError("Request root must be a JSON object.");
                return false;
            }

            if (HasDuplicateField(root, out var duplicate))
            {
                error = new ActivationRequestDecodeError($"Request contains duplicate field '{duplicate}'.");
                return false;
            }

            foreach (var property in root.EnumerateObject())
            {
                if (!Fields.Contains(property.Name))
                {
                    error = new ActivationRequestDecodeError($"Unknown request field '{property.Name}'.");
                    return false;
                }
            }

            if (!TryReadString(root, "format", out var format, ref error)) return false;
            if (!string.Equals(format, Format, StringComparison.Ordinal))
            {
                error = new ActivationRequestDecodeError($"Unknown request format '{format}'.");
                return false;
            }

            if (!root.TryGetProperty("version", out var versionElement)
                || versionElement.ValueKind != JsonValueKind.Number
                || !versionElement.TryGetInt32(out var version))
            {
                error = new ActivationRequestDecodeError("Request field 'version' must be an integer.");
                return false;
            }

            if (version != Version)
            {
                error = new ActivationRequestDecodeError($"Unsupported request version {version} (supported: {Version}).");
                return false;
            }

            if (!TryReadGuid(root, "licenseId", out var licenseId, ref error)) return false;
            if (!TryReadGuid(root, "productId", out var productId, ref error)) return false;
            if (!TryReadGuid(root, "customerId", out var customerId, ref error)) return false;
            if (!TryReadString(root, "activationOtt", out var ott, ref error)) return false;
            if (!Base64Url.TryDecode(ott, out _))
            {
                error = new ActivationRequestDecodeError("Request field 'activationOtt' is not valid base64url.");
                return false;
            }

            if (!TryReadTimestamp(root, "requestedAtUtc", out var requestedAtUtc, ref error)) return false;

            string? organization = TryReadOptionalString(root, "organizationName");
            string? computer = TryReadOptionalString(root, "computerName");
            string? installation = TryReadOptionalString(root, "installationId");

            request = new ActivationRequest
            {
                LicenseId = licenseId,
                ProductId = productId,
                CustomerId = customerId,
                OrganizationOrPersonName = organization,
                ComputerName = computer,
                InstallationId = installation,
                ActivationOtt = ott!,
                RequestedAtUtc = requestedAtUtc
            };

            return true;
        }
    }

    private static bool HasDuplicateField(JsonElement element, out string name)
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

    private static bool TryReadString(JsonElement root, string field, out string? value, ref ActivationRequestDecodeError? error)
    {
        value = null;
        if (!root.TryGetProperty(field, out var element) || element.ValueKind != JsonValueKind.String)
        {
            error = new ActivationRequestDecodeError($"Request field '{field}' must be a JSON string.");
            return false;
        }

        value = element.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            error = new ActivationRequestDecodeError($"Request field '{field}' must not be empty.");
            return false;
        }

        return true;
    }

    private static string? TryReadOptionalString(JsonElement root, string field)
    {
        if (!root.TryGetProperty(field, out var element))
        {
            return null;
        }

        var value = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static bool TryReadGuid(JsonElement root, string field, out Guid value, ref ActivationRequestDecodeError? error)
    {
        value = Guid.Empty;
        if (!root.TryGetProperty(field, out var element)
            || element.ValueKind != JsonValueKind.String
            || !Guid.TryParseExact(element.GetString(), "D", out value)
            || value == Guid.Empty)
        {
            error = new ActivationRequestDecodeError($"Request field '{field}' must be a non-empty GUID in the canonical 'D' form.");
            return false;
        }

        return true;
    }

    private static bool TryReadTimestamp(JsonElement root, string field, out DateTimeOffset value, ref ActivationRequestDecodeError? error)
    {
        value = default;
        if (!root.TryGetProperty(field, out var element) || element.ValueKind != JsonValueKind.String)
        {
            error = new ActivationRequestDecodeError($"Request field '{field}' must be a JSON string.");
            return false;
        }

        if (!DateTimeOffset.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value))
        {
            error = new ActivationRequestDecodeError($"Request field '{field}' is not a valid date-time.");
            return false;
        }

        return true;
    }
}

/// <summary>Structured activation-request decode failure detail (safe for logs).</summary>
public sealed record ActivationRequestDecodeError(string Detail);
