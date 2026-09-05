using System.Buffers;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace SSP.Activation;

/// <summary>
/// Deterministic canonical serialization of a <see cref="LicensePayload"/>. The produced
/// byte sequence is the exact content covered by the authority's signature — there is
/// exactly one canonical form per logical payload.
///
/// Canonical form (artifact version 1):
///   - UTF-8, no BOM, no whitespace between tokens.
///   - JSON object keys appear in fixed lexicographic (ordinal) order:
///     [computerName], customerId, customerName, edition, expiresAt, featureSet,
///     [installationId], issuedAt, licenseId, licenseVersion, limits, notBefore,
///     [organizationName], productId, productName, sequenceNumber, status.
///   - GUIDs: lowercase hyphenated "D" form.
///   - Timestamps: RFC 3339 UTC with fixed format yyyy-MM-ddTHH:mm:ss.fffffffZ (exactly
///     seven fractional digits). Non-UTC offsets are converted to UTC first, so the
///     representation is locale- and timezone-independent.
///   - Numbers: integers only; floating point values never appear in the payload.
///   - Strings: minimal JSON escaping (only what JSON requires); non-ASCII characters are
///     preserved as UTF-8 (no unicode normalization, matching RFC 8785 practice).
///   - featureSet: normalized (trimmed, invariant lower-case), de-duplicated and sorted
///     ordinally — a set, not an ordered list.
///   - limits: JSON object with normalized, ordinally sorted keys; an explicit null value
///     means "unlimited" for that limit and is preserved.
///   - Optional members that are not set (installationId, computerName,
///     organizationName) are omitted; null appears only for explicitly
///     unlimited limits.
/// </summary>
public static class LicenseCanonicalJson
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>Serializes the payload to its canonical UTF-8 byte representation.</summary>
    public static byte[] Serialize(LicensePayload payload)
    {
        if (payload is null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, WriterOptions);

        writer.WriteStartObject();

        if (!string.IsNullOrEmpty(payload.ComputerName))
        {
            writer.WritePropertyName("computerName");
            writer.WriteStringValue(payload.ComputerName);
        }

        writer.WritePropertyName("customerId");
        writer.WriteStringValue(payload.CustomerId.ToString("D"));

        writer.WritePropertyName("customerName");
        writer.WriteStringValue(payload.CustomerName);

        writer.WritePropertyName("edition");
        writer.WriteStringValue(payload.Edition);

        WriteTimestamp(writer, "expiresAt", payload.ExpiresAt);

        writer.WritePropertyName("featureSet");
        writer.WriteStartArray();
        foreach (var feature in payload.FeatureSet.Values)
        {
            writer.WriteStringValue(feature);
        }

        writer.WriteEndArray();

        if (!string.IsNullOrEmpty(payload.InstallationId))
        {
            writer.WritePropertyName("installationId");
            writer.WriteStringValue(payload.InstallationId);
        }

        WriteTimestamp(writer, "issuedAt", payload.IssuedAt);

        writer.WritePropertyName("licenseId");
        writer.WriteStringValue(payload.LicenseId.ToString("D"));

        writer.WritePropertyName("licenseVersion");
        writer.WriteStringValue(payload.LicenseVersion);

        writer.WritePropertyName("limits");
        writer.WriteStartObject();
        foreach (var entry in payload.Limits.Entries)
        {
            writer.WritePropertyName(entry.Name);
            if (entry.Max is null)
            {
                writer.WriteNullValue();
            }
            else
            {
                writer.WriteNumberValue(entry.Max.Value);
            }
        }

        writer.WriteEndObject();

        WriteTimestamp(writer, "notBefore", payload.NotBefore);

        if (!string.IsNullOrEmpty(payload.OrganizationOrPersonName))
        {
            writer.WritePropertyName("organizationName");
            writer.WriteStringValue(payload.OrganizationOrPersonName);
        }

        writer.WritePropertyName("productId");
        writer.WriteStringValue(payload.ProductId.ToString("D"));

        writer.WritePropertyName("productName");
        writer.WriteStringValue(payload.ProductName);

        writer.WriteNumber("sequenceNumber", payload.SequenceNumber);

        writer.WritePropertyName("status");
        writer.WriteStringValue(payload.Status == LicenseStatus.Revoked ? "revoked" : "active");

        writer.WriteEndObject();
        writer.Flush();

        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteTimestamp(Utf8JsonWriter writer, string name, DateTimeOffset value)
    {
        var utc = value.ToUniversalTime(); // exact arithmetic on the stored offset; no locale involvement
        var formatted = utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        writer.WritePropertyName(name);
        writer.WriteStringValue(formatted);
    }
}
