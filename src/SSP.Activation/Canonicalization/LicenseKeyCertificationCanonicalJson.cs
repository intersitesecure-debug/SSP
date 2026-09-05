using System.Buffers;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace SSP.Activation;

/// <summary>
/// Deterministic canonical serialization of a <see cref="LicenseKeyCertification"/>. The
/// produced byte sequence is the exact content covered by the root authority signature, so
/// exactly one canonical form exists per logical certification.
///
/// Canonical form (activation architecture v2):
///   - UTF-8, no BOM, no whitespace between tokens.
///   - JSON object keys appear in fixed lexicographic (ordinal) order:
///     activationCodeHash, [activationOtt], customerId, expiresAt, licenseId, notBefore,
///     productId, publicKeySpkiDer.
///   - GUIDs: lowercase hyphenated "D" form (same convention as the license payload).
///   - Timestamps: RFC 3339 UTC, fixed yyyy-MM-ddTHH:mm:ss.fffffffZ (seven fractional
///     digits), converted to UTC first (same convention as the license payload).
///   - publicKeySpkiDer: base64url (RFC 4648 §5, unpadded) of the DER
///     SubjectPublicKeyInfo. base64url — not standard base64 — because the
///     certification JSON is itself base64url-decoded by
///     <see cref="LicenseKeyCertificationCodec"/> (which rejects '+', '/' and '=').
///     Utf8JsonWriter.WriteBase64StringValue must NOT be used here: it emits
///     standard base64 and would produce certifications that fail closed on
///     decode for almost every real RSA key.
///   - activationOtt: base64url string, present only when non-null (activation licenses).
///   - activationCodeHash: lowercase-hex SHA-256 string, present only when non-null.
/// </summary>
public static class LicenseKeyCertificationCanonicalJson
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>Serializes the certification to its canonical UTF-8 byte representation.</summary>
    public static byte[] Serialize(LicenseKeyCertification certification)
    {
        if (certification is null)
        {
            throw new ArgumentNullException(nameof(certification));
        }

        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, WriterOptions);

        writer.WriteStartObject();

        if (!string.IsNullOrEmpty(certification.ActivationCodeHash))
        {
            writer.WritePropertyName("activationCodeHash");
            writer.WriteStringValue(certification.ActivationCodeHash);
        }

        if (!string.IsNullOrEmpty(certification.ActivationOtt))
        {
            writer.WritePropertyName("activationOtt");
            writer.WriteStringValue(certification.ActivationOtt);
        }

        writer.WritePropertyName("customerId");
        writer.WriteStringValue(certification.CustomerId.ToString("D"));

        WriteTimestamp(writer, "expiresAt", certification.ExpiresAt);

        writer.WritePropertyName("licenseId");
        writer.WriteStringValue(certification.LicenseId.ToString("D"));

        WriteTimestamp(writer, "notBefore", certification.NotBefore);

        writer.WritePropertyName("productId");
        writer.WriteStringValue(certification.ProductId.ToString("D"));

        writer.WritePropertyName("publicKeySpkiDer");
        writer.WriteStringValue(Base64Url.Encode(certification.PublicKeySpkiDer));

        writer.WriteEndObject();
        writer.Flush();

        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteTimestamp(Utf8JsonWriter writer, string name, DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        var formatted = utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        writer.WritePropertyName(name);
        writer.WriteStringValue(formatted);
    }
}
