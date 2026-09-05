// File: tools/SSP.LicenseAuthority/LicenseIssuance.cs
//
// Authority-side license payload construction, issuance and inspection.
// Issuance always goes through SSP.Activation.LicenseIssuer.EncodeLicenseArtifact
// so the produced artifact is the existing ssp-license v1 envelope
// (RSA-PSS-SHA256 over LicenseCanonicalJson). This type does not invent a
// second license format.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSP.Activation;

namespace SSP.LicenseAuthority;

/// <summary>In-memory description of a license the authority is about to sign.</summary>
internal sealed class LicenseIssueRequest
{
    public Guid LicenseId { get; init; } = Guid.NewGuid();
    public Guid ProductId { get; init; } = AuthorityProduct.ProductId;
    public string ProductName { get; init; } = AuthorityProduct.ProductName;
    public Guid CustomerId { get; init; }
    public string CustomerName { get; init; } = string.Empty;
    public string? OrganizationOrPersonName { get; init; }
    public string? ComputerName { get; init; }
    public string Edition { get; init; } = string.Empty;
    public string LicenseVersion { get; init; } = "1.0";
    public DateTimeOffset IssuedAt { get; init; }
    public DateTimeOffset NotBefore { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public string? InstallationId { get; init; }
    public IReadOnlyList<string> Features { get; init; } = Array.Empty<string>();
    public IReadOnlyList<KeyValuePair<string, long?>> Limits { get; init; } = Array.Empty<KeyValuePair<string, long?>>();
    public LicenseStatus Status { get; init; } = LicenseStatus.Active;
    public long SequenceNumber { get; init; } = 1;
}

/// <summary>JSON issuance spec (operator input). This is NOT a license artifact.</summary>
internal sealed class LicenseIssueSpecDocument
{
    public Guid? LicenseId { get; set; }
    public Guid? ProductId { get; set; }
    public string? ProductName { get; set; }
    public Guid? CustomerId { get; set; }
    public string? CustomerName { get; set; }
    public string? OrganizationName { get; set; }
    public string? ComputerName { get; set; }
    public string? Edition { get; set; }
    public string? LicenseVersion { get; set; }
    public string? IssuedAt { get; set; }
    public string? NotBefore { get; set; }
    public string? ExpiresAt { get; set; }
    public int? ValidForDays { get; set; }
    public string? InstallationId { get; set; }
    public string[]? Features { get; set; }
    public Dictionary<string, long?>? Limits { get; set; }
    public string? Status { get; set; }
    public long? SequenceNumber { get; set; }
}

internal static class LicenseIssuance
{
    // Mirror of the vendored codec's internal LicenseStringLimits. Enforced
    // here so an over-long field fails at issue time rather than producing an
    // artifact the relying party cannot decode.
    public const int MaxProductName = 200;
    public const int MaxCustomerName = 200;
    public const int MaxOrganizationOrPersonName = 200;
    public const int MaxComputerName = 64;
    public const int MaxEdition = 64;
    public const int MaxLicenseVersion = 32;
    public const int MaxInstallationId = 128;

    private static readonly JsonSerializerOptions SpecJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false
    };

    /// <summary>Sign <paramref name="payload"/> with the caller-owned authority key via the existing issuer.</summary>
    public static string Issue(LicensePayload payload, RSA authorityPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(authorityPrivateKey);
        AuthorityKeyMaterial.AssertAuthorityRsa(authorityPrivateKey, requirePrivate: true, source: "signing key");
        return LicenseIssuer.EncodeLicenseArtifact(payload, authorityPrivateKey, SignatureAlgorithms.RsaPssSha256);
    }

    /// <summary>
    /// Verify that <paramref name="artifact"/> is a well-formed ssp-license v1
    /// whose signature matches <paramref name="authorityKey"/> (public or
    /// private). Does NOT run the time/product/installation pipeline — that is
    /// <see cref="Validate"/> — so an expired license can still be renewed.
    /// </summary>
    public static bool SignatureMatches(string artifactJson, RSA authorityKey, out string? error)
    {
        error = null;
        if (!LicenseArtifactCodec.TryDecode(artifactJson, out var artifact, out var decodeError) || artifact is null)
        {
            error = decodeError is null
                ? "License artifact could not be decoded."
                : $"License artifact could not be decoded ({decodeError.Code}): {decodeError.Detail}";
            return false;
        }

        if (!SignatureAlgorithms.IsSupported(artifact.SignatureAlgorithm))
        {
            error = $"Signature algorithm '{artifact.SignatureAlgorithm}' is not supported.";
            return false;
        }

        byte[] canonical;
        try
        {
            canonical = LicenseCanonicalJson.Serialize(artifact.Payload);
        }
        catch (Exception ex)
        {
            error = $"Payload could not be canonicalized: {ex.GetType().Name}.";
            return false;
        }

        try
        {
            if (!authorityKey.VerifyData(
                    canonical,
                    artifact.Signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss))
            {
                error = "License signature does not verify against the supplied authority key.";
                return false;
            }
        }
        catch (Exception ex)
        {
            error = $"Signature verification failed with a cryptographic error: {ex.GetType().Name}.";
            return false;
        }

        return true;
    }

    /// <summary>Full relying-party validation pipeline (the same <see cref="LicenseValidator"/> SSP uses).</summary>
    public static LicenseValidationResult Validate(
        string artifactJson,
        RSA authorityPublicKey,
        Guid? expectedProductId = null,
        string? installationId = null,
        DateTimeOffset? now = null,
        long? highestAcceptedSequence = null)
    {
        using var anchor = LicenseTrustAnchor.FromPublicKey(authorityPublicKey);
        var options = new LicenseValidationOptions(expectedProductId ?? AuthorityProduct.ProductId);
        IClock clock = now is null ? SystemClock.Instance : new FixedUtcClock(now.Value);
        var identity = new StaticInstallationIdentityProvider(installationId);
        var store = new InMemoryLicenseStateStore();
        if (highestAcceptedSequence is not null)
        {
            store.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = highestAcceptedSequence.Value
            });
        }

        var validator = new LicenseValidator(
            anchor,
            options,
            clock,
            identity,
            store,
            revocationChecker: null,
            eventSink: NullSecurityEventSink.Instance);

        return validator.Validate(artifactJson);
    }

    public static LicensePayload ToPayload(LicenseIssueRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.LicenseId == Guid.Empty)
            throw new AuthorityToolException("licenseId must not be empty.");
        if (request.ProductId == Guid.Empty)
            throw new AuthorityToolException("productId must not be empty.");
        if (request.CustomerId == Guid.Empty)
            throw new AuthorityToolException("customerId is required and must not be empty.");

        RequireString(request.ProductName, "productName", MaxProductName);
        RequireString(request.CustomerName, "customerName", MaxCustomerName);
        RequireString(request.Edition, "edition", MaxEdition);
        RequireString(request.LicenseVersion, "licenseVersion", MaxLicenseVersion);

        if (!string.IsNullOrEmpty(request.InstallationId) && request.InstallationId.Length > MaxInstallationId)
        {
            throw new AuthorityToolException($"installationId exceeds {MaxInstallationId} characters.");
        }

        if (!string.IsNullOrEmpty(request.OrganizationOrPersonName) && request.OrganizationOrPersonName.Length > MaxOrganizationOrPersonName)
        {
            throw new AuthorityToolException($"organizationName exceeds {MaxOrganizationOrPersonName} characters.");
        }

        if (!string.IsNullOrEmpty(request.ComputerName) && request.ComputerName.Length > MaxComputerName)
        {
            throw new AuthorityToolException($"computerName exceeds {MaxComputerName} characters.");
        }

        if (request.IssuedAt > request.NotBefore)
        {
            throw new AuthorityToolException("issuedAt must not be after notBefore.");
        }

        if (request.NotBefore > request.ExpiresAt)
        {
            throw new AuthorityToolException("notBefore must not be after expiresAt.");
        }

        if (request.SequenceNumber < 0)
        {
            throw new AuthorityToolException("sequenceNumber must be a non-negative integer.");
        }

        LicenseFeatureSet features;
        try
        {
            features = new LicenseFeatureSet(request.Features);
        }
        catch (ArgumentException ex)
        {
            throw new AuthorityToolException($"Invalid feature set: {ex.Message}", ex);
        }

        LicenseLimits limits;
        try
        {
            limits = new LicenseLimits(request.Limits);
        }
        catch (ArgumentException ex)
        {
            throw new AuthorityToolException($"Invalid limits: {ex.Message}", ex);
        }

        return new LicensePayload
        {
            LicenseId = request.LicenseId,
            ProductId = request.ProductId,
            ProductName = request.ProductName,
            CustomerId = request.CustomerId,
            CustomerName = request.CustomerName,
            OrganizationOrPersonName = string.IsNullOrWhiteSpace(request.OrganizationOrPersonName) ? null : request.OrganizationOrPersonName,
            ComputerName = string.IsNullOrWhiteSpace(request.ComputerName) ? null : request.ComputerName,
            Edition = request.Edition,
            LicenseVersion = request.LicenseVersion,
            IssuedAt = request.IssuedAt,
            NotBefore = request.NotBefore,
            ExpiresAt = request.ExpiresAt,
            InstallationId = string.IsNullOrWhiteSpace(request.InstallationId) ? null : request.InstallationId,
            FeatureSet = features,
            Limits = limits,
            Status = request.Status,
            SequenceNumber = request.SequenceNumber
        };
    }

    public static LicenseIssueSpecDocument LoadSpec(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new AuthorityToolException("A spec path is required.");
        }

        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
        {
            throw new AuthorityToolException($"Issuance spec was not found: {full}");
        }

        var json = File.ReadAllText(full);
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new AuthorityToolException($"Issuance spec '{full}' is empty.");
        }

        // Refuse to treat a signed artifact as an issuance spec — that would
        // be a second, confused way to "issue" and skips the explicit renew
        // path that re-checks the signature.
        if (json.Contains("\"format\"", StringComparison.Ordinal) &&
            json.Contains("ssp-license", StringComparison.Ordinal))
        {
            throw new AuthorityToolException(
                $"File '{full}' looks like a signed ssp-license artifact, not an issuance spec. " +
                "Use 'renew' to re-issue an existing license or 'inspect' to read it.");
        }

        LicenseIssueSpecDocument? spec;
        try
        {
            spec = JsonSerializer.Deserialize<LicenseIssueSpecDocument>(json, SpecJsonOptions);
        }
        catch (JsonException ex)
        {
            throw new AuthorityToolException($"Issuance spec '{full}' is not valid JSON: {ex.Message}", ex);
        }

        if (spec is null)
        {
            throw new AuthorityToolException($"Issuance spec '{full}' is empty.");
        }

        return spec;
    }

    public static DateTimeOffset ParseTimestamp(string text, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new AuthorityToolException($"{fieldName} must not be empty.");
        }

        var value = text.Trim();
        if (DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var dateOnly))
        {
            return dateOnly;
        }

        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new AuthorityToolException(
                $"{fieldName} is not a valid RFC 3339 date-time or yyyy-MM-dd date: '{text}'.");
        }

        return parsed.ToUniversalTime();
    }

    public static Guid ParseGuid(string text, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new AuthorityToolException($"{fieldName} must not be empty.");
        }

        if (!Guid.TryParse(text.Trim(), CultureInfo.InvariantCulture, out var guid) || guid == Guid.Empty)
        {
            throw new AuthorityToolException($"{fieldName} must be a non-empty GUID.");
        }

        return guid;
    }

    public static LicenseStatus ParseStatus(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return LicenseStatus.Active;
        }

        var value = text.Trim();
        if (string.Equals(value, "active", StringComparison.OrdinalIgnoreCase))
        {
            return LicenseStatus.Active;
        }

        if (string.Equals(value, "revoked", StringComparison.OrdinalIgnoreCase))
        {
            return LicenseStatus.Revoked;
        }

        throw new AuthorityToolException($"Unknown license status '{text}'. Expected 'active' or 'revoked'.");
    }

    public static KeyValuePair<string, long?> ParseLimit(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new AuthorityToolException("Limit assignment must be name=value (value is a non-negative integer or 'unlimited').");
        }

        var split = text.IndexOf('=');
        if (split <= 0 || split == text.Length - 1)
        {
            throw new AuthorityToolException(
                $"Invalid limit '{text}'. Expected name=value (value is a non-negative integer or 'unlimited').");
        }

        var name = text[..split].Trim();
        var raw = text[(split + 1)..].Trim();
        if (string.IsNullOrEmpty(name))
        {
            throw new AuthorityToolException($"Invalid limit '{text}': name is empty.");
        }

        if (raw.Length == 0 ||
            string.Equals(raw, "unlimited", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(raw, "null", StringComparison.OrdinalIgnoreCase))
        {
            return new KeyValuePair<string, long?>(name, null);
        }

        if (!long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var max) || max < 0)
        {
            throw new AuthorityToolException(
                $"Limit '{name}' must be a non-negative integer or 'unlimited' (got '{raw}').");
        }

        return new KeyValuePair<string, long?>(name, max);
    }

    public static string DescribePayload(LicensePayload payload, string? signatureAlgorithm = null, int? signatureLength = null)
    {
        var builder = new StringBuilder();
        if (signatureAlgorithm is not null)
        {
            builder.AppendLine($"  Format              : {LicenseArtifactCodec.ArtifactFormat}");
            builder.AppendLine($"  Artifact version    : {LicenseArtifactCodec.CurrentArtifactVersion}");
            builder.AppendLine($"  Signature algorithm : {signatureAlgorithm}");
            builder.AppendLine(signatureLength is null
                ? "  Signature           : (present)"
                : $"  Signature           : (present, {signatureLength.Value} bytes)");
        }

        builder.AppendLine($"  LicenseId           : {payload.LicenseId:D}");
        builder.AppendLine($"  ProductId           : {payload.ProductId:D}");
        builder.AppendLine($"  ProductName         : {payload.ProductName}");
        builder.AppendLine($"  CustomerId          : {payload.CustomerId:D}");
        builder.AppendLine($"  CustomerName        : {payload.CustomerName}");
        builder.AppendLine($"  Organization        : {payload.OrganizationOrPersonName ?? "(not set)"}");
        builder.AppendLine($"  Computer            : {payload.ComputerName ?? "(not set)"}");
        builder.AppendLine($"  Edition             : {payload.Edition}");
        builder.AppendLine($"  LicenseVersion      : {payload.LicenseVersion}");
        builder.AppendLine($"  IssuedAt            : {FormatTime(payload.IssuedAt)}");
        builder.AppendLine($"  NotBefore           : {FormatTime(payload.NotBefore)}");
        builder.AppendLine($"  ExpiresAt           : {FormatTime(payload.ExpiresAt)}");
        builder.AppendLine($"  InstallationId      : {payload.InstallationId ?? "(floating)"}");
        builder.AppendLine($"  Features            : {(payload.FeatureSet.Count == 0 ? "(none)" : string.Join(", ", payload.FeatureSet.Values))}");
        builder.AppendLine($"  Limits              : {(payload.Limits.Count == 0 ? "(none; unconstrained)" : payload.Limits.ToString())}");
        builder.AppendLine($"  Status              : {(payload.Status == LicenseStatus.Revoked ? "revoked" : "active")}");
        builder.AppendLine($"  Sequence            : {payload.SequenceNumber}");
        return builder.ToString();
    }

    public static string FormatTime(DateTimeOffset value)
        => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);

    public static IEnumerable<string> UnknownFeatures(IEnumerable<string> features)
    {
        var known = new HashSet<string>(AuthorityProduct.KnownFeatures, StringComparer.Ordinal);
        foreach (var feature in features)
        {
            string normalized;
            try
            {
                normalized = new LicenseFeatureSet(new[] { feature }).Values[0];
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (!known.Contains(normalized))
            {
                yield return normalized;
            }
        }
    }

    public static IEnumerable<string> UnknownLimits(IEnumerable<string> names)
    {
        var known = new HashSet<string>(AuthorityProduct.KnownLimits, StringComparer.Ordinal);

        foreach (var name in names)
        {
            string normalized;
            try
            {
                normalized = new LicenseFeatureSet(new[] { name }).Values[0];
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (!known.Contains(normalized))
            {
                yield return normalized;
            }
        }
    }

    private static void RequireString(string? value, string field, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new AuthorityToolException($"{field} is required.");
        }

        if (value.Length > maxLength)
        {
            throw new AuthorityToolException($"{field} exceeds {maxLength} characters.");
        }
    }

    private sealed class FixedUtcClock : IClock
    {
        public FixedUtcClock(DateTimeOffset utcNow) => UtcNow = utcNow.ToUniversalTime();

        public DateTimeOffset UtcNow { get; }
    }
}
