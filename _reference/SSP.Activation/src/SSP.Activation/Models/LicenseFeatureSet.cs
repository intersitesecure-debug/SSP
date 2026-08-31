namespace SSP.Activation;

/// <summary>
/// Immutable, order-independent set of feature identifiers carried by a license.
/// Names are normalized (trimmed, invariant lower-case) and stored sorted so the canonical
/// serialization is deterministic regardless of the order in which features were supplied.
/// </summary>
/// <remarks>
/// Normalization rules: surrounding whitespace is trimmed; names are compared and stored
/// in invariant lower-case; names must not be empty, must not contain whitespace and are
/// limited to 64 characters. The feature vocabulary is deliberately generic: SSP.Core
/// defines its own feature names (e.g. "rdp", "web", "ssh"); the licensing library does
/// not hard-code product functionality.
/// </remarks>
public sealed class LicenseFeatureSet : IEquatable<LicenseFeatureSet>
{
    /// <summary>Maximum length of a normalized feature name.</summary>
    public const int MaxLength = 64;

    private readonly string[] _features; // distinct, ordinal-sorted, normalized

    /// <summary>An empty feature set.</summary>
    public static LicenseFeatureSet Empty { get; } = new(Array.Empty<string>());

    /// <summary>Creates a feature set from the supplied names. Throws <see cref="ArgumentException"/> for invalid names (issuer error).</summary>
    public LicenseFeatureSet(IEnumerable<string>? features)
    {
        if (features is null)
        {
            throw new ArgumentNullException(nameof(features));
        }

        _features = features
            .Select(Normalize)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>Number of distinct features in the set.</summary>
    public int Count => _features.Length;

    /// <summary>Normalized, ordinal-sorted feature names (read-only view).</summary>
    public IReadOnlyList<string> Values => _features;

    /// <summary>Determines whether the set contains the given feature (normalization applied to the argument).</summary>
    public bool Contains(string? feature)
        => TryNormalize(feature, out var normalized)
           && Array.BinarySearch(_features, normalized, StringComparer.Ordinal) >= 0;

    /// <summary>Normalizes a feature name for storage; throws for invalid input (issuer-side strictness).</summary>
    internal static string Normalize(string feature)
    {
        if (feature is null)
        {
            throw new ArgumentException("Feature name must not be null.", nameof(feature));
        }

        if (!TryNormalize(feature, out var normalized))
        {
            throw new ArgumentException($"Invalid feature name '{feature}': must be 1..{MaxLength} characters without whitespace.", nameof(feature));
        }

        return normalized;
    }

    /// <summary>Attempts to normalize a feature name for queries; returns false for invalid input (fail closed, no throw).</summary>
    internal static bool TryNormalize(string? feature, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(feature))
        {
            return false;
        }

        normalized = feature.Trim().ToLowerInvariant();
        if (normalized.Length == 0 || normalized.Length > MaxLength)
        {
            normalized = string.Empty;
            return false;
        }

        foreach (var ch in normalized)
        {
            if (char.IsWhiteSpace(ch))
            {
                normalized = string.Empty;
                return false;
            }
        }

        return true;
    }

    public bool Equals(LicenseFeatureSet? other)
    {
        if (other is null)
        {
            return false;
        }

        return ReferenceEquals(this, other) || _features.SequenceEqual(other._features, StringComparer.Ordinal);
    }

    public override bool Equals(object? obj) => Equals(obj as LicenseFeatureSet);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var feature in _features)
        {
            hash.Add(feature, StringComparer.Ordinal);
        }

        return hash.ToHashCode();
    }

    public override string ToString() => string.Join(",", _features);
}
