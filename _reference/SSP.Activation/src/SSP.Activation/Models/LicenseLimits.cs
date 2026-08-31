namespace SSP.Activation;

/// <summary>
/// Immutable, order-independent set of named license limits. A limit maps a normalized
/// name to either a maximum value (a non-negative integer) or null, where an explicit
/// null means "unlimited" for that limit. Limits that are absent entirely are treated as
/// unconstrained by the default policy.
/// </summary>
/// <remarks>
/// Names follow the same normalization rules as feature names (see
/// <see cref="LicenseFeatureSet"/>). Conventional names used by the built-in
/// <see cref="ProtectedOperation"/> factories are defined in <see cref="LicenseLimitNames"/>.
/// </remarks>
public sealed class LicenseLimits : IEquatable<LicenseLimits>
{
    private readonly (string Name, long? Max)[] _entries; // ordinal-sorted by name, distinct

    /// <summary>An empty limit set (all operations unconstrained).</summary>
    public static LicenseLimits Empty { get; } = new(Array.Empty<KeyValuePair<string, long?>>());

    /// <summary>Creates a limit set. Throws <see cref="ArgumentException"/> for invalid names, negative values or case-duplicates (issuer error).</summary>
    public LicenseLimits(IEnumerable<KeyValuePair<string, long?>>? limits)
    {
        if (limits is null)
        {
            throw new ArgumentNullException(nameof(limits));
        }

        _entries = limits
            .Select(kv =>
            {
                var name = LicenseFeatureSet.Normalize(kv.Key);
                if (kv.Value is < 0)
                {
                    throw new ArgumentException($"Limit '{kv.Key}' must not be negative.", nameof(limits));
                }

                return (Name: name, Max: kv.Value);
            })
            .OrderBy(e => e.Name, StringComparer.Ordinal)
            .ToArray();

        for (var i = 1; i < _entries.Length; i++)
        {
            if (string.Equals(_entries[i - 1].Name, _entries[i].Name, StringComparison.Ordinal))
            {
                throw new ArgumentException($"Duplicate limit '{_entries[i].Name}' (differing only in case or surrounding whitespace).", nameof(limits));
            }
        }
    }

    /// <summary>Normalized, ordinal-sorted entries (read-only view).</summary>
    public IReadOnlyList<(string Name, long? Max)> Entries => _entries;

    /// <summary>Number of defined limits.</summary>
    public int Count => _entries.Length;

    /// <summary>
    /// Looks up a limit. Returns false when the limit is absent (unconstrained).
    /// Returns true with <paramref name="max"/> = null for an explicitly unlimited limit.
    /// </summary>
    public bool TryGetValue(string? name, out long? max)
    {
        max = null;
        if (!LicenseFeatureSet.TryNormalize(name, out var normalized))
        {
            return false;
        }

        foreach (var entry in _entries)
        {
            var comparison = string.CompareOrdinal(entry.Name, normalized);
            if (comparison == 0)
            {
                max = entry.Max;
                return true;
            }

            if (comparison > 0)
            {
                break; // entries are sorted; no further match possible
            }
        }

        return false;
    }

    public bool Equals(LicenseLimits? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        if (_entries.Length != other._entries.Length)
        {
            return false;
        }

        for (var i = 0; i < _entries.Length; i++)
        {
            if (!string.Equals(_entries[i].Name, other._entries[i].Name, StringComparison.Ordinal) ||
                _entries[i].Max != other._entries[i].Max)
            {
                return false;
            }
        }

        return true;
    }

    public override bool Equals(object? obj) => Equals(obj as LicenseLimits);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var entry in _entries)
        {
            hash.Add(entry.Name, StringComparer.Ordinal);
            hash.Add(entry.Max);
        }

        return hash.ToHashCode();
    }

    public override string ToString()
        => string.Join(";", _entries.Select(e => e.Max is null ? $"{e.Name}=unlimited" : $"{e.Name}<={e.Max.Value}"));
}
