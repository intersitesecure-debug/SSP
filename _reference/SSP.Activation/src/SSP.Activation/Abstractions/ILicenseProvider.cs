namespace SSP.Activation;

/// <summary>
/// Source of license artifacts (local file, online activation, offline exchange, ...).
/// Providers perform transport only — they never evaluate, trust or authorize anything.
/// Absence and transport errors are both expressed as HasLicense=false (fail closed).
/// </summary>
public interface ILicenseProvider
{
    /// <summary>Fetches the current license artifact, if one is available.</summary>
    LicenseFetchResult FetchLicense();
}

/// <summary>Result of a provider fetch.</summary>
public sealed record LicenseFetchResult
{
    public bool HasLicense { get; init; }

    public string? ArtifactJson { get; init; }

    /// <summary>Safe diagnostic detail when no artifact was returned.</summary>
    public string? Detail { get; init; }

    public static LicenseFetchResult FromArtifact(string artifactJson)
        => new() { HasLicense = true, ArtifactJson = artifactJson };

    public static LicenseFetchResult Empty(string? detail = null)
        => new() { HasLicense = false, Detail = detail };

    public static LicenseFetchResult Error(string detail)
        => new() { HasLicense = false, Detail = detail };
}
