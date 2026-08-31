namespace SSP.Activation;

/// <summary>
/// Optional revocation check invoked after signature verification (the checker is only
/// consulted for cryptographically authentic payloads). Future implementations may
/// consult online services, signed revocation lists or license status endpoints without
/// redesigning the core model. The default implementation never revokes.
/// </summary>
public interface ILicenseRevocationChecker
{
    LicenseRevocationCheckResult Check(LicensePayload license);
}

/// <summary>Result of a revocation check. A failing checker must be reported as revoked-or-unavailable by the caller (fail closed).</summary>
public sealed record LicenseRevocationCheckResult
{
    public bool IsRevoked { get; init; }

    public string? Detail { get; init; }

    public static LicenseRevocationCheckResult NotRevoked() => new();

    public static LicenseRevocationCheckResult Revoked(string? detail = null)
        => new() { IsRevoked = true, Detail = detail };
}
