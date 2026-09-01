namespace SSP.Activation;

/// <summary>
/// Structured outcome of a license validation. Expected invalid-license conditions are
/// expressed as results, never as exceptions. <see cref="License"/> is the decoded
/// artifact content and is UNTRUSTED while <see cref="IsValid"/> is false; it is exposed
/// only for diagnostics (e.g. showing the customer which license was rejected and why).
/// Results never contain secrets or signature material.
/// </summary>
public sealed record LicenseValidationResult
{
    public required bool IsValid { get; init; }

    public required LicenseState State { get; init; }

    /// <summary>Stable machine-readable reason; see <see cref="LicenseReasons"/>.</summary>
    public required string ReasonCode { get; init; }

    /// <summary>Human-readable detail, safe for logs (no secrets, no signature material).</summary>
    public string? Detail { get; init; }

    /// <summary>Decoded license when the artifact could be parsed; untrusted unless valid.</summary>
    public License? License { get; init; }

    /// <summary>The terminal security event describing this validation outcome.</summary>
    public LicenseSecurityEvent? SecurityEvent { get; init; }

    public static LicenseValidationResult Valid(License license, LicenseSecurityEvent securityEvent) => new()
    {
        IsValid = true,
        State = LicenseState.Valid,
        ReasonCode = LicenseReasons.Ok,
        License = license,
        SecurityEvent = securityEvent
    };

    public static LicenseValidationResult Fail(
        LicenseState state,
        string reasonCode,
        string detail,
        License? license = null,
        LicenseSecurityEvent? securityEvent = null) => new()
    {
        IsValid = false,
        State = state,
        ReasonCode = reasonCode,
        Detail = detail,
        License = license,
        SecurityEvent = securityEvent
    };
}
