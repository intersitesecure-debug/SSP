namespace SSP.Activation;

/// <summary>
/// Outcome of a policy evaluation for a protected operation. Denial is the default; a
/// decision must never be constructed ad-hoc by callers.
/// </summary>
public sealed record AuthorizationDecision
{
    public required bool IsAllowed { get; init; }

    /// <summary>"ok" when allowed; otherwise a stable reason from <see cref="LicenseReasons"/>.</summary>
    public required string ReasonCode { get; init; }

    public string? Detail { get; init; }

    public static AuthorizationDecision Allow() => new()
    {
        IsAllowed = true,
        ReasonCode = LicenseReasons.Ok
    };

    public static AuthorizationDecision Deny(string reasonCode, string? detail = null) => new()
    {
        IsAllowed = false,
        ReasonCode = reasonCode,
        Detail = detail
    };
}
