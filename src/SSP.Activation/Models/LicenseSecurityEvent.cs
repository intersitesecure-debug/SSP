namespace SSP.Activation;

/// <summary>Types of structured security events emitted by the licensing subsystem.</summary>
public enum LicenseSecurityEventType
{
    LicenseLoaded = 1,
    LicenseValidated = 2,
    LicenseValidationFailed = 3,
    InvalidSignature = 4,
    LicenseExpired = 5,
    LicenseBindingFailed = 6,
    LicenseRevoked = 7,
    LicenseLockdownActivated = 8,
    LicenseLockdownCleared = 9,
    LicenseSuperseded = 10,
    ProtectedOperationDenied = 11,

    /// <summary>A license validated to the ActivationRequired state (chain verified, awaiting the activation code).</summary>
    ActivationRequired = 12,

    /// <summary>An activation code was accepted and the license transitioned to Valid.</summary>
    LicenseActivated = 13
}

/// <summary>
/// A licensing security event. Events never contain private keys, credentials, API
/// secrets or signature material — only identifiers, reason codes and safe detail text.
/// </summary>
public sealed record LicenseSecurityEvent
{
    public required LicenseSecurityEventType EventType { get; init; }

    public required DateTimeOffset OccurredAtUtc { get; init; }

    /// <summary>License state at the time of the event (Unknown while still undetermined).</summary>
    public LicenseState State { get; init; }

    public Guid? LicenseId { get; init; }

    public string? ReasonCode { get; init; }

    public string? Detail { get; init; }
}
