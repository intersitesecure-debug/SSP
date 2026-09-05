namespace SSP.Activation;

/// <summary>
/// Persisted licensing state used for anti-rollback (highest accepted sequence number)
/// and diagnostics. This record can NEVER grant authorization — it can only restrict it.
/// The root of trust is always the cryptographically signed license artifact; see
/// docs/ARCHITECTURE.md for the documented security assumptions of persistence.
/// </summary>
public sealed record LicenseStateRecord
{
    /// <summary>Highest license sequence number accepted for this installation.</summary>
    public long HighestAcceptedSequenceNumber { get; init; }

    /// <summary>Identifier of the most recently accepted license (diagnostics).</summary>
    public Guid? LastAcceptedLicenseId { get; init; }

    /// <summary>Time of the most recent successful validation (diagnostics).</summary>
    public DateTimeOffset? LastValidatedUtc { get; init; }

    /// <summary>
    /// Identifier of the license whose activation code has been accepted on this
    /// installation. A null value means no license is activated yet. The validator
    /// treats an activation-required license as <see cref="LicenseState.ActivationRequired"/>
    /// unless this matches the license id. This field can only restrict authorization
    /// (an activation-required license needs it); it can never grant it (the signed
    /// artifact remains the root of trust).
    /// </summary>
    public Guid? ActivatedLicenseId { get; init; }
}
