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

    /// <summary>
    /// Installation identity the record is bound to (roadmap Phase 4 / M-3).
    /// The host store stamps this value on every write; a record that names a
    /// DIFFERENT installation must never be accepted, so replaying another
    /// machine's state cannot silently reset this installation's anti-rollback
    /// floor. Null on records written by pre-Phase-4 builds (legacy records are
    /// adopted and upgraded on the next save, never rejected). Like every field
    /// of this record, it can only restrict authorization, never grant it.
    /// </summary>
    public string? InstallationId { get; init; }

    /// <summary>
    /// Monotonic write counter for the persisted license state (roadmap
    /// Phase 4 / M-3). Incremented by the host store on every save; it never
    /// decreases on a legitimate installation. A durable value of this counter
    /// that is HIGHER than the value in the state file proves the file was
    /// rolled back to an older copy. Zero on records written by pre-Phase-4
    /// builds. Purely a rollback-detection signal: it never influences any
    /// authorization decision by itself.
    /// </summary>
    public long StateEpoch { get; init; }
}
