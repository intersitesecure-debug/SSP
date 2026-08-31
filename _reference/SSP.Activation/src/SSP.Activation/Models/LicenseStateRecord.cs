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
}
