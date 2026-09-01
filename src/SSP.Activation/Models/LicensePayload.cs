namespace SSP.Activation;

/// <summary>
/// Strongly typed immutable license payload. This is the exact data covered by the
/// Licensing Authority's signature; <see cref="LicenseCanonicalJson"/> defines its single
/// deterministic byte representation. Never construct a payload from untrusted input
/// directly — use <see cref="LicenseArtifactCodec"/> to decode artifacts, or construct
/// payloads on the authority side only.
/// </summary>
public sealed record LicensePayload
{
    /// <summary>Unique identifier assigned by the Licensing Authority.</summary>
    public required Guid LicenseId { get; init; }

    /// <summary>Identifier of the product this license authorizes.</summary>
    public required Guid ProductId { get; init; }

    /// <summary>Human readable product name (informational).</summary>
    public required string ProductName { get; init; }

    /// <summary>Identifier of the customer the license was issued to.</summary>
    public required Guid CustomerId { get; init; }

    /// <summary>Human readable customer name (informational).</summary>
    public required string CustomerName { get; init; }

    /// <summary>Commercial edition, e.g. "Professional" or "Enterprise" (informational).</summary>
    public required string Edition { get; init; }

    /// <summary>License document version assigned by the authority (informational).</summary>
    public required string LicenseVersion { get; init; }

    /// <summary>Time the license was issued (UTC).</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>Earliest time the license is valid (UTC, inclusive).</summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>Latest time the license is valid (UTC, exclusive).</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Installation the license is bound to, or null for an installation-independent
    /// (floating) license. Comparison against the installation identity provider is
    /// ordinal and case-insensitive.
    /// </summary>
    public string? InstallationId { get; init; }

    /// <summary>Authorized features (normalized, order-independent).</summary>
    public required LicenseFeatureSet FeatureSet { get; init; }

    /// <summary>License limits; limits that are absent are unconstrained.</summary>
    public required LicenseLimits Limits { get; init; }

    /// <summary>Authority-assigned lifecycle status, covered by the signature.</summary>
    public required LicenseStatus Status { get; init; }

    /// <summary>
    /// Monotonic issuance sequence number used for anti-rollback. The license manager
    /// persists the highest accepted value per installation; a license with an older
    /// sequence is rejected as superseded.
    /// </summary>
    public long SequenceNumber { get; init; }
}
