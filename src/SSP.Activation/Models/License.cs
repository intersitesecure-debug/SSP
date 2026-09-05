namespace SSP.Activation;

/// <summary>
/// A decoded, schema-valid license artifact: the signed payload plus envelope metadata.
/// Presence of this object does NOT imply trust — only
/// <see cref="LicenseValidator"/> results with <see cref="LicenseState.Valid"/> may be
/// relied upon.
/// </summary>
public sealed record License
{
    public required LicensePayload Payload { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required int ArtifactVersion { get; init; }

    /// <summary>
    /// The per-license key certification for version-2 (certified) artifacts; null for
    /// legacy version-1 artifacts where the root authority signs the payload directly.
    /// Presence of this object does NOT imply trust: only results with
    /// <see cref="LicenseState.Valid"/> may be relied upon.
    /// </summary>
    public LicenseKeyCertification? Certification { get; init; }

    public Guid LicenseId => Payload.LicenseId;
    public Guid ProductId => Payload.ProductId;
}
