namespace SSP.Activation;

/// <summary>
/// Decoded artifact envelope: parsed payload plus envelope metadata and the raw signature
/// bytes. Produced by <see cref="LicenseArtifactCodec.TryDecode"/>.
/// </summary>
public sealed record LicenseArtifact
{
    public required LicensePayload Payload { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required int ArtifactVersion { get; init; }
    public required byte[] Signature { get; init; }

    /// <summary>
    /// For version-2 artifacts: the decoded per-license key certification (its canonical
    /// bytes are what the root authority signed). Null for version-1 artifacts. The
    /// certification is untrusted until <see cref="LicenseValidator"/> verifies its
    /// signature against the root anchor.
    /// </summary>
    public LicenseKeyCertification? Certification { get; init; }

    /// <summary>
    /// For version-2 artifacts: the root authority's signature over the certification's
    /// canonical bytes. Null for version-1 artifacts.
    /// </summary>
    public byte[]? CertificationSignature { get; init; }
}
