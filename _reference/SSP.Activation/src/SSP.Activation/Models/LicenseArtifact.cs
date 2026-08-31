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
}
