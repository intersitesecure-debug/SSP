namespace SSP.Activation;

/// <summary>
/// Classification of artifact decode failures. Every decode failure leads to a Malformed
/// validation state — malformed artifacts never reach signature verification and can never
/// authorize anything.
/// </summary>
public enum ArtifactDecodeErrorCode
{
    InvalidJson = 1,
    DuplicateField = 2,
    MissingField = 3,
    UnknownField = 4,
    UnsupportedFormat = 5,
    UnknownArtifactVersion = 6,
    UnknownSignatureAlgorithm = 7,
    InvalidEncoding = 8,
    InvalidPayloadJson = 9,
    InvalidPayloadSchema = 10
}

/// <summary>Structured decode failure detail. Safe for logs; never contains secrets.</summary>
public sealed record ArtifactDecodeError(ArtifactDecodeErrorCode Code, string Detail);
