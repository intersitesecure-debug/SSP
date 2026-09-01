namespace SSP.Activation;

/// <summary>
/// Stable, machine-readable reason codes exposed on validation results, authorization
/// decisions and security events. Codes are part of the public contract: new codes may be
/// added in future versions, existing codes will not change meaning.
/// </summary>
public static class LicenseReasons
{
    public const string Ok = "ok";
    public const string MissingLicense = "missing_license";
    public const string MalformedArtifact = "malformed_artifact";
    public const string InvalidSchema = "invalid_payload_schema";
    public const string UnsupportedSignatureAlgorithm = "unsupported_signature_algorithm";
    public const string InvalidSignature = "invalid_signature";
    public const string Revoked = "revoked";
    public const string WrongProduct = "wrong_product";
    public const string WrongInstallation = "wrong_installation";
    public const string IdentityUnavailable = "installation_identity_unavailable";
    public const string NotYetValid = "not_yet_valid";
    public const string Expired = "expired";
    public const string Superseded = "superseded";
    public const string LicenseNotValid = "license_not_valid";
    public const string FeatureNotLicensed = "feature_not_licensed";
    public const string LimitExceeded = "limit_exceeded";
    public const string OperationNotSupported = "operation_not_supported";
    public const string InvalidOperation = "invalid_operation";
    public const string ProviderError = "provider_error";
    public const string RevocationCheckFailed = "revocation_check_failed";
    public const string StateStoreUnavailable = "state_store_unavailable";
    public const string InternalError = "internal_error";
}
