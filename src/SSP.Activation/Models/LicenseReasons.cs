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

    /// <summary>The local UTC clock regressed below protected, previously observed time.</summary>
    public const string ClockRollbackDetected = "clock_rollback_detected";

    /// <summary>The clock cannot be sampled reliably. State I/O failures retain state_store_unavailable.</summary>
    public const string TimeIntegrityUnavailable = "time_integrity_unavailable";

    /// <summary>The license is valid but requires activation (10-digit code) before it can authorize anything.</summary>
    public const string ActivationRequired = "activation_required";

    /// <summary>The activation code entered did not match the signed verification data for this license.</summary>
    public const string InvalidActivationCode = "invalid_activation_code";

    /// <summary>The root signature over the per-license key certification did not verify.</summary>
    public const string InvalidCertificationSignature = "invalid_certification_signature";

    /// <summary>The certified per-license public key is not a usable RSA key.</summary>
    public const string InvalidCertificationKey = "invalid_certification_key";

    /// <summary>The certification does not match the license payload it is embedded with (LicenseId/ProductId/CustomerId).</summary>
    public const string CertificationBindingMismatch = "certification_binding_mismatch";

    /// <summary>The certification is not yet valid (its NotBefore is in the future).</summary>
    public const string CertificationNotYetValid = "certification_not_yet_valid";

    /// <summary>The certification has expired (its ExpiresAt has passed).</summary>
    public const string CertificationExpired = "certification_expired";
}
