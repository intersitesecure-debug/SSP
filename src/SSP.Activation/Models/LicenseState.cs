namespace SSP.Activation;

/// <summary>
/// Strongly typed state classification for a license during validation and at runtime.
/// Authorization must never be derived from raw integer values; always compare against
/// the named enum members.
/// </summary>
public enum LicenseState
{
    /// <summary>No license has been loaded (e.g. license missing or deleted), or the installation identity is unavailable.</summary>
    Unknown = 0,

    /// <summary>The license is cryptographically valid and currently within its validity window.</summary>
    Valid = 1,

    /// <summary>The license is otherwise valid, but its NotBefore time is in the future.</summary>
    NotYetValid = 2,

    /// <summary>The license validity window has ended (ExpiresAt is exclusive).</summary>
    Expired = 3,

    /// <summary>The signature over the license payload does not verify against the trust anchor, or the signature algorithm is unsupported.</summary>
    InvalidSignature = 4,

    /// <summary>The artifact could not be parsed or failed schema validation.</summary>
    Malformed = 5,

    /// <summary>The license was issued for a different product.</summary>
    WrongProduct = 6,

    /// <summary>The license is bound to a different installation.</summary>
    WrongInstallation = 7,

    /// <summary>The license was revoked (payload status or a revocation checker).</summary>
    Revoked = 8,

    /// <summary>Runtime lockdown: a loaded license failed validation; all protected operations are denied until a valid license is loaded and revalidated.</summary>
    LockedDown = 9,

    /// <summary>Anti-rollback: the license sequence number is older than the highest accepted sequence number.</summary>
    Superseded = 10,

    /// <summary>
    /// The license chain verified, but this license is activation-required and has not
    /// been activated yet (the persisted <c>ActivatedLicenseId</c> does not match this
    /// license). Protected operations are denied; entering the activation code transitions
    /// the license to <see cref="Valid"/>.
    /// </summary>
    ActivationRequired = 11,

    /// <summary>The per-license key certification failed to verify (bad root signature, unusable certified key, or a certification/license binding mismatch).</summary>
    InvalidCertification = 12
}
