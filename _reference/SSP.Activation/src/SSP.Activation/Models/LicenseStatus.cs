namespace SSP.Activation;

/// <summary>
/// Lifecycle status assigned by the SSP Licensing Authority and covered by the signature.
/// A license cannot be revoked by editing the artifact (that would break the signature);
/// revocation is expressed by the authority (payload status) or through an
/// <see cref="ILicenseRevocationChecker"/>.
/// </summary>
public enum LicenseStatus
{
    Active = 1,
    Revoked = 2
}
