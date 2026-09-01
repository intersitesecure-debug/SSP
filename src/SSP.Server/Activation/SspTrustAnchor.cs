// File: src/SSP.Server/Activation/SspTrustAnchor.cs
//
// SSP-native trust-anchor composition. The Licensing Authority public key is
// the single root of trust for activation. It is a build/deployment constant
// of the SSP shipping builds - never loaded from user-editable configuration,
// environment variables or the filesystem - so configuration changes can never
// install a usable verification key. The private signing key never exists in
// this repository or in any shipped SSP binary.

using SSP.Activation;

namespace SSP.Server.Activation;

/// <summary>
/// Owns the compiled-in SSP Licensing Authority public key and builds the
/// <see cref="LicenseTrustAnchor"/> used by the activation runtime.
/// </summary>
public static class SspTrustAnchor
{
    /// <summary>
    /// The SSP Licensing Authority RSA public key in PEM ("PUBLIC KEY")
    /// format.
    ///
    /// TODO (release ceremony): set this to the actual authority public key
    /// before shipping a production-protecting build. A build with no anchor
    /// compiled in must not enforce (the later composition root enters the
    /// loud unmanaged-development mode); <see cref="Create"/> fails closed
    /// rather than falling back to an assumed key.
    /// </summary>
    public const string AuthorityPublicKeyPem = "";

    /// <summary>Minimum RSA key size accepted for the trusted anchor.</summary>
    public const int MinimumKeySizeBits = LicenseTrustAnchor.MinimumKeySizeBits;

    /// <summary>
    /// True when this build has an actual trust anchor compiled in. Dev
    /// builds without one return false so the composition root can run the
    /// documented unmanaged-dev mode instead of silently enforcing nothing
    /// while pretending to be licensed.
    /// </summary>
    public static bool IsCompiledIn => !string.IsNullOrWhiteSpace(AuthorityPublicKeyPem);

    /// <summary>
    /// Creates the production trust anchor from the compiled-in public key.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// No production trust anchor is compiled into this build.
    /// </exception>
    public static LicenseTrustAnchor Create()
    {
        if (!IsCompiledIn)
        {
            throw new InvalidOperationException(
                "SSP activation trust anchor is not compiled into this build. " +
                "Set SspTrustAnchor.AuthorityPublicKeyPem to the SSP Licensing " +
                "Authority public key before shipping a production-protecting build.");
        }

        return LicenseTrustAnchor.FromPem(AuthorityPublicKeyPem);
    }
}
