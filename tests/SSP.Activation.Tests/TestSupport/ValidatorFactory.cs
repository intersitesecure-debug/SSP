using SSP.Activation;

namespace SSP.Activation.Tests.TestSupport;

/// <summary>Factory for standalone <see cref="LicenseValidator"/> instances with sensible test defaults.</summary>
internal static class ValidatorFactory
{
    public const string DefaultInstallationId = "INSTALLATION-A";

    public static LicenseValidator Create(
        TestAuthority authority,
        FixedClock? clock = null,
        IInstallationIdentityProvider? identity = null,
        ILicenseStateStore? stateStore = null,
        ILicenseRevocationChecker? revocationChecker = null,
        ISecurityEventSink? eventSink = null)
    {
        return new LicenseValidator(
            authority.TrustAnchor,
            new LicenseValidationOptions(authority.ProductId),
            clock ?? new FixedClock(LicensePayloadFactory.BaseTime),
            identity ?? new StaticInstallationIdentityProvider(DefaultInstallationId),
            stateStore,
            revocationChecker,
            eventSink);
    }
}
