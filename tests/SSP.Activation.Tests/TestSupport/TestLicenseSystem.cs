using SSP.Activation;

namespace SSP.Activation.Tests.TestSupport;

/// <summary>
/// Pre-wired licensing runtime for manager/enforcement/lockdown tests. Uses a fixed clock,
/// an in-memory event sink and an in-memory state store; the installation identity is a
/// static id (default INSTALLATION-A).
/// </summary>
internal sealed class TestLicenseSystem : IDisposable
{
    private readonly bool _ownsAuthority;

    public TestAuthority Authority { get; }

    public FixedClock Clock { get; } = new(LicensePayloadFactory.BaseTime);

    public InMemorySecurityEventSink Events { get; } = new();

    public ILicenseStateStore StateStore { get; }

    public StaticInstallationIdentityProvider Identity { get; }

    public ILicenseProvider? Provider { get; }

    public LicenseManager Manager { get; }

    public TestLicenseSystem(
        string installationId = ValidatorFactory.DefaultInstallationId,
        ILicenseProvider? provider = null,
        ILicensePolicy? policy = null,
        ILicenseStateStore? stateStore = null,
        TestAuthority? authority = null)
    {
        // The authority (trust anchor + product id) can be shared across systems, e.g. to
        // simulate the same installation after a restart, or the same license on a
        // different installation.
        Authority = authority ?? new TestAuthority();
        _ownsAuthority = authority is null;
        Identity = new StaticInstallationIdentityProvider(installationId);
        Provider = provider;
        StateStore = stateStore ?? new InMemoryLicenseStateStore();
        Manager = new LicenseManager(
            new LicenseValidationOptions(Authority.ProductId),
            Authority.TrustAnchor,
            Identity,
            Clock,
            Provider,
            policy,
            Events,
            StateStore);
    }

    /// <summary>A payload factory bound to this system's authority.</summary>
    public LicensePayloadFactory License() => LicensePayloadFactory.For(Authority);

    public LicenseEnforcement Enforcement() => new(Manager);

    public void Dispose()
    {
        // Only dispose an authority this system created; shared authorities are owned
        // (and disposed) by the test itself.
        if (_ownsAuthority)
        {
            Authority.Dispose();
        }
    }
}
