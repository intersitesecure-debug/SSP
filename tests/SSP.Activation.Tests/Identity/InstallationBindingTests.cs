using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Identity;

/// <summary>Installation binding: identity matching, mismatch, case handling, floating licenses.</summary>
public class InstallationBindingTests
{
    [Fact]
    public void BoundLicense_MatchingInstallation_IsValid()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(
            authority,
            identity: new StaticInstallationIdentityProvider("INSTALLATION-A"));

        var artifact = authority.Issue(LicensePayloadFactory.For(authority).WithInstallationId("INSTALLATION-A").Build());

        Assert.True(validator.Validate(artifact).IsValid);
    }

    [Fact]
    public void LicenseCopiedToAnotherInstallation_IsRejected()
    {
        using var authority = new TestAuthority();
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).WithInstallationId("INSTALLATION-A").Build());

        var installationA = ValidatorFactory.Create(authority, identity: new StaticInstallationIdentityProvider("INSTALLATION-A"));
        var installationB = ValidatorFactory.Create(authority, identity: new StaticInstallationIdentityProvider("INSTALLATION-B"));

        Assert.True(installationA.Validate(artifact).IsValid);

        var result = installationB.Validate(artifact);
        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.WrongInstallation, result.State);
        Assert.Equal(LicenseReasons.WrongInstallation, result.ReasonCode);
    }

    [Fact]
    public void InstallationComparison_IsCaseAndWhitespaceInsensitive()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(
            authority,
            identity: new StaticInstallationIdentityProvider("  installation-a  "));

        var artifact = authority.Issue(LicensePayloadFactory.For(authority).WithInstallationId("INSTALLATION-A").Build());

        Assert.True(validator.Validate(artifact).IsValid);
    }

    [Fact]
    public void UnboundLicense_IsAcceptedOnAnyInstallation()
    {
        using var authority = new TestAuthority();
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).WithInstallationId(null).Build());

        var installationA = ValidatorFactory.Create(authority, identity: new StaticInstallationIdentityProvider("INSTALLATION-A"));
        var installationB = ValidatorFactory.Create(authority, identity: new StaticInstallationIdentityProvider("INSTALLATION-B"));

        Assert.True(installationA.Validate(artifact).IsValid);
        Assert.True(installationB.Validate(artifact).IsValid);
    }

    [Fact]
    public void IdentityUnavailable_FailsClosed()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority, identity: new StaticInstallationIdentityProvider(null));

        var boundArtifact = authority.Issue(LicensePayloadFactory.For(authority).WithInstallationId("INSTALLATION-A").Build());
        var boundResult = validator.Validate(boundArtifact);
        Assert.False(boundResult.IsValid);
        Assert.Equal(LicenseReasons.IdentityUnavailable, boundResult.ReasonCode);

        // Even an unbound license must not pass when the host cannot prove an installation
        // identity is irrelevant... unbound licenses are installation-independent by design,
        // so they remain valid; the binding check is what requires identity.
        var unboundArtifact = authority.Issue(LicensePayloadFactory.For(authority).WithInstallationId(null).Build());
        Assert.True(validator.Validate(unboundArtifact).IsValid);
    }

    [Fact]
    public void IdentityProviderThrowing_FailsClosed()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority, identity: new ThrowingIdentityProvider());

        var artifact = authority.Issue(LicensePayloadFactory.For(authority).WithInstallationId("INSTALLATION-A").Build());
        var result = validator.Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.IdentityUnavailable, result.ReasonCode);
    }

    private sealed class ThrowingIdentityProvider : IInstallationIdentityProvider
    {
        public string? GetInstallationId() => throw new InvalidOperationException("identity source unavailable");
    }
}
