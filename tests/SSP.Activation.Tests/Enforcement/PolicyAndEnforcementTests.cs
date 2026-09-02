using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Enforcement;

/// <summary>Feature authorization and limit enforcement through manager + default policy.</summary>
public class PolicyAndEnforcementTests
{
    [Fact]
    public void LicensedFeature_IsAllowed()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        var decision = system.Enforcement().CanUseFeature("rdp");

        Assert.True(decision.IsAllowed);
        Assert.Equal(LicenseReasons.Ok, decision.ReasonCode);
    }

    [Fact]
    public void UnlicensedFeature_IsDenied()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithFeatures("rdp").Build()));

        var decision = system.Enforcement().CanUseFeature("ssh");

        Assert.False(decision.IsAllowed);
        Assert.Equal(LicenseReasons.FeatureNotLicensed, decision.ReasonCode);
    }

    [Fact]
    public void UnknownFeature_IsDenied_WithSameReasonAsUnlicensed()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        var decision = system.Enforcement().CanUseFeature("made-up-feature");

        Assert.False(decision.IsAllowed);
        Assert.Equal(LicenseReasons.FeatureNotLicensed, decision.ReasonCode);
    }

    [Fact]
    public void FeatureCheck_IsCaseAndWhitespaceInsensitive()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithFeatures("rdp").Build()));

        Assert.True(system.Enforcement().CanUseFeature("RDP").IsAllowed);
        Assert.True(system.Enforcement().CanUseFeature("  rdp ").IsAllowed);
    }

    [Fact]
    public void InvalidFeatureName_IsDenied_AsInvalidOperation()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        var decision = system.Enforcement().CanUseFeature("   ");

        Assert.False(decision.IsAllowed);
        Assert.Equal(LicenseReasons.InvalidOperation, decision.ReasonCode);
    }

    [Fact]
    public void EmptyFeatureSet_DeniesAllFeatures()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithFeatures().Build()));

        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        Assert.True(system.Manager.CurrentState == LicenseState.Valid);
    }

    [Fact]
    public void LimitWithinCap_IsAllowed()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithLimit(LicenseLimitNames.MaxConcurrentSessions, 5).Build()));

        Assert.True(system.Enforcement().CanCreateSession(4).IsAllowed); // 4 active, adding 5th
    }

    [Fact]
    public void LimitExceeded_IsDenied()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithLimit(LicenseLimitNames.MaxConcurrentSessions, 5).Build()));

        var decision = system.Enforcement().CanCreateSession(5); // 5 active, a 6th would exceed

        Assert.False(decision.IsAllowed);
        Assert.Equal(LicenseReasons.LimitExceeded, decision.ReasonCode);
    }

    [Fact]
    public void ExplicitUnlimitedLimit_IsAlwaysAllowed()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(
            system.License().WithLimit(LicenseLimitNames.MaxConcurrentSessions, null).Build()));

        Assert.True(system.Enforcement().CanCreateSession(1_000_000).IsAllowed);
    }

    [Fact]
    public void AbsentLimit_IsUnconstrained()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithLimits(new Dictionary<string, long?>()).Build()));

        Assert.True(system.Enforcement().CanCreateSession(999).IsAllowed);
        Assert.True(system.Enforcement().CanStartProtectedService(999).IsAllowed);
    }

    [Fact]
    public void NegativeUsage_IsDenied_AsInvalidOperation()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        var decision = system.Enforcement().CanCreateSession(-1);

        Assert.False(decision.IsAllowed);
        Assert.Equal(LicenseReasons.InvalidOperation, decision.ReasonCode);
    }

    [Fact]
    public void EnforcementFacade_RoutesAllProtectedOperations()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(
            system.License()
                .WithFeatures("rdp")
                .WithLimit(LicenseLimitNames.MaxServices, 2)
                .WithLimit(LicenseLimitNames.MaxConcurrentTunnels, 1)
                .Build()));

        Assert.True(system.Enforcement().CanStartProtectedService(1).IsAllowed);
        Assert.False(system.Enforcement().CanStartProtectedService(2).IsAllowed);
        Assert.True(system.Enforcement().CanEstablishTunnel(0).IsAllowed);
        Assert.False(system.Enforcement().CanEstablishTunnel(1).IsAllowed);
        Assert.True(system.Enforcement().CanUseFeature("rdp").IsAllowed);
    }

    [Fact]
    public void CustomPolicy_IsConsulted_AndCanDeny()
    {
        using var system = new TestLicenseSystem(policy: new DenyAllPolicy());
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        var decision = system.Enforcement().CanUseFeature("rdp");

        Assert.False(decision.IsAllowed);
        Assert.Equal("custom_deny", decision.ReasonCode);
    }

    [Fact]
    public void DeniedOperations_EmitProtectedOperationDeniedEvents()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        system.Enforcement().CanUseFeature("not-licensed");

        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied);
    }

    private sealed class DenyAllPolicy : ILicensePolicy
    {
        public AuthorizationDecision Evaluate(LicenseEvaluationContext context)
            => AuthorizationDecision.Deny("custom_deny", "Denied by test policy.");
    }
}
