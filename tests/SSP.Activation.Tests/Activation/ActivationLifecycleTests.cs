using System.Security.Cryptography;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Activation;

/// <summary>
/// The activation state machine, end to end: a certified license whose key
/// certification carries an activation-code hash loads as ActivationRequired
/// (denied), only the correct 10-digit code transitions it to Valid, the
/// activation is durable across restart, and it never leaks to a different
/// license. The server never generates a code — these tests only VERIFY one.
/// </summary>
public class ActivationLifecycleTests
{
    private static string IssueActivationRequired(
        TestAuthority authority,
        LicensePayload payload,
        string activationCode,
        out RSA leaf,
        string? activationOtt = null)
    {
        leaf = TestAuthority.CreateLeafKey();
        var certification = authority.Certify(
            payload,
            leaf,
            activationOtt,
            LicenseActivation.ComputeActivationCodeHash(activationCode));
        return authority.IssueCertified(payload, certification, leaf);
    }

    [Fact]
    public void ActivationRequiredLicense_LoadsAsActivationRequired_AndIsDenied()
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().Build();
        var artifact = IssueActivationRequired(system.Authority, payload, "1234567890", out var leaf);
        using (leaf)
        {
            var result = system.Manager.LoadLicense(artifact);

            Assert.Equal(LicenseState.ActivationRequired, result.State);
            Assert.Equal(LicenseReasons.ActivationRequired, result.ReasonCode);
            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.ActivationRequired, system.Manager.CurrentState);
            Assert.Null(system.Manager.CurrentLicense);

            // The chain verified: the authenticated payload and certification are still
            // available for diagnostics and for the activation step.
            Assert.NotNull(result.License);
            Assert.NotNull(result.License!.Certification);
            Assert.True(result.License.Certification!.RequiresActivation);

            // Protected operations stay denied while activation is pending.
            Assert.False(system.Enforcement().RequireValidLicense().IsAllowed);
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
            Assert.False(system.Enforcement().CanStartProtectedService().IsAllowed);
        }
    }

    [Fact]
    public void WrongActivationCode_StaysActivationRequired()
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().Build();
        var artifact = IssueActivationRequired(system.Authority, payload, "1234567890", out var leaf);
        using (leaf)
        {
            system.Manager.LoadLicense(artifact);

            var result = system.Manager.TryActivate("0000000000");

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.ActivationRequired, result.State);
            Assert.Equal(LicenseReasons.InvalidActivationCode, result.ReasonCode);
            Assert.Equal(LicenseState.ActivationRequired, system.Manager.CurrentState);
            Assert.False(system.Enforcement().RequireValidLicense().IsAllowed);
        }
    }

    [Fact]
    public void CorrectActivationCode_TransitionsToValid()
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().Build();
        var artifact = IssueActivationRequired(system.Authority, payload, "2468013579", out var leaf);
        using (leaf)
        {
            system.Manager.LoadLicense(artifact);

            var result = system.Manager.TryActivate("2468 0135 79"); // spaces are tolerated

            Assert.True(result.IsValid);
            Assert.Equal(LicenseState.Valid, result.State);
            Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);
            Assert.NotNull(system.Manager.CurrentLicense);
            Assert.True(system.Enforcement().RequireValidLicense().IsAllowed);

            Assert.Contains(
                system.Events.Snapshot(),
                e => e.EventType == LicenseSecurityEventType.LicenseActivated && e.State == LicenseState.Valid);
        }
    }

    [Fact]
    public void ActivatedLicense_DoesNotRequireReactivation_AfterRestart()
    {
        // A durable state store (or any store) records ActivatedLicenseId; a NEW manager
        // over the same store (a "restart") must validate the same artifact as Valid
        // without the operator re-entering the code.
        using var authority = new TestAuthority();
        var store = new InMemoryLicenseStateStore();

        var payload = LicensePayloadFactory.For(authority).Build();
        var artifact = IssueActivationRequired(authority, payload, "1357924680", out var leaf);
        using (leaf)
        {
            using (var first = new TestLicenseSystem(stateStore: store, authority: authority))
            {
                first.Manager.LoadLicense(artifact);
                Assert.Equal(LicenseState.ActivationRequired, first.Manager.CurrentState);
                Assert.True(first.Manager.TryActivate("1357924680").IsValid);
                Assert.NotNull(store.Load()?.ActivatedLicenseId);
                Assert.Equal(payload.LicenseId, store.Load()!.ActivatedLicenseId);
            }

            using (var restarted = new TestLicenseSystem(stateStore: store, authority: authority))
            {
                var result = restarted.Manager.LoadLicense(artifact);
                Assert.True(result.IsValid);
                Assert.Equal(LicenseState.Valid, restarted.Manager.CurrentState);
            }
        }
    }

    [Fact]
    public void ActivationForOneLicense_DoesNotActivateAnotherLicense()
    {
        using var system = new TestLicenseSystem();
        var payloadA = system.License().Build();
        var payloadB = system.License().Build(); // different LicenseId
        Assert.NotEqual(payloadA.LicenseId, payloadB.LicenseId);

        var artifactA = IssueActivationRequired(system.Authority, payloadA, "1111111111", out var leafA);
        var artifactB = IssueActivationRequired(system.Authority, payloadB, "2222222222", out var leafB);
        using (leafA)
        using (leafB)
        {
            system.Manager.LoadLicense(artifactA);
            Assert.True(system.Manager.TryActivate("1111111111").IsValid);

            // Loading license B returns it to ActivationRequired: A's activation is bound
            // to A's license id and does not carry over.
            var resultB = system.Manager.LoadLicense(artifactB);
            Assert.Equal(LicenseState.ActivationRequired, resultB.State);
            Assert.False(resultB.IsValid);

            // And only B's code activates B.
            Assert.False(system.Manager.TryActivate("1111111111").IsValid);
            Assert.True(system.Manager.TryActivate("2222222222").IsValid);
        }
    }

    [Fact]
    public void PreActivatedCertifiedLicense_IsValidImmediately()
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().Build();
        using var leaf = TestAuthority.CreateLeafKey();
        var certification = system.Authority.Certify(payload, leaf); // no activation material
        var artifact = system.Authority.IssueCertified(payload, certification, leaf);

        var result = system.Manager.LoadLicense(artifact);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, result.State);
        Assert.False(certification.RequiresActivation);
    }

    [Fact]
    public void TryActivate_WithoutPendingLicense_FailsClosed()
    {
        using var system = new TestLicenseSystem();
        var result = system.Manager.TryActivate("1234567890");

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.ActivationRequired, result.State);
        Assert.Equal(LicenseReasons.ActivationRequired, result.ReasonCode);
    }

    [Fact]
    public void LegacyV1License_NeverEntersActivationRequired()
    {
        using var system = new TestLicenseSystem();
        var artifact = system.Authority.Issue(system.License().Build());

        var result = system.Manager.LoadLicense(artifact);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, result.State);
        Assert.Null(result.License!.Certification);
    }
}
