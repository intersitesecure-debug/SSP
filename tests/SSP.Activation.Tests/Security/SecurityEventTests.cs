using System.Text.Json;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Security;

/// <summary>Verifies the correct security event is emitted for important failures and successes.</summary>
public class SecurityEventTests
{
    [Fact]
    public void ValidLicense_EmitsLoadedThenValidated()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        var events = system.Events.Snapshot();
        Assert.Contains(events, e => e.EventType == LicenseSecurityEventType.LicenseLoaded);
        Assert.Contains(events, e => e.EventType == LicenseSecurityEventType.LicenseValidated && e.State == LicenseState.Valid);
    }

    [Fact]
    public void InvalidSignature_EmitsInvalidSignatureEvent()
    {
        using var system = new TestLicenseSystem();
        var tampered = ArtifactTestHelper.MakeArtifact(
            ArtifactTestHelper.MutatePayloadJson(
                ArtifactTestHelper.GetPayloadJson(system.Authority.Issue(system.License().Build())),
                node => node["customerName"] = "Someone Else"),
            ArtifactTestHelper.GetSignatureBytes(system.Authority.Issue(system.License().Build())));

        system.Manager.LoadLicense(tampered);

        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.InvalidSignature);
    }

    [Fact]
    public void Expired_EmitsLicenseExpiredEvent()
    {
        using var system = new TestLicenseSystem();
        system.Clock.Advance(TimeSpan.FromDays(400));
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseExpired);
    }

    [Fact]
    public void WrongInstallation_EmitsLicenseBindingFailedEvent()
    {
        using var system = new TestLicenseSystem("INSTALLATION-A");
        var artifact = system.Authority.Issue(LicensePayloadFactory.For(system.Authority).WithInstallationId("OTHER-INSTALL").Build());

        system.Manager.LoadLicense(artifact);

        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseBindingFailed);
    }

    [Fact]
    public void Revoked_EmitsLicenseRevokedEvent()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithStatus(LicenseStatus.Revoked).Build()));

        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseRevoked);
    }

    [Fact]
    public void Malformed_EmitsLicenseValidationFailedEvent()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense("::garbage::");

        Assert.Contains(system.Events.Snapshot(), e =>
            e.EventType == LicenseSecurityEventType.LicenseValidationFailed &&
            e.ReasonCode == LicenseReasons.MalformedArtifact);
    }

    [Fact]
    public void MissingLicense_EmitsLicenseValidationFailedEvent_WithMissingReason()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense("   ");

        Assert.Contains(system.Events.Snapshot(), e =>
            e.EventType == LicenseSecurityEventType.LicenseValidationFailed &&
            e.ReasonCode == LicenseReasons.MissingLicense);
    }

    [Fact]
    public void Lockdown_EmitsActivatedAndClearedEvents()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(
            system.License().WithExpiresAt(LicensePayloadFactory.BaseTime.AddSeconds(-1)).Build()));
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithSequence(2).Build()));

        var events = system.Events.Snapshot();
        Assert.Contains(events, e => e.EventType == LicenseSecurityEventType.LicenseLockdownActivated);
        Assert.Contains(events, e => e.EventType == LicenseSecurityEventType.LicenseLockdownCleared);
    }

    [Fact]
    public void Events_CarryReasonCodeAndLicenseIdButNeverSecretMaterial()
    {
        using var system = new TestLicenseSystem();
        var artifact = system.Authority.Issue(system.License().Build());
        system.Manager.LoadLicense(artifact);
        system.Manager.LoadLicense("::garbage::");

        var json = JsonSerializer.Serialize(system.Events.Snapshot());

        // Events must not embed signature material or key material.
        Assert.DoesNotContain("signature", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BEGIN", json, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", json, StringComparison.Ordinal);

        var loadedEvent = system.Events.Snapshot().First(e => e.EventType == LicenseSecurityEventType.LicenseLoaded);
        Assert.NotNull(loadedEvent.LicenseId);
        Assert.Equal(LicenseReasons.Ok, loadedEvent.ReasonCode);
    }
}
