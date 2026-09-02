using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Lockdown;

/// <summary>
/// Lockdown lifecycle: activation on invalid license, denial during lockdown, recovery
/// with a valid license, re-lockdown, restart behavior and non-destructiveness.
/// </summary>
public class LockdownTests
{
    [Fact]
    public void InvalidLicense_ActivatesLockdown()
    {
        using var system = new TestLicenseSystem();
        var invalidArtifact = system.Authority.Issue(system.License().WithExpiresAt(LicensePayloadFactory.BaseTime.AddSeconds(-1)).Build());

        var result = system.Manager.LoadLicense(invalidArtifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.Null(system.Manager.CurrentLicense);
        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseLockdownActivated);
    }

    [Fact]
    public void Lockdown_DeniesProtectedOperations()
    {
        using var system = new TestLicenseSystem();
        var invalidArtifact = system.Authority.Issue(system.License().WithStatus(LicenseStatus.Revoked).Build());
        system.Manager.LoadLicense(invalidArtifact);

        var enforcement = system.Enforcement();
        Assert.False(enforcement.CanUseFeature("rdp").IsAllowed);
        Assert.False(enforcement.CanCreateSession(0).IsAllowed);
        Assert.False(enforcement.CanStartProtectedService(0).IsAllowed);
        Assert.False(enforcement.CanEstablishTunnel(0).IsAllowed);

        var decision = enforcement.CanUseFeature("rdp");
        Assert.Equal(LicenseReasons.LicenseNotValid, decision.ReasonCode);
        Assert.Contains("LockedDown", decision.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void LockdownActivated_EmittedOncePerTransition()
    {
        using var system = new TestLicenseSystem();
        var invalidArtifact = system.Authority.Issue(system.License().WithStatus(LicenseStatus.Revoked).Build());
        system.Manager.LoadLicense(invalidArtifact);
        system.Manager.LoadLicense(invalidArtifact);

        var activations = system.Events.Snapshot()
            .Count(e => e.EventType == LicenseSecurityEventType.LicenseLockdownActivated);

        Assert.Equal(1, activations);
    }

    [Fact]
    public void Revalidate_AfterClockPassesExpiry_LocksDown()
    {
        using var system = new TestLicenseSystem();
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));
        Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);

        system.Clock.Advance(TimeSpan.FromDays(400)); // license valid 1 year from base time

        var result = system.Manager.Revalidate();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Expired, result.State);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
    }

    [Fact]
    public void Restart_RequiresRevalidation_BeforeOperationsResume()
    {
        // One deployment = one authority (trust anchor + product id), shared across runs.
        var authority = new TestAuthority();
        try
        {
            var issued = authority.Issue(LicensePayloadFactory.For(authority).Build());

            using (var running = new TestLicenseSystem(authority: authority))
            {
                Assert.True(running.Manager.LoadLicense(issued).IsValid);
                Assert.True(running.Enforcement().CanUseFeature("rdp").IsAllowed);
            }

            // Restart: a fresh manager with no in-memory state, same trust anchor and
            // product identity, and no license loaded yet.
            using (var restarted = new TestLicenseSystem(authority: authority))
            {
                Assert.Equal(LicenseState.Unknown, restarted.Manager.CurrentState);
                Assert.False(restarted.Enforcement().CanUseFeature("rdp").IsAllowed);
                Assert.Equal(LicenseReasons.LicenseNotValid, restarted.Manager.Authorize(ProtectedOperation.UseFeature("rdp")).ReasonCode);

                // Only revalidation against the signed artifact restores the Valid state.
                var result = restarted.Manager.LoadLicense(issued);
                Assert.True(result.IsValid);
                Assert.Equal(LicenseState.Valid, restarted.Manager.CurrentState);
                Assert.True(restarted.Enforcement().CanUseFeature("rdp").IsAllowed);
            }
        }
        finally
        {
            authority.Dispose();
        }
    }

    [Fact]
    public void ValidLicense_ClearsLockdown()
    {
        using var system = new TestLicenseSystem();

        // Enter lockdown with an expired license.
        system.Manager.LoadLicense(system.Authority.Issue(
            system.License().WithExpiresAt(LicensePayloadFactory.BaseTime.AddSeconds(-1)).Build()));
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);

        // Install a legitimate replacement license.
        var replacement = system.Authority.Issue(system.License().WithSequence(2).Build());
        var result = system.Manager.LoadLicense(replacement);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);
        Assert.True(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseLockdownCleared);
    }

    [Fact]
    public void InvalidLicense_AfterRecovery_ReturnsToLockdown()
    {
        using var system = new TestLicenseSystem();

        system.Manager.LoadLicense(system.Authority.Issue(
            system.License().WithExpiresAt(LicensePayloadFactory.BaseTime.AddSeconds(-1)).Build()));
        system.Manager.LoadLicense(system.Authority.Issue(system.License().WithSequence(2).Build()));
        Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);

        system.Manager.LoadLicense(system.Authority.Issue(
            system.License().WithSequence(3).WithStatus(LicenseStatus.Revoked).Build()));

        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        var activations = system.Events.Snapshot()
            .Count(e => e.EventType == LicenseSecurityEventType.LicenseLockdownActivated);
        Assert.Equal(2, activations);
    }

    [Fact]
    public void Lockdown_IsNotClearedByDeletingTheLicense()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var licensePath = Path.Combine(dir, "license.json");
            using var system = NewSystemWithFileProvider(licensePath);

            system.Manager.LoadLicense(system.Authority.Issue(
                system.License().WithExpiresAt(LicensePayloadFactory.BaseTime.AddSeconds(-1)).Build()));
            Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);

            File.Delete(licensePath);
            var result = system.Manager.Load();

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState); // stays locked down
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    private static TestLicenseSystem NewSystemWithFileProvider(string licensePath)
        => new(provider: new LocalLicenseFileProvider(licensePath));
}
