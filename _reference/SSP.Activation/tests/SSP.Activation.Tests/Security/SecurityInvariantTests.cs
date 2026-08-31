using System.Text.Json.Nodes;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Security;

/// <summary>
/// Explicit security invariant tests. Each test encodes one non-negotiable guarantee of
/// the licensing subsystem. If any of these fail, the trust boundary is broken.
/// </summary>
public class SecurityInvariantTests
{
    [Fact]
    public void Invariant_NoValidLicense_NoProtectedOperation()
    {
        using var system = new TestLicenseSystem();
        var enforcement = system.Enforcement();

        // Nothing loaded at all.
        Assert.False(enforcement.CanUseFeature("rdp").IsAllowed);
        Assert.False(enforcement.CanCreateSession(0).IsAllowed);
        Assert.False(enforcement.CanStartProtectedService(0).IsAllowed);
        Assert.False(enforcement.CanEstablishTunnel(0).IsAllowed);

        // A garbage artifact must not change that.
        system.Manager.LoadLicense("definitely not a license");
        Assert.False(enforcement.CanUseFeature("rdp").IsAllowed);
        Assert.False(enforcement.CanCreateSession(0).IsAllowed);

        // A syntactically valid artifact with an invalid signature must not either.
        var forged = ArtifactTestHelper.MakeArtifact(
            System.Text.Encoding.UTF8.GetString(LicenseCanonicalJson.Serialize(system.License().Build())),
            new byte[64]);
        system.Manager.LoadLicense(forged);
        Assert.False(enforcement.CanUseFeature("rdp").IsAllowed);
        Assert.False(enforcement.CanCreateSession(0).IsAllowed);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
    }

    [Fact]
    public void Invariant_ModifyingSignedField_InvalidatesLicense()
    {
        using var system = new TestLicenseSystem();
        var artifact = system.Authority.Issue(system.License().WithFeatures("rdp").Build());

        // Add a feature the authority never granted, keep the original signature.
        var mutatedPayload = ArtifactTestHelper.MutatePayloadJson(
            ArtifactTestHelper.GetPayloadJson(artifact),
            node => node["featureSet"] = new JsonArray("rdp", "ssh", "sql"));
        var tampered = ArtifactTestHelper.MakeArtifact(mutatedPayload, ArtifactTestHelper.GetSignatureBytes(artifact));

        var result = system.Manager.LoadLicense(tampered);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.False(system.Enforcement().CanUseFeature("ssh").IsAllowed);
        Assert.False(system.Enforcement().CanUseFeature("sql").IsAllowed);
        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed); // entire artifact rejected
    }

    [Fact]
    public void Invariant_WrongSigningKey_IsRejected()
    {
        using var system = new TestLicenseSystem();

        // An attacker-run "authority" signs a payload for the trusted product id.
        using var attackerAuthority = new TestAuthority();
        var attackerPayload = LicensePayloadFactory.For(attackerAuthority).WithProductId(system.Authority.ProductId).Build();
        var forgedArtifact = attackerAuthority.Issue(attackerPayload);

        var result = system.Manager.LoadLicense(forgedArtifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
    }

    [Fact]
    public void Invariant_WrongInstallation_IsRejected()
    {
        var authority = new TestAuthority();
        try
        {
            using var systemA = new TestLicenseSystem("INSTALLATION-A", authority: authority);
            var artifact = systemA.Authority.Issue(
                LicensePayloadFactory.For(systemA.Authority).WithInstallationId("INSTALLATION-A").Build());
            Assert.True(systemA.Manager.LoadLicense(artifact).IsValid);

            // The same artifact is copied to installation B (fresh process, fresh identity,
            // same deployment trust anchor).
            using var systemB = new TestLicenseSystem("INSTALLATION-B", authority: authority);
            var result = systemB.Manager.LoadLicense(artifact);

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.WrongInstallation, result.State);
            Assert.False(systemB.Enforcement().CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            authority.Dispose();
        }
    }

    [Fact]
    public void Invariant_ConfigurationCannotCreateAuthorization()
    {
        // (a) Environment variables claiming a licensed state must not authorize.
        Environment.SetEnvironmentVariable("SSP_LICENSING_STATE", "licensed");
        try
        {
            using var system = new TestLicenseSystem();
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);

            // (b) A configuration file that claims licensing must not authorize either:
            // the library reads no configuration at all; the only path to authorization is
            // a cryptographically valid artifact.
            var dir = TestPaths.CreateTempDirectory();
            try
            {
                File.WriteAllText(Path.Combine(dir, "ssp.config.json"), "{ \"licensed\": true, \"features\": [\"*\"] }");
                Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
                Assert.False(system.Manager.Authorize(ProtectedOperation.CheckLimit("unlimited_override", 0)).IsAllowed);
            }
            finally
            {
                TestPaths.DeleteDirectory(dir);
            }

            // (c) A poisoned state store (claiming a previously accepted license) must not
            // authorize a fresh process either.
            using var poisonedStoreSystem = new TestLicenseSystem(
                stateStore: new InMemoryLicenseStateStore());
            poisonedStoreSystem.StateStore.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = 100,
                LastAcceptedLicenseId = Guid.NewGuid()
            });
            Assert.Equal(LicenseState.Unknown, poisonedStoreSystem.Manager.CurrentState);
            Assert.False(poisonedStoreSystem.Enforcement().CanUseFeature("rdp").IsAllowed);
            Assert.False(poisonedStoreSystem.Enforcement().CanCreateSession(0).IsAllowed);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSP_LICENSING_STATE", null);
        }
    }

    [Fact]
    public void Invariant_ServiceRestartRequiresRevalidation()
    {
        var authority = new TestAuthority();
        try
        {
            var issued = authority.Issue(LicensePayloadFactory.For(authority).Build());

            using (var running = new TestLicenseSystem(authority: authority))
            {
                Assert.True(running.Manager.LoadLicense(issued).IsValid);
                Assert.True(running.Enforcement().CanUseFeature("rdp").IsAllowed);
            }

            // "Restart": a brand new manager knows nothing — even with a valid license file
            // present on disk, it must deny until it has REvalidated the artifact.
            using (var restarted = new TestLicenseSystem(authority: authority))
            {
                Assert.Equal(LicenseState.Unknown, restarted.Manager.CurrentState);
                Assert.False(restarted.Enforcement().CanUseFeature("rdp").IsAllowed);
                Assert.True(restarted.Manager.Revalidate().State == LicenseState.Unknown); // nothing loaded yet

                // Revalidation with the signed artifact is the only path back to Valid.
                Assert.True(restarted.Manager.LoadLicense(issued).IsValid);
                Assert.True(restarted.Enforcement().CanUseFeature("rdp").IsAllowed);
            }
        }
        finally
        {
            authority.Dispose();
        }
    }

    [Fact]
    public void Invariant_LicenseDeletionCannotAuthorize()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var licensePath = Path.Combine(dir, "ssp.license.json");
            using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(licensePath));

            // License present: valid.
            File.WriteAllText(licensePath, system.Authority.Issue(system.License().Build()));
            Assert.True(system.Manager.Load().IsValid);

            // License deleted: a fresh process must see UNKNOWN and deny everything.
            File.Delete(licensePath);
            using var fresh = new TestLicenseSystem(provider: new LocalLicenseFileProvider(licensePath));
            var result = fresh.Manager.Load();

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.Unknown, result.State);
            Assert.Equal(LicenseReasons.MissingLicense, result.ReasonCode);
            Assert.False(fresh.Enforcement().CanUseFeature("rdp").IsAllowed);
            Assert.False(fresh.Enforcement().CanCreateSession(0).IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void Invariant_OldLicenseAfterNewerLicense_IsRejected()
    {
        using var system = new TestLicenseSystem();

        // A newer license is accepted and its anti-rollback floor is persisted.
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(system.License().WithSequence(5).Build())).IsValid);
        Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);

        // An older license must never regain authorization — it is superseded and the
        // runtime enters (or stays in) lockdown, so nothing becomes operational.
        var older = system.Manager.LoadLicense(system.Authority.Issue(system.License().WithSequence(3).Build()));

        Assert.False(older.IsValid);
        Assert.Equal(LicenseState.Superseded, older.State);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        Assert.False(system.Enforcement().CanCreateSession(0).IsAllowed);
    }

    [Fact]
    public void Invariant_LockdownIsNonDestructive()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var licensePath = Path.Combine(dir, "ssp.license.json");
            var dataPath = Path.Combine(dir, "customer-data.txt");
            var licenseContent = "{}";
            var dataContent = "customer data that must never be touched by licensing";
            File.WriteAllText(licensePath, licenseContent);
            File.WriteAllText(dataPath, dataContent);
            var filesBefore = Directory.GetFiles(dir).OrderBy(p => p).ToArray();

            using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(licensePath));
            var result = system.Manager.Load(); // "{}" is a malformed artifact → lockdown

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);

            // Nothing may be deleted, modified or corrupted by the lockdown.
            var filesAfter = Directory.GetFiles(dir).OrderBy(p => p).ToArray();
            Assert.Equal(filesBefore, filesAfter);
            Assert.Equal(licenseContent, File.ReadAllText(licensePath));
            Assert.Equal(dataContent, File.ReadAllText(dataPath));
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void Invariant_ValidReplacementLicenseCanRecover()
    {
        using var system = new TestLicenseSystem();

        // Lockdown through an expired license.
        system.Manager.LoadLicense(system.Authority.Issue(
            system.License().WithExpiresAt(LicensePayloadFactory.BaseTime.AddSeconds(-1)).Build()));
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.False(system.Enforcement().CanCreateSession(0).IsAllowed);

        // A legitimate, signed replacement license recovers the installation.
        var replacement = system.Authority.Issue(
            system.License().WithSequence(2).WithFeatures("rdp", "web").Build());
        var result = system.Manager.LoadLicense(replacement);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);
        Assert.True(system.Enforcement().CanCreateSession(0).IsAllowed);
        Assert.True(system.Enforcement().CanUseFeature("web").IsAllowed);

        // And an invalid license after recovery returns the system to lockdown.
        system.Manager.LoadLicense(system.Authority.Issue(
            system.License().WithSequence(3).WithExpiresAt(LicensePayloadFactory.BaseTime.AddSeconds(-1)).Build()));
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
    }
}
