using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Security;

/// <summary>
/// Configuration tampering must never manufacture an authorization decision: changing
/// JSON/XML, environment variables, command line, registry or deleting/replacing
/// configuration cannot create a valid license — only a signed artifact can.
/// </summary>
public class ConfigurationBypassTests
{
    [Fact]
    public void EnvironmentVariableClaimingLicense_CannotAuthorize()
    {
        Environment.SetEnvironmentVariable("SSP_LICENSED", "true");
        try
        {
            using var system = new TestLicenseSystem();

            Assert.Equal(LicenseState.Unknown, system.Manager.CurrentState);
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
            Assert.False(system.Enforcement().CanCreateSession(0).IsAllowed);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSP_LICENSED", null);
        }
    }

    [Fact]
    public void ConfigFileClaimingLicense_CannotAuthorize()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var configPath = Path.Combine(dir, "ssp.config.json");
            File.WriteAllText(configPath, "{ \"licensed\": true, \"edition\": \"ultimate\", \"features\": [\"*\"], \"limits\": { \"max_concurrent_sessions\": 999999 } }");

            using var system = new TestLicenseSystem();

            // The licensing library never reads configuration; nothing changed.
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
            Assert.False(system.Manager.Authorize(ProtectedOperation.CheckLimit("max_concurrent_sessions", 0)).IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void ReplacingLicenseFileWithConfiguration_CannotAuthorize()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var licensePath = Path.Combine(dir, "ssp.license.json");
            using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(licensePath));

            // Overwrite the license file with plain configuration JSON claiming a license.
            File.WriteAllText(licensePath, "{ \"licensed\": true }");
            var result = system.Manager.Load();

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void PoisonedStateStore_CannotAuthorize()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var licensePath = Path.Combine(dir, "ssp.license.json");
            var store = new InMemoryLicenseStateStore();

            using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(licensePath), stateStore: store);

            // Legitimately validate a license so the store records state.
            File.WriteAllText(licensePath, system.Authority.Issue(system.License().Build()));
            Assert.True(system.Manager.Load().IsValid);

            // Now replace the license with garbage, but KEEP the poisoned "valid-looking" store.
            File.WriteAllText(licensePath, "tampered garbage");
            store.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = long.MaxValue,
                LastAcceptedLicenseId = system.Manager.CurrentLicense?.LicenseId
            });

            // Simulated restart with the tampered license file: the store cannot rescue it.
            using var fresh = new TestLicenseSystem(provider: new LocalLicenseFileProvider(licensePath));
            fresh.StateStore.Save(store.Load()!);

            var result = fresh.Manager.Load();
            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.Malformed, result.State);
            Assert.False(fresh.Enforcement().CanUseFeature("rdp").IsAllowed);
            Assert.False(fresh.Enforcement().CanCreateSession(0).IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void DeletingConfigurationDirectory_CannotAuthorize()
    {
        var dir = TestPaths.CreateTempDirectory();
        var licensePath = Path.Combine(dir, "ssp.license.json");
        File.WriteAllText(licensePath, "placeholder");

        using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(licensePath));
        TestPaths.DeleteDirectory(dir); // wipe everything

        var result = system.Manager.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Unknown, system.Manager.CurrentState);
        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
    }
}
