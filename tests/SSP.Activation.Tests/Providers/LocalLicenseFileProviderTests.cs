using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Providers;

/// <summary>Local license file provider: transport behavior and fail-closed error handling.</summary>
public class LocalLicenseFileProviderTests
{
    [Fact]
    public void ExistingFile_ReturnsArtifactContent()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = TestPaths.WriteFile(dir, "license.json", "{ \"format\": \"ssp-license\" }");
            var provider = new LocalLicenseFileProvider(path);

            var result = provider.FetchLicense();

            Assert.True(result.HasLicense);
            Assert.Equal("{ \"format\": \"ssp-license\" }", result.ArtifactJson);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void MissingFile_ReturnsNoLicense_WithErrorDetail()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var provider = new LocalLicenseFileProvider(Path.Combine(dir, "does-not-exist.json"));

            var result = provider.FetchLicense();

            Assert.False(result.HasLicense);
            Assert.Null(result.ArtifactJson);
            Assert.NotNull(result.Detail);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void UnreadableLocation_ReturnsNoLicense_AndNeverThrows()
    {
        // Passing a DIRECTORY as the license path must fail closed, not throw.
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var provider = new LocalLicenseFileProvider(dir);

            var result = provider.FetchLicense();

            Assert.False(result.HasLicense);
            Assert.NotNull(result.Detail);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void OversizedFile_ReturnsNoLicense_AndFailsClosed()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "huge-license.json");
            var bytes = new byte[LicenseArtifactCodec.MaxArtifactCharacters + 1];
            File.WriteAllBytes(path, bytes);
            var provider = new LocalLicenseFileProvider(path);

            var result = provider.FetchLicense();

            Assert.False(result.HasLicense);
            Assert.Null(result.ArtifactJson);
            Assert.NotNull(result.Detail);
            Assert.Contains("maximum size", result.Detail, StringComparison.Ordinal);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void EmptyFile_YieldsArtifact_WhichFailsValidationAsMissing()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = TestPaths.WriteFile(dir, "license.json", "");
            using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(path));

            var result = system.Manager.Load();

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.Unknown, result.State);
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void Provider_Integration_ValidLicenseFile_ResultInValidState()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "license.json");
            using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(path));
            File.WriteAllText(path, system.Authority.Issue(system.License().Build()));

            var result = system.Manager.Load();

            Assert.True(result.IsValid);
            Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);
            Assert.True(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void Provider_Integration_LicenseUpdatedOnDisk_IsPickedUpOnNextLoad()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "license.json");
            using var system = new TestLicenseSystem(provider: new LocalLicenseFileProvider(path));

            File.WriteAllText(path, system.Authority.Issue(system.License().WithFeatures("rdp").Build()));
            Assert.True(system.Manager.Load().IsValid);
            Assert.True(system.Enforcement().CanUseFeature("rdp").IsAllowed);

            File.WriteAllText(path, system.Authority.Issue(system.License().WithFeatures("web").WithSequence(2).Build()));
            system.Manager.Load();

            Assert.True(system.Enforcement().CanUseFeature("web").IsAllowed);
            Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }
}
