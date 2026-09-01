// File: tests/SSP.Tests/Activation/SspLicensePathsTests.cs
//
// Tests for the canonical activation path resolution. The licensing root
// honors an explicit override first, then the SSP_LICENSE_ROOT environment
// seam (same pattern as SSP_CLIENT_ROOT), and finally falls back to the
// canonical {Product Root}/licensing location so tests never touch Program
// Files.

using SSP.Core.IO;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

public class SspLicensePathsTests
{
    [Fact]
    public void Resolve_UsesEnvironmentOverride()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        var dir = CreateTempDir();
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, dir);

            var paths = SspLicensePaths.Resolve();

            Assert.Equal(Path.GetFullPath(dir), paths.LicenseDirectory);
            Assert.Equal(Path.Combine(Path.GetFullPath(dir), SspLicensePaths.LicenseFileName), paths.LicenseFilePath);
            Assert.Equal(Path.Combine(Path.GetFullPath(dir), SspLicensePaths.StateFileName), paths.StateStorePath);
            Assert.Equal(paths.LicenseDirectory, paths.SecurityLogDirectory);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
            TryDelete(dir);
        }
    }

    [Fact]
    public void Resolve_ExplicitRoot_WinsOverEnvironment()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        var envDir = CreateTempDir();
        var explicitDir = CreateTempDir();
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, envDir);

            var paths = SspLicensePaths.Resolve(explicitDir);

            Assert.Equal(Path.GetFullPath(explicitDir), paths.LicenseDirectory);
            Assert.NotEqual(Path.GetFullPath(envDir), paths.LicenseDirectory);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
            TryDelete(envDir);
            TryDelete(explicitDir);
        }
    }

    [Fact]
    public void Resolve_NoOverrides_FallsBackToCanonicalProductRootLicensing()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, null);

            var paths = SspLicensePaths.Resolve();

            Assert.True(Path.IsPathRooted(paths.LicenseDirectory), "Default licensing root must be absolute.");
            Assert.EndsWith(
                Path.Combine(ClientInstallPaths.ProductDirectoryName, SspLicensePaths.LicensingDirectoryName),
                paths.LicenseDirectory,
                StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
        }
    }

    [Fact]
    public void FileNames_MatchStoreAndSinkContracts()
    {
        Assert.Equal("license.json", SspLicensePaths.LicenseFileName);
        Assert.Equal(SspLicenseStateStore.DefaultFileName, SspLicensePaths.StateFileName);
        Assert.Equal("SSP_LICENSE_ROOT", SspLicensePaths.EnvironmentRootOverrideVariable);
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-license-paths-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
