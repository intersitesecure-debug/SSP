// File: tests/SSP.Tests/Activation/SspLicensePathsTests.cs
//
// Tests for the canonical activation path resolution. The licensing root
// honors an explicit override first, then the SSP_LICENSE_ROOT environment
// seam, and finally falls back to the canonical {Product Root}/licensing
// location so tests never touch Program Files.
//
// Two seams are deliberately separate concepts and these tests pin that:
//
//   SSP_CLIENT_ROOT  - redirects CLIENT CONNECTION STATE only
//                      (ClientInstallPaths.GetProductRoot/GetConnectionsRoot)
//   SSP_LICENSE_ROOT - redirects LICENSING STATE only (SspLicensePaths)
//
// The licensing root must therefore stay canonical even while
// SSP_CLIENT_ROOT is redirected, which is exactly the case the whole test
// assembly lives in: TestAssemblyInit sets SSP_CLIENT_ROOT process-wide to a
// temporary directory before any test runs (see tests/SSP.Tests/AssemblyInfo.cs),
// so the "NoOverrides" tests below exercise the fallback *with the client
// seam still redirected*. That is intentional - clearing SSP_CLIENT_ROOT here
// would hide a re-coupling of the two seams instead of detecting it.
// Nothing in these tests may touch Program Files, and resolution performs no
// I/O, so asserting the canonical value is side-effect free.

using SSP.Core.IO;
using SSP.Server.Activation;
using SSP.Tests.Helpers;

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

            // The canonical root exactly, not merely "something ending in
            // SSP/licensing": {Program Files}\SSP\licensing. Note that the
            // client seam (SSP_CLIENT_ROOT) is still redirected to a
            // temporary directory for the whole test assembly; the licensing
            // fallback must not follow it.
            Assert.Equal(ExpectedCanonicalLicenseDirectory(), paths.LicenseDirectory);
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

    // ────────────────────────────────────────────────────────────────
    // Regression: the client/test root and the licensing root are
    // separate concepts.
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The two seams are distinct environment variables: redirecting client
    /// connection state must never be a way to redirect licensing state, and
    /// vice versa.
    /// </summary>
    [Fact]
    public void ClientRootSeam_AndLicenseRootSeam_AreDistinctVariables()
    {
        Assert.Equal("SSP_CLIENT_ROOT", ClientInstallPaths.EnvironmentRootOverrideVariable);
        Assert.Equal("SSP_LICENSE_ROOT", SspLicensePaths.EnvironmentRootOverrideVariable);
        Assert.NotEqual(
            ClientInstallPaths.EnvironmentRootOverrideVariable,
            SspLicensePaths.EnvironmentRootOverrideVariable);
    }

    /// <summary>
    /// The core regression for the integration bug: moving the client root
    /// (which relocates connections state) must leave the licensing root
    /// exactly where it was. Before the fix, SspLicensePaths.Resolve() derived
    /// the licensing root from ClientInstallPaths.GetProductRoot(), which
    /// honors SSP_CLIENT_ROOT, so the licensing directory silently followed
    /// the client redirect and the license artifact / DPAPI anti-rollback
    /// floor would be re-read from an unrelated (usually empty) directory.
    /// </summary>
    [Fact]
    public void Resolve_ClientRootRedirect_DoesNotRelocateLicensingRoot()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, null);

            var outside = SspLicensePaths.Resolve();

            using var scope = new ClientConnectionRootScope();

            // The scope really did move the client root, and it really moved
            // the connections root that rides on it.
            Assert.Equal(scope.ProductRoot, ClientInstallPaths.GetProductRoot());
            Assert.Equal(
                Path.Combine(scope.ProductRoot, ClientInstallPaths.ConnectionsDirectoryName),
                ClientInstallPaths.GetConnectionsRoot());

            var inside = SspLicensePaths.Resolve();

            // ...but the licensing root is untouched by it.
            Assert.Equal(outside.LicenseDirectory, inside.LicenseDirectory);
            Assert.Equal(ExpectedCanonicalLicenseDirectory(), inside.LicenseDirectory);
            Assert.DoesNotContain(scope.ProductRoot, inside.LicenseDirectory);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
        }
    }

    /// <summary>
    /// Even with the client root redirected, the licensing root must still be
    /// the canonical product-root location (the same SSP directory name,
    /// under Program Files, not under the client redirect).
    /// </summary>
    [Fact]
    public void Resolve_ClientRootRedirect_KeepsCanonicalProductRootSuffix()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, null);

            using var scope = new ClientConnectionRootScope();
            var paths = SspLicensePaths.Resolve();

            Assert.EndsWith(
                Path.Combine(ClientInstallPaths.ProductDirectoryName, SspLicensePaths.LicensingDirectoryName),
                paths.LicenseDirectory,
                StringComparison.Ordinal);
            Assert.False(
                paths.LicenseDirectory.StartsWith(Path.GetFullPath(scope.ProductRoot), StringComparison.Ordinal),
                "Licensing state must not live under the redirected client root.");
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
        }
    }

    /// <summary>
    /// Precedence step 2 over step 3: SSP_LICENSE_ROOT wins when only the
    /// client root is also set. Precedence step 1 over both: the explicit
    /// argument wins over SSP_LICENSE_ROOT, and SSP_LICENSE_ROOT wins over
    /// the client root.
    /// </summary>
    [Fact]
    public void Resolve_LicenseRootWinsOverClientRoot_ExplicitArgWinsOverBoth()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        var licenseDir = CreateTempDir();
        var explicitDir = CreateTempDir();
        try
        {
            using var scope = new ClientConnectionRootScope();
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, licenseDir);

            // step 2 beats step 3 (canonical fallback / client redirect)
            var fromEnvironment = SspLicensePaths.Resolve();
            Assert.Equal(Path.GetFullPath(licenseDir), fromEnvironment.LicenseDirectory);
            Assert.DoesNotContain(scope.ProductRoot, fromEnvironment.LicenseDirectory);

            // step 1 beats step 2
            var fromArgument = SspLicensePaths.Resolve(explicitDir);
            Assert.Equal(Path.GetFullPath(explicitDir), fromArgument.LicenseDirectory);
            Assert.NotEqual(fromEnvironment.LicenseDirectory, fromArgument.LicenseDirectory);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
            TryDelete(licenseDir);
            TryDelete(explicitDir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Blank override handling: "set but empty" means "not set"
    // (same convention as ClientInstallPaths and AuthenticationCodeFile),
    // so a blank value falls through to the canonical root rather than
    // resolving to the current directory.
    // ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData(" \t\n ")]
    public void Resolve_BlankLicenseRootEnvironment_FallsBackToCanonical(string blank)
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, blank);

            var paths = SspLicensePaths.Resolve();

            Assert.Equal(ExpectedCanonicalLicenseDirectory(), paths.LicenseDirectory);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void Resolve_BlankLicenseRootArgument_FallsBackToCanonical(string blank)
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, null);

            // A blank explicit argument must not win: it is ignored and the
            // canonical fallback applies.
            var paths = SspLicensePaths.Resolve(blank);

            Assert.Equal(ExpectedCanonicalLicenseDirectory(), paths.LicenseDirectory);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Path normalization: every spelling of the same directory must
    // resolve to one canonical absolute form, so the license file, the
    // DPAPI state file and the security log never split across two
    // "different" directories that are actually the same one.
    // ────────────────────────────────────────────────────────────────

    [Fact]
    public void Resolve_TrailingSeparatorsAndDotSegments_AreNormalized()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        var dir = CreateTempDir();
        try
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, dir);
            var expected = SspLicensePaths.Resolve().LicenseDirectory;

            Assert.Equal(Path.GetFullPath(dir), expected);
            Assert.False(
                expected.EndsWith(Path.DirectorySeparatorChar) ||
                expected.EndsWith(Path.AltDirectorySeparatorChar),
                "A trailing directory separator must be normalized away.");

            // Redundant separators and a trailing one must not change the result.
            var sep = Path.DirectorySeparatorChar;
            string[] spellings =
            {
                dir + sep,
                dir + sep + sep,
                Path.Combine(dir, "."),
                Path.Combine(dir, "nested", ".."),
            };

            foreach (var spelling in spellings)
            {
                Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, spelling);
                Assert.Equal(expected, SspLicensePaths.Resolve().LicenseDirectory);
            }

            // The derived file paths stay inside the normalized directory.
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, dir + sep + sep);
            var paths = SspLicensePaths.Resolve();
            Assert.Equal(
                Path.Combine(expected, SspLicensePaths.LicenseFileName),
                paths.LicenseFilePath);
            Assert.Equal(
                Path.Combine(expected, SspLicensePaths.StateFileName),
                paths.StateStorePath);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
            TryDelete(dir);
        }
    }

    [Fact]
    public void Resolve_SameDirectoryDifferentSpelling_ProducesEqualPaths()
    {
        var original = Environment.GetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable);
        var dir = CreateTempDir();
        try
        {
            var sep = Path.DirectorySeparatorChar;

            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, dir);
            var first = SspLicensePaths.Resolve();

            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, dir + sep);
            var second = SspLicensePaths.Resolve();

            // SspLicensePaths is a record over the normalized directory, so two
            // spellings of one directory are one value: no aliasing between the
            // license provider and the state store.
            Assert.Equal(first, second);
            Assert.Equal(first.LicenseDirectory, second.LicenseDirectory);
        }
        finally
        {
            Environment.SetEnvironmentVariable(SspLicensePaths.EnvironmentRootOverrideVariable, original);
            TryDelete(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The canonical licensing directory spelled the way the product spells
    /// it: {Program Files}\SSP\licensing. Deliberately independent of
    /// SspLicensePaths (it must not read SSP_CLIENT_ROOT), so it cannot agree
    /// with a broken implementation by construction.
    /// </summary>
    private static string ExpectedCanonicalLicenseDirectory() =>
        Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ClientInstallPaths.ProductDirectoryName,
            SspLicensePaths.LicensingDirectoryName));

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
