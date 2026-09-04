// File: tests/SSP.Tests/Activation/SspTrustAnchorProvisioningTests.cs
//
// THE trust-anchor release-blocker suite.
//
// The Licensing Authority public key is the single root of trust for SSP
// activation. It is provisioned into SSP.Server at BUILD time by the release
// key ceremony (see src/SSP.Server/Activation/SspTrustAnchor.targets and
// TRUST_ANCHOR_KEY_CEREMONY.md); the authority PRIVATE key never exists in this
// repository, in any test, or in any shipped binary.
//
// These tests pin the four properties that make that mechanism production-ready:
//
//   1. missing trust anchor            -> every production entry point fails closed
//   2. valid configured trust anchor   -> licenses from that authority validate
//   3. invalid/malformed trust anchor  -> fails closed (never a partial anchor)
//   4. the ephemeral TEST signing keys are isolated from the production trust
//      configuration: they are never the compiled-in anchor, they cannot become
//      it at runtime, and nothing in the environment or on disk can install one.
//
// Every test is written to hold for BOTH shapes of the product: the repository's
// default fail-closed build (no anchor) and a release build produced by the key
// ceremony (anchor present). That is deliberate - the suite must not have to be
// rewritten at the ceremony, which is exactly when nobody should be editing
// security tests.

using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Activation;
using SSP.Core.Models;
using SSP.Server;
using SSP.Server.Activation;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation;

public class SspTrustAnchorProvisioningTests
{
    private static readonly DateTimeOffset FixedNow = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ------------------------------------------------------------------
    // 1. Missing trust anchor => fail closed
    // ------------------------------------------------------------------

    /// <summary>
    /// The default (unprovisioned) build must refuse everything: no anchor, no
    /// composition, no gate, and a non-zero exit from the release verification
    /// verb. A build produced by the key ceremony must instead report a usable
    /// anchor - there is no third outcome, and in particular no "run anyway".
    /// </summary>
    [Fact]
    public void MissingTrustAnchor_FailsClosedAcrossEveryProductionEntryPoint()
    {
        var info = SspTrustAnchor.Inspect();

        if (!SspTrustAnchor.IsCompiledIn)
        {
            Assert.False(info.IsProvisioned);
            Assert.False(info.IsUsable);
            Assert.Equal(SspTrustAnchor.NotProvisionedSource, info.Source);
            Assert.Equal(0, info.KeySizeBits);
            Assert.Null(info.PublicKeySha256);
            Assert.False(string.IsNullOrWhiteSpace(info.Error));

            // The anchor itself refuses to exist.
            var anchorEx = Assert.Throws<InvalidOperationException>(() => SspTrustAnchor.Create());
            Assert.Contains("trust anchor", anchorEx.Message, StringComparison.OrdinalIgnoreCase);

            // The composition root refuses to compose.
            var composeEx = Assert.Throws<InvalidOperationException>(() => SspActivationService.Create());
            Assert.Contains("trust anchor", composeEx.Message, StringComparison.OrdinalIgnoreCase);

            // The production gate refuses to exist, with the stable reason code.
            var config = new ServiceConfig { ApplicationName = "RDP", WindowsServiceName = "SSP Test RDP" };
            var gateEx = Assert.Throws<SspActivationException>(() => SspRuntimeLicense.CreateForService(config));
            Assert.Equal(SspActivationException.TrustAnchorMissingReason, gateEx.ReasonCode);

            // Provisioning refuses, loudly, and never returns a gate.
            Assert.Null(SspRuntimeLicense.TryCreateForProvisioning("RDP"));

            // The release verification verb reports failure (non-zero exit).
            Assert.False(Program.RunTrustAnchorInfo());
            return;
        }

        // Ceremony build: the anchor must be present, usable and describable.
        Assert.True(info.IsProvisioned);
        Assert.True(info.IsUsable, info.Error);
        Assert.True(info.KeySizeBits >= SspTrustAnchor.MinimumKeySizeBits);
        Assert.False(string.IsNullOrWhiteSpace(info.PublicKeySha256));
        Assert.True(Program.RunTrustAnchorInfo());

        using var anchor = SspTrustAnchor.Create();
        Assert.Equal(info.PublicKeySha256, SspTrustAnchor.ComputeFingerprint(anchor));
    }

    /// <summary>
    /// The report is operator-facing: it must diagnose the build without ever
    /// printing key material.
    /// </summary>
    [Fact]
    public void TrustAnchorReport_IsSecretFree()
    {
        var text = SspTrustAnchor.Inspect().Describe();

        Assert.Contains("SSP Licensing Authority trust anchor", text, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", text, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", text, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------
    // 2. Valid configured trust anchor => license validation works
    // ------------------------------------------------------------------

    /// <summary>
    /// The ceremony rules applied to a well-formed authority public key must
    /// produce a working root of trust: the same validation
    /// <see cref="SspTrustAnchor.Create"/> applies to the release-provisioned key,
    /// here applied to an ephemeral key the test owns. A license signed by the
    /// matching private key validates end-to-end through the production
    /// composition graph.
    /// </summary>
    [Fact]
    public void ValidConfiguredTrustAnchor_ValidatesLicensesFromThatAuthority()
    {
        using var authority = RSA.Create(SspTrustAnchor.RecommendedKeySizeBits);
        var pem = authority.ExportSubjectPublicKeyInfoPem();
        var fingerprint = SspTrustAnchor.ComputeFingerprint(authority.ExportSubjectPublicKeyInfo());

        // Fingerprint pin supplied exactly as a key-ceremony record would.
        using var anchor = SspTrustAnchor.ImportAuthorityPublicKey(
            pem, "unit-test ceremony file", expectedSha256: fingerprint);

        Assert.Equal(SspTrustAnchor.RecommendedKeySizeBits, anchor.KeySizeBits);
        Assert.Equal(fingerprint, SspTrustAnchor.ComputeFingerprint(anchor));

        var dir = CreateTempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            WriteLicense(paths, CreatePayload(), authority);

            using var service = SspActivationService.Compose(
                paths,
                anchor,
                new StaticInstallationIdentityProvider("INSTALLATION-A"),
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            var result = service.Load();

            Assert.True(result.IsValid, $"{result.State} / {result.ReasonCode}: {result.Detail}");
            Assert.Equal(LicenseState.Valid, service.CurrentState);
            Assert.Equal(LicenseReasons.Ok, result.ReasonCode);

            // The wired runtime reports the anchor it is actually verifying
            // against (fingerprint only - never the key).
            var status = service.DescribeStatus();
            Assert.Contains($"sha256:{fingerprint}", status, StringComparison.Ordinal);
            Assert.DoesNotContain("BEGIN", status, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>
    /// A configured anchor authorizes exactly one authority: an artifact signed
    /// by any other key is refused even though it is a perfectly well-formed,
    /// unexpired, in-product license.
    /// </summary>
    [Fact]
    public void ConfiguredTrustAnchor_RefusesLicensesFromAnotherAuthority()
    {
        using var authority = RSA.Create(2048);
        using var otherAuthority = RSA.Create(2048);
        using var anchor = SspTrustAnchor.ImportAuthorityPublicKey(
            authority.ExportSubjectPublicKeyInfoPem(), "unit-test ceremony file");

        var dir = CreateTempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            WriteLicense(paths, CreatePayload(), otherAuthority);

            using var service = SspActivationService.Compose(
                paths,
                anchor,
                new StaticInstallationIdentityProvider("INSTALLATION-A"),
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            var result = service.Load();

            Assert.False(result.IsValid);
            Assert.NotEqual(LicenseState.Valid, service.CurrentState);
            Assert.Equal(LicenseReasons.InvalidSignature, result.ReasonCode);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ------------------------------------------------------------------
    // 3. Invalid / malformed trust anchor => fail closed
    // ------------------------------------------------------------------

    /// <summary>
    /// Every way a key ceremony can go wrong must produce an exception and no
    /// anchor. A partially trusted anchor - or an anchor built from something
    /// that merely looks like a key - would silently become the root of trust of
    /// a shipping build, so each case is asserted explicitly rather than left to
    /// the vendored library's contract.
    /// </summary>
    [Fact]
    public void MalformedTrustAnchorMaterial_AlwaysFailsClosed()
    {
        using var weakKey = RSA.Create(1024);
        using var privateKey = RSA.Create(2048);
        using var goodKey = RSA.Create(2048);
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var spki = goodKey.ExportSubjectPublicKeyInfo();
        var withTrailingData = new byte[spki.Length + 1];
        spki.CopyTo(withTrailingData, 0);
        withTrailingData[^1] = 0x2A;

        var truncated = goodKey.ExportSubjectPublicKeyInfoPem()
            .Replace("\n", string.Empty, StringComparison.Ordinal);
        truncated = truncated[..(truncated.Length / 2)];

        AssertFailsClosed(null, "null input");
        AssertFailsClosed(string.Empty, "empty input");
        AssertFailsClosed("   \r\n  ", "whitespace input");
        AssertFailsClosed("this is not a PEM block at all", "garbage input");
        AssertFailsClosed(privateKey.ExportPkcs8PrivateKeyPem(), "PRIVATE KEY material");
        AssertFailsClosed(privateKey.ExportRSAPrivateKeyPem(), "RSA PRIVATE KEY material");
        AssertFailsClosed(
            PemEncoding.WriteString("CERTIFICATE", spki), "wrong PEM label");
        AssertFailsClosed(truncated, "truncated PEM");
        AssertFailsClosed(
            PemEncoding.WriteString("PUBLIC KEY", withTrailingData), "trailing DER data");
        AssertFailsClosed(
            weakKey.ExportSubjectPublicKeyInfoPem(), $"{weakKey.KeySize}-bit key");
        AssertFailsClosed(
            ecKey.ExportSubjectPublicKeyInfoPem(), "non-RSA key");

        static void AssertFailsClosed(string? pem, string because)
        {
            var ex = Assert.Throws<InvalidOperationException>(
                () => SspTrustAnchor.ImportAuthorityPublicKey(pem, "unit-test ceremony file"));

            Assert.Contains("unit-test ceremony file", ex.Message, StringComparison.Ordinal);
            Assert.False(string.IsNullOrWhiteSpace(ex.Message), because);
        }
    }

    /// <summary>
    /// A private key handed to the ceremony by mistake is named as such, not
    /// reported as a generic parse error: the authority private key must never
    /// travel with a relying-party binary and the diagnosis has to say so.
    /// </summary>
    [Fact]
    public void PrivateKeyMaterial_IsRejectedExplicitly()
    {
        using var privateKey = RSA.Create(2048);

        var ex = Assert.Throws<InvalidOperationException>(
            () => SspTrustAnchor.ImportAuthorityPublicKey(
                privateKey.ExportPkcs8PrivateKeyPem(), "ceremony export"));

        Assert.Contains("PRIVATE KEY", ex.Message, StringComparison.Ordinal);
        Assert.Contains("never", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The ceremony records the fingerprint of the key it produced; the build
    /// pins it; the runtime enforces it. A build that embedded the wrong key
    /// (substitution, stale file, mixed-up ceremony media) must fail closed
    /// instead of trusting whatever it was handed.
    /// </summary>
    [Fact]
    public void FingerprintPin_IsEnforced_AndToleratesRecordedFormats()
    {
        using var authority = RSA.Create(2048);
        using var impostor = RSA.Create(2048);

        var pem = authority.ExportSubjectPublicKeyInfoPem();
        var fingerprint = SspTrustAnchor.ComputeFingerprint(authority.ExportSubjectPublicKeyInfo());
        var impostorFingerprint = SspTrustAnchor.ComputeFingerprint(impostor.ExportSubjectPublicKeyInfo());

        Assert.NotEqual(fingerprint, impostorFingerprint);

        var mismatch = Assert.Throws<InvalidOperationException>(
            () => SspTrustAnchor.ImportAuthorityPublicKey(pem, "ceremony", impostorFingerprint));
        Assert.Contains("does not match the fingerprint", mismatch.Message, StringComparison.Ordinal);

        // Formats a ceremony record realistically carries: uppercase, a
        // "sha256:" prefix, colon separators and stray whitespace.
        var colonised = string.Join(':', Enumerable
            .Range(0, fingerprint.Length / 2)
            .Select(i => fingerprint.Substring(i * 2, 2)));

        foreach (var recorded in new[]
                 {
                     fingerprint,
                     fingerprint.ToUpperInvariant(),
                     "sha256:" + fingerprint,
                     "SHA256:" + fingerprint.ToUpperInvariant(),
                     "  " + colonised + "  ",
                 })
        {
            using var anchor = SspTrustAnchor.ImportAuthorityPublicKey(pem, "ceremony", recorded);
            Assert.Equal(fingerprint, SspTrustAnchor.ComputeFingerprint(anchor));
        }
    }

    // ------------------------------------------------------------------
    // 4. Test signing keys stay isolated from the production trust config
    // ------------------------------------------------------------------

    /// <summary>
    /// The ephemeral authority every licensing test issues with must never be,
    /// and must never be able to become, the production root of trust: it is not
    /// the compiled-in anchor, it is not embedded anywhere in the shipped
    /// assembly, and composing a test runtime with it leaves the production
    /// composition path exactly as fail-closed as it was.
    /// </summary>
    [Fact]
    public void TestSigningKeys_AreIsolatedFromTheProductionTrustConfiguration()
    {
        using var env = LicensedTestEnvironment.Create();
        env.Load();
        Assert.Equal(LicenseState.Valid, env.State);

        var testAnchorFingerprint = SspTrustAnchor.ComputeFingerprint(env.Activation.TrustAnchor);
        var production = SspTrustAnchor.Inspect();

        // The test authority is not the production anchor, in either build shape.
        Assert.NotEqual(testAnchorFingerprint, production.PublicKeySha256);

        // Using a test anchor cannot provision one: the compiled-in state is a
        // property of the BUILD, and nothing at runtime can change it.
        Assert.Equal(production.IsProvisioned, SspTrustAnchor.IsCompiledIn);

        if (!SspTrustAnchor.IsCompiledIn)
        {
            // A default build carries no authority key resource at all - the
            // test keys live only in memory, in the test process.
            Assert.DoesNotContain(
                SspTrustAnchor.AuthorityPublicKeyResourceName,
                typeof(SspRuntimeLicense).Assembly.GetManifestResourceNames());
            Assert.Equal(string.Empty, SspTrustAnchor.AuthorityPublicKeyPem);

            // ...and the production composition path is still refused while a
            // fully valid, test-signed license sits on disk.
            Assert.Throws<InvalidOperationException>(() => SspActivationService.Create(env.Paths));
        }
    }

    /// <summary>
    /// There is deliberately NO runtime substitution path for the root of trust.
    /// Environment variables spelled the way an attacker (or a well-meaning
    /// operator) would try are ignored, and so is a key file dropped into the
    /// licensing directory: the anchor comes from the build and nowhere else.
    /// </summary>
    [Fact]
    public void NoEnvironmentVariableOrDroppedFile_CanSupplyTheTrustAnchor()
    {
        using var attacker = RSA.Create(2048);
        var attackerPem = attacker.ExportSubjectPublicKeyInfoPem();

        var variables = new[]
        {
            "SSP_AUTHORITY_PUBLIC_KEY",
            "SSP_AUTHORITY_PUBLIC_KEY_PEM",
            "SSP_TRUST_ANCHOR",
            "SSP_TRUST_ANCHOR_PEM",
            "SSP_LICENSE_PUBLIC_KEY",
            "SspAuthorityPublicKeyPemFile",
        };

        var dir = CreateTempDir();
        try
        {
            var keyFile = Path.Combine(dir, "authority-public.pem");
            File.WriteAllText(keyFile, attackerPem);

            foreach (var variable in variables)
            {
                Environment.SetEnvironmentVariable(variable, attackerPem);
            }

            Environment.SetEnvironmentVariable("SspAuthorityPublicKeyPemFile", keyFile);

            var attackerFingerprint = SspTrustAnchor.ComputeFingerprint(attacker.ExportSubjectPublicKeyInfo());
            var info = SspTrustAnchor.Inspect();

            Assert.NotEqual(attackerFingerprint, info.PublicKeySha256);
            Assert.Equal(SspTrustAnchor.IsCompiledIn, info.IsProvisioned);

            if (!SspTrustAnchor.IsCompiledIn)
            {
                Assert.Equal(string.Empty, SspTrustAnchor.AuthorityPublicKeyPem);
                Assert.Throws<InvalidOperationException>(() => SspTrustAnchor.Create());

                // A key file next to the licensing state is inert as well: the
                // licensing directory holds artifacts and state, never trust.
                var paths = SspLicensePaths.Resolve(dir);
                Assert.Throws<InvalidOperationException>(() => SspActivationService.Create(paths));
            }
        }
        finally
        {
            foreach (var variable in variables)
            {
                Environment.SetEnvironmentVariable(variable, null);
            }

            TryDelete(dir);
        }
    }

    // ------------------------------------------------------------------
    // The ceremony seam itself (it must not be silently removed)
    // ------------------------------------------------------------------

    /// <summary>
    /// The release-time provisioning seam is the only way a production key can
    /// enter a binary, so its existence is part of the security contract: the
    /// targets file must be imported by SSP.Server and must still expose the
    /// three ceremony properties. The same check proves the opposite property -
    /// that no key material file has been committed to the tree.
    /// </summary>
    [Fact]
    public void ReleaseCeremonySeam_IsWiredIntoTheBuild_AndNoKeyMaterialIsCommitted()
    {
        var root = FindRepositoryRoot();
        if (root is null)
        {
            // Not running from a source checkout (packaged test run): the
            // assembly-level assertions in the other tests still apply.
            return;
        }

        var targetsPath = Path.Combine(root, "src", "SSP.Server", "Activation", "SspTrustAnchor.targets");
        Assert.True(File.Exists(targetsPath), $"The release key-ceremony seam is missing: {targetsPath}");

        var targets = File.ReadAllText(targetsPath);
        Assert.Contains("SspAuthorityPublicKeyPemFile", targets, StringComparison.Ordinal);
        Assert.Contains("SspAuthorityPublicKeySha256", targets, StringComparison.Ordinal);
        Assert.Contains("SspRequireTrustAnchor", targets, StringComparison.Ordinal);
        Assert.Contains(SspTrustAnchor.AuthorityPublicKeyResourceName, targets, StringComparison.Ordinal);

        var csproj = File.ReadAllText(Path.Combine(root, "src", "SSP.Server", "SSP.Server.csproj"));
        Assert.Contains("SspTrustAnchor.targets", csproj, StringComparison.Ordinal);

        // No key material of any kind is committed under src/ or tests/: the
        // ceremony hands the build a path to a file that lives outside the tree.
        var keyExtensions = new[] { ".pem", ".key", ".pfx", ".p12", ".crt", ".der" };
        var committedKeyFiles = new[] { "src", "tests" }
            .Select(part => Path.Combine(root, part))
            .Where(Directory.Exists)
            .SelectMany(dir => Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            .Where(file => keyExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                        && !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToArray();

        Assert.Empty(committedKeyFiles);
    }

    private static string? FindRepositoryRoot()
    {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "SSP.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return null;
    }

    // ------------------------------------------------------------------
    // Test support (ephemeral keys only; no key material is ever persisted)
    // ------------------------------------------------------------------

    private static LicensePayload CreatePayload() => new()
    {
        LicenseId = Guid.NewGuid(),
        ProductId = SspLicensing.ProductId,
        ProductName = SspLicensing.ProductName,
        CustomerId = Guid.NewGuid(),
        CustomerName = "Trust Anchor Test Customer",
        Edition = "Enterprise",
        LicenseVersion = "1.0",
        IssuedAt = FixedNow.AddDays(-30),
        NotBefore = FixedNow.AddDays(-1),
        ExpiresAt = FixedNow.AddDays(365),
        InstallationId = "INSTALLATION-A",
        FeatureSet = new LicenseFeatureSet(new[] { "rdp", "ssh", "web", "sql" }),
        Limits = new LicenseLimits(Array.Empty<KeyValuePair<string, long?>>()),
        Status = LicenseStatus.Active,
        SequenceNumber = 1,
    };

    private static void WriteLicense(SspLicensePaths paths, LicensePayload payload, RSA authorityKey)
        => File.WriteAllText(paths.LicenseFilePath, LicenseIssuer.EncodeLicenseArtifact(payload, authorityKey));

    private sealed class FixedClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = FixedNow;
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-trust-anchor-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch
        {
            // Temp cleanup must never fail a test.
        }
    }
}
