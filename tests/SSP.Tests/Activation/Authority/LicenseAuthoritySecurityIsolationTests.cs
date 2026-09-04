// File: tests/SSP.Tests/Activation/Authority/LicenseAuthoritySecurityIsolationTests.cs
//
// P4 security isolation: the authority tool never ships, never embeds a
// private key, never hands one to SSP.Server, and never becomes a runtime
// substitution path for the compiled-in trust anchor.

using System.Reflection;
using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Activation;
using SSP.LicenseAuthority;
using SSP.Server.Activation;

namespace SSP.Tests.Activation.Authority;

public sealed class LicenseAuthoritySecurityIsolationTests
{
    [Fact]
    public void AuthorityProduct_MatchesSspLicensing()
    {
        Assert.Equal(SspLicensing.ProductId, AuthorityProduct.ProductId);
        Assert.Equal(SspLicensing.ProductName, AuthorityProduct.ProductName);
        Assert.Equal(SspLicensing.Features.Known, AuthorityProduct.KnownFeatures);
        Assert.Equal(
            new[]
            {
                SspLicensing.Limits.MaxServices,
                SspLicensing.Limits.MaxClients,
                SspLicensing.Limits.MaxSessions,
                SspLicensing.Limits.MaxConcurrentSessions,
                SspLicensing.Limits.MaxConcurrentTunnels,
            },
            AuthorityProduct.KnownLimits);
        Assert.Equal(LicenseLimitNames.MaxServices, SspLicensing.Limits.MaxServices);
        Assert.Equal(LicenseLimitNames.MaxClients, SspLicensing.Limits.MaxClients);
        Assert.Equal(LicenseLimitNames.MaxSessions, SspLicensing.Limits.MaxSessions);
        Assert.Equal(LicenseLimitNames.MaxConcurrentSessions, SspLicensing.Limits.MaxConcurrentSessions);
        Assert.Equal(LicenseLimitNames.MaxConcurrentTunnels, SspLicensing.Limits.MaxConcurrentTunnels);
    }

    [Fact]
    public void AuthorityTool_DependsOnlyOnActivation_AndHasNoPackageReferences()
    {
        var root = AuthorityTestPayload.FindRepositoryRoot();
        if (root is null)
        {
            return;
        }

        var csproj = File.ReadAllText(Path.Combine(root, "tools", "SSP.LicenseAuthority", "SSP.LicenseAuthority.csproj"));
        Assert.DoesNotContain("<PackageReference", csproj, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("System.CommandLine", csproj, StringComparison.Ordinal);
        Assert.DoesNotContain("SSP.Core", csproj, StringComparison.Ordinal);
        Assert.DoesNotContain("SSP.Server", csproj, StringComparison.Ordinal);
        Assert.Contains("SSP.Activation", csproj, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthorityTool_IsNotReferencedByAnyShippedProject()
    {
        var root = AuthorityTestPayload.FindRepositoryRoot();
        if (root is null)
        {
            return;
        }

        var shipped = new[]
        {
            Path.Combine(root, "src", "SSP.Server", "SSP.Server.csproj"),
            Path.Combine(root, "src", "SSP.ServiceHost", "SSP.ServiceHost.csproj"),
            Path.Combine(root, "src", "SSP.Client", "SSP.Client.csproj"),
            Path.Combine(root, "src", "SSP.ServiceBuilder", "SSP.ServiceBuilder.csproj"),
            Path.Combine(root, "src", "SSP.Core", "SSP.Core.csproj"),
            Path.Combine(root, "src", "SSP.Activation", "SSP.Activation.csproj"),
        };

        foreach (var csproj in shipped)
        {
            Assert.True(File.Exists(csproj), csproj);
            var text = File.ReadAllText(csproj);
            Assert.DoesNotContain("SSP.LicenseAuthority", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void LicenseIssuer_IsNotCalledFromShippedRuntimeProjects()
    {
        var root = AuthorityTestPayload.FindRepositoryRoot();
        if (root is null)
        {
            return;
        }

        var shippedTrees = new[]
        {
            Path.Combine(root, "src", "SSP.Server"),
            Path.Combine(root, "src", "SSP.ServiceHost"),
            Path.Combine(root, "src", "SSP.Client"),
            Path.Combine(root, "src", "SSP.ServiceBuilder"),
            Path.Combine(root, "src", "SSP.Core"),
        };

        var hits = shippedTrees
            .Where(Directory.Exists)
            .SelectMany(dir => Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories))
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(file => File.ReadAllText(file).Contains("LicenseIssuer", StringComparison.Ordinal))
            .ToArray();

        Assert.Empty(hits);
    }

    [Fact]
    public void AuthorityAssembly_EmbedsNoKeyMaterial()
    {
        var assembly = typeof(LicenseAuthorityCli).Assembly;
        Assert.Empty(assembly.GetManifestResourceNames());

        foreach (var attribute in assembly.GetCustomAttributes<AssemblyMetadataAttribute>())
        {
            Assert.DoesNotContain("BEGIN", attribute.Value ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE", attribute.Value ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ShippedAssemblies_StillHaveNoCompiledInAuthorityPrivateKey()
    {
        // The development build remains unanchored; P4 must not have changed that.
        Assert.False(SspTrustAnchor.IsCompiledIn);
        var info = SspTrustAnchor.Inspect();
        Assert.False(info.IsProvisioned);
        Assert.False(info.IsUsable);
        Assert.Equal(SspTrustAnchor.NotProvisionedSource, info.Source);

        var server = typeof(SspTrustAnchor).Assembly;
        foreach (var name in server.GetManifestResourceNames())
        {
            using var stream = server.GetManifestResourceStream(name);
            if (stream is null)
            {
                continue;
            }

            using var reader = new StreamReader(stream);
            var body = reader.ReadToEnd();
            Assert.DoesNotContain("PRIVATE KEY", body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void GitIgnore_ExcludesAuthorityPrivateKeys()
    {
        var root = AuthorityTestPayload.FindRepositoryRoot();
        if (root is null)
        {
            return;
        }

        var gitignore = File.ReadAllText(Path.Combine(root, ".gitignore"));
        Assert.Contains("authority-private", gitignore, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ssp-authority-private", gitignore, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NoKeyMaterialIsCommittedUnderSrcTestsOrTools()
    {
        var root = AuthorityTestPayload.FindRepositoryRoot();
        if (root is null)
        {
            return;
        }

        var keyExtensions = new[] { ".pem", ".key", ".pfx", ".p12", ".crt", ".der" };
        var committed = new[] { "src", "tests", "tools" }
            .Select(part => Path.Combine(root, part))
            .Where(Directory.Exists)
            .SelectMany(dir => Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            .Where(file => keyExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                        && !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToArray();

        Assert.Empty(committed);
    }

    [Fact]
    public void FingerprintAlgorithm_IsIdenticalToSspTrustAnchor()
    {
        using var rsa = RSA.Create(2048);
        var tool = AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa);
        var server = SspTrustAnchor.ComputeFingerprint(rsa.ExportSubjectPublicKeyInfo());
        Assert.Equal(server, tool);

        var colonised = string.Join(':', Enumerable.Range(0, server.Length / 2).Select(i => server.Substring(i * 2, 2)));
        Assert.Equal(server, AuthorityKeyMaterial.NormalizeFingerprint("SHA256:" + colonised));
        Assert.Equal(server, SspTrustAnchor.NormalizeFingerprint("SHA256:" + colonised));
    }

    [Fact]
    public void UsingTheAuthorityTool_CannotProvisionTheCompiledInTrustAnchor()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportSubjectPublicKeyInfoPem();
        Environment.SetEnvironmentVariable("SSP_AUTHORITY_PUBLIC_KEY", pem);
        try
        {
            Assert.False(SspTrustAnchor.IsCompiledIn);
            Assert.Throws<InvalidOperationException>(() => SspTrustAnchor.Create());
            Assert.NotEqual(
                SspTrustAnchor.ComputeFingerprint(rsa.ExportSubjectPublicKeyInfo()),
                SspTrustAnchor.Inspect().PublicKeySha256);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSP_AUTHORITY_PUBLIC_KEY", null);
        }
    }
}
