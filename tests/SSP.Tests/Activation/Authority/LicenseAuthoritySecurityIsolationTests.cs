// File: tests/SSP.Tests/Activation/Authority/LicenseAuthoritySecurityIsolationTests.cs
//
// P4 security isolation: the authority tool never ships, never embeds a
// private key, never hands one to SSP.Server, and never becomes a runtime
// substitution path for the compiled-in trust anchor.

using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
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

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            var finding = FindPrivateKeyMaterial(buffer.ToArray());
            Assert.True(finding is null, $"Manifest resource '{name}': {finding}");
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

    // ------------------------------------------------------------------
    // Embedded key-material scan
    //
    // SSP.Server.dll carries the shipped client and service-host images as
    // manifest resources (SSP.Server.Embedded.SSP.Client.bin and
    // SSP.Server.Embedded.SSP.ServiceHost.bin). In a production embed build
    // those are real self-contained single-file PE binaries of tens of MB, so
    // "does this resource mention the words private key" is not a key-material
    // test: the embedded SSP.Core legitimately carries the label literal
    // "PRIVATE KEY" it passes to its own PEM encoder when it EXPORTS a key at
    // runtime, the embedded SSP.Client legitimately carries diagnostics such
    // as "private key present but public key missing", and the .NET payload
    // inside a single-file bundle carries unrelated framework prose (the
    // "... certificate private key check failed ..." string that made the
    // phrase version of this test fail on a production build). Requiring a
    // COMPLETE PEM private key block is what actually expresses the invariant
    // "no authority private key is compiled in", and a compiled image cannot
    // satisfy it by accident.
    // ------------------------------------------------------------------

    /// <summary>
    /// A complete PEM private key block: "-----BEGIN &lt;label&gt; PRIVATE
    /// KEY-----", a base64 body long enough to be a key, and the matching
    /// footer. The body length is bounded so a stray header without a footer
    /// cannot make the match backtrack across an entire embedded image.
    /// </summary>
    private static readonly Regex PrivateKeyPemBlock = new(
        @"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[A-Za-z0-9+/=\s]{64,20000}?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>The PEM header as it appears inside a managed string constant (UTF-16LE).</summary>
    private static readonly byte[] Utf16PemHeader = Encoding.Unicode.GetBytes("-----BEGIN ");

    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Returns null when <paramref name="bytes"/> holds no private key
    /// material, otherwise a description of what was found.
    /// </summary>
    private static string? FindPrivateKeyMaterial(byte[] bytes)
    {
        // Latin-1 maps every byte to the same code point, so this decode is
        // lossless and cannot throw - unlike the UTF-8 read this test used to
        // do, which silently turned every invalid byte of a binary resource
        // into U+FFFD and could split or merge a needle.
        var text = Encoding.Latin1.GetString(bytes);

        var block = PrivateKeyPemBlock.Match(text);
        if (block.Success)
        {
            return $"contains a PEM PRIVATE KEY block (ascii/utf-8 view, offset {block.Index}). "
                + "No Licensing Authority private key may be compiled into, or embedded in, a shipped SSP assembly.";
        }

        // A key compiled in as a C# string constant - exactly the shape the
        // release key ceremony seam writes - sits in the assembly's #US heap
        // as UTF-16LE, where the ASCII view above cannot see it. Probe for the
        // header in that encoding with a cheap byte scan, and only pay for a
        // second view of the resource when the probe actually hits.
        if (bytes.AsSpan().IndexOf(Utf16PemHeader) >= 0)
        {
            var managed = Encoding.Latin1.GetString(bytes.Where(b => b != 0).ToArray());
            var managedBlock = PrivateKeyPemBlock.Match(managed);
            if (managedBlock.Success)
            {
                return $"contains a PEM PRIVATE KEY block (utf-16le view, offset {managedBlock.Index}). "
                    + "No Licensing Authority private key may be compiled into, or embedded in, a shipped SSP assembly.";
            }
        }

        // A resource that is genuinely text - the ceremony's authority PUBLIC
        // key PEM, the client patch-slot and services templates - is held to
        // the strict rule: the phrase itself must not appear anywhere in it.
        // PE images never decode as strict UTF-8 (the DOS/PE headers carry
        // bytes above 0x7F), so the embedded binaries keep the block-level
        // scan above and are not failed for unrelated prose.
        if (IsStrictUtf8(bytes) && text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            return "is a text resource that contains the literal 'PRIVATE KEY'. "
                + "Only public key material may be compiled into a shipped SSP assembly.";
        }

        return null;
    }

    private static bool IsStrictUtf8(byte[] bytes)
    {
        try
        {
            StrictUtf8.GetString(bytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
