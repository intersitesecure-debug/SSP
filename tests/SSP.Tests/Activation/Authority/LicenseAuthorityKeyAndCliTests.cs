// File: tests/SSP.Tests/Activation/Authority/LicenseAuthorityKeyAndCliTests.cs
//
// P4: keygen, export-public, fingerprint, malformed keys, wrong key types /
// sizes, and CLI argument validation. Keys are ephemeral.

using System.Security.Cryptography;
using SSP.LicenseAuthority;
using SSP.Server.Activation;

namespace SSP.Tests.Activation.Authority;

public sealed class LicenseAuthorityKeyAndCliTests
{
    [Fact]
    public async Task NoArguments_PrintsHelp_AndExitsNonZero()
    {
        using var ws = new AuthorityWorkspace();
        var result = await ws.Run();
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("keygen", result.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BEGIN", result.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", result.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownCommandAndUnknownOption_FailClosed()
    {
        using var ws = new AuthorityWorkspace();
        var unknownCommand = await ws.Run("not-a-command");
        Assert.NotEqual(0, unknownCommand.Exit);
        Assert.Contains("unknown command", unknownCommand.Stderr, StringComparison.OrdinalIgnoreCase);

        var unknownOption = await ws.Run("fingerprint", "--not-a-real-flag", "x");
        Assert.NotEqual(0, unknownOption.Exit);
        Assert.Contains("Unknown option", unknownOption.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Keygen_Writes3072PrivateKey_AndPublicKeyOnlyWhenRequested()
    {
        using var ws = new AuthorityWorkspace();
        var privatePath = ws.PathTo("authority-private.pem");
        var publicPath = ws.PathTo("authority-public.pem");

        var withoutPublic = await ws.Run("keygen", "--private-key", privatePath);
        Assert.Equal(0, withoutPublic.Exit);
        Assert.True(File.Exists(privatePath));
        Assert.False(File.Exists(publicPath));
        Assert.Contains("BEGIN PRIVATE KEY", File.ReadAllText(privatePath), StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", withoutPublic.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN PUBLIC KEY", withoutPublic.Stdout, StringComparison.Ordinal);
        Assert.Contains("SPKI SHA-256", withoutPublic.Stdout, StringComparison.Ordinal);
        Assert.Contains("NEVER", withoutPublic.Stderr, StringComparison.OrdinalIgnoreCase);

        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(privatePath);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }

        var withPublic = await ws.Run(
            "keygen", "--private-key", privatePath, "--public-key", publicPath, "--force");
        Assert.Equal(0, withPublic.Exit);
        Assert.True(File.Exists(publicPath));
        var publicPem = File.ReadAllText(publicPath);
        Assert.Contains("BEGIN PUBLIC KEY", publicPem, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", publicPem, StringComparison.OrdinalIgnoreCase);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicPem);
        Assert.Equal(AuthorityKeyMaterial.ProductionKeySizeBits, rsa.KeySize);

        var fingerprint = SspTrustAnchor.ComputeFingerprint(rsa.ExportSubjectPublicKeyInfo());
        Assert.Contains(fingerprint, withPublic.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Keygen_RefusesToOverwriteWithoutForce_AndLeavesOriginalIntact()
    {
        using var ws = new AuthorityWorkspace();
        var privatePath = ws.PathTo("authority-private.pem");
        File.WriteAllText(privatePath, "original-not-a-key");

        var result = await ws.Run("keygen", "--private-key", privatePath);
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("overwrite", result.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("original-not-a-key", File.ReadAllText(privatePath));
    }

    [Fact]
    public async Task ExportPublic_WritesOnlyThePublicHalf()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var privatePath = ws.PathTo("priv.pem");
        var publicPath = ws.PathTo("pub.pem");
        File.WriteAllText(privatePath, pair.PrivatePem);

        var result = await ws.Run("export-public", "--private-key", privatePath, "--output", publicPath);
        Assert.Equal(0, result.Exit);
        Assert.Equal(pair.Fingerprint, ExtractFingerprint(result.Stdout));
        var exported = File.ReadAllText(publicPath);
        Assert.Contains("BEGIN PUBLIC KEY", exported, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", exported, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", result.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Fingerprint_MatchesSspTrustAnchor_AndVerifiesExpect()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var publicPath = ws.PathTo("pub.pem");
        File.WriteAllText(publicPath, pair.PublicPem);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(pair.PublicPem);
        var serverFingerprint = SspTrustAnchor.ComputeFingerprint(rsa.ExportSubjectPublicKeyInfo());
        Assert.Equal(pair.Fingerprint, serverFingerprint);

        var shown = await ws.Run("fingerprint", "--public-key", publicPath);
        Assert.Equal(0, shown.Exit);
        Assert.Contains(serverFingerprint, shown.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", shown.Stdout, StringComparison.Ordinal);

        var match = await ws.Run(
            "fingerprint", "--public-key", publicPath, "--expect", "sha256:" + serverFingerprint.ToUpperInvariant());
        Assert.Equal(0, match.Exit);
        Assert.Contains("Match", match.Stdout, StringComparison.OrdinalIgnoreCase);

        var colonised = string.Join(':', Enumerable.Range(0, serverFingerprint.Length / 2)
            .Select(i => serverFingerprint.Substring(i * 2, 2)));
        var colonMatch = await ws.Run("fingerprint", "--public-key", publicPath, "--expect", colonised);
        Assert.Equal(0, colonMatch.Exit);

        var other = EphemeralAuthorityKeys.CreateForeign();
        var mismatch = await ws.Run("fingerprint", "--public-key", publicPath, "--expect", other.Fingerprint);
        Assert.NotEqual(0, mismatch.Exit);
        Assert.Contains("does not match", mismatch.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Fingerprint_FromPrivateKey_MatchesPublicHalf()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var privatePath = ws.PathTo("priv.pem");
        File.WriteAllText(privatePath, pair.PrivatePem);

        var result = await ws.Run("fingerprint", "--private-key", privatePath);
        Assert.Equal(0, result.Exit);
        Assert.Contains(pair.Fingerprint, result.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", result.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Fingerprint_RequiresExactlyOneKeyOption()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var pub = ws.PathTo("pub.pem");
        var priv = ws.PathTo("priv.pem");
        File.WriteAllText(pub, pair.PublicPem);
        File.WriteAllText(priv, pair.PrivatePem);

        var neither = await ws.Run("fingerprint");
        Assert.NotEqual(0, neither.Exit);

        var both = await ws.Run("fingerprint", "--public-key", pub, "--private-key", priv);
        Assert.NotEqual(0, both.Exit);
        Assert.Contains("exactly one", both.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("garbage")]
    [InlineData("truncated")]
    [InlineData("ec-public")]
    [InlineData("ec-private")]
    [InlineData("rsa-1024-public")]
    [InlineData("rsa-1024-private")]
    [InlineData("certificate")]
    public async Task MalformedAndWrongTypeKeys_AreRejected(string kind)
    {
        using var ws = new AuthorityWorkspace();
        var path = ws.PathTo("key.pem");
        File.WriteAllText(path, MakeBadKey(kind));

        var asPublic = await ws.Run("fingerprint", "--public-key", path);
        Assert.NotEqual(0, asPublic.Exit);
        Assert.False(string.IsNullOrWhiteSpace(asPublic.Stderr));
        Assert.DoesNotContain("BEGIN", asPublic.Stderr, StringComparison.Ordinal);

        var asPrivate = await ws.Run("fingerprint", "--private-key", path);
        Assert.NotEqual(0, asPrivate.Exit);
    }

    [Fact]
    public async Task PublicKeyCommand_RejectsPrivateKeyMaterialExplicitly()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var path = ws.PathTo("priv.pem");
        File.WriteAllText(path, pair.PrivatePem);

        var result = await ws.Run("fingerprint", "--public-key", path);
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("PRIVATE KEY", result.Stderr, StringComparison.Ordinal);
        Assert.Contains("never", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PrivateKeyCommand_RejectsPublicOnlyPem()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var path = ws.PathTo("pub.pem");
        File.WriteAllText(path, pair.PublicPem);

        var result = await ws.Run(
            "export-public", "--private-key", path, "--output", ws.PathTo("out.pem"));
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("private key", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Issue_RefusesMissingRequiredFields()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        File.WriteAllText(priv, pair.PrivatePem);

        var missingCustomer = await ws.Run(
            "issue",
            "--private-key", priv,
            "--output", ws.PathTo("lic.json"),
            "--edition", "Enterprise",
            "--expires-at", "2031-01-01T00:00:00Z",
            "--feature", "rdp");
        Assert.NotEqual(0, missingCustomer.Exit);
        Assert.Contains("customer", missingCustomer.Stderr, StringComparison.OrdinalIgnoreCase);

        var missingExpiry = await ws.Run(
            "issue",
            "--private-key", priv,
            "--output", ws.PathTo("lic.json"),
            "--customer-id", Guid.NewGuid().ToString("D"),
            "--customer-name", "X",
            "--edition", "Enterprise",
            "--feature", "rdp");
        Assert.NotEqual(0, missingExpiry.Exit);
        Assert.Contains("expires", missingExpiry.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Issue_RefusesInvertedTimeWindow_AndUnknownStatus_AndNegativeLimit()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        File.WriteAllText(priv, pair.PrivatePem);

        var inverted = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, ws.PathTo("a.json"), issuedAt: "2030-06-01T00:00:00Z", notBefore: "2030-01-01T00:00:00Z"));
        Assert.NotEqual(0, inverted.Exit);
        Assert.Contains("issuedAt", inverted.Stderr, StringComparison.OrdinalIgnoreCase);

        var status = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, ws.PathTo("b.json"), status: "paused"));
        Assert.NotEqual(0, status.Exit);
        Assert.Contains("status", status.Stderr, StringComparison.OrdinalIgnoreCase);

        var limit = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, ws.PathTo("c.json"), limits: new[] { "max_services=-1" }));
        Assert.NotEqual(0, limit.Exit);
        Assert.Contains("limit", limit.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Issue_RefusesUndersizedSigningKey()
    {
        using var ws = new AuthorityWorkspace();
        using var weak = RSA.Create(1024);
        var priv = ws.PathTo("weak.pem");
        File.WriteAllText(priv, weak.ExportPkcs8PrivateKeyPem());

        var result = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(priv, ws.PathTo("lic.json")));
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("1024", result.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingKeyFile_FailsClosed()
    {
        using var ws = new AuthorityWorkspace();
        var result = await ws.Run("fingerprint", "--public-key", ws.PathTo("no-such.pem"));
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("not found", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EnvironmentVariable_CannotSupplyAPrivateKey()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        Environment.SetEnvironmentVariable("SSP_AUTHORITY_PRIVATE_KEY", pair.PrivatePem);
        Environment.SetEnvironmentVariable("SSP_AUTHORITY_PRIVATE_KEY_FILE", ws.PathTo("priv.pem"));
        try
        {
            File.WriteAllText(ws.PathTo("priv.pem"), pair.PrivatePem);
            var result = await ws.Run("fingerprint");
            Assert.NotEqual(0, result.Exit);
            Assert.DoesNotContain(pair.Fingerprint, result.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SSP_AUTHORITY_PRIVATE_KEY", null);
            Environment.SetEnvironmentVariable("SSP_AUTHORITY_PRIVATE_KEY_FILE", null);
        }
    }

    private static string ExtractFingerprint(string stdout)
    {
        const string marker = "SPKI SHA-256";
        var line = stdout.Split('\n').First(l => l.Contains(marker, StringComparison.Ordinal));
        var colon = line.LastIndexOf(':');
        return line[(colon + 1)..].Trim();
    }

    private static string MakeBadKey(string kind)
    {
        switch (kind)
        {
            case "empty":
                return "   \n";
            case "garbage":
                return "this is not a PEM block at all";
            case "truncated":
            {
                using var rsa = RSA.Create(2048);
                var pem = rsa.ExportSubjectPublicKeyInfoPem().Replace("\n", string.Empty, StringComparison.Ordinal);
                return pem[..(pem.Length / 2)];
            }
            case "ec-public":
            {
                using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                return ec.ExportSubjectPublicKeyInfoPem();
            }
            case "ec-private":
            {
                using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                return ec.ExportPkcs8PrivateKeyPem();
            }
            case "rsa-1024-public":
            {
                using var rsa = RSA.Create(1024);
                return rsa.ExportSubjectPublicKeyInfoPem();
            }
            case "rsa-1024-private":
            {
                using var rsa = RSA.Create(1024);
                return rsa.ExportPkcs8PrivateKeyPem();
            }
            case "certificate":
            {
                using var rsa = RSA.Create(2048);
                return PemEncoding.WriteString("CERTIFICATE", rsa.ExportSubjectPublicKeyInfo());
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown bad-key kind.");
        }
    }
}
