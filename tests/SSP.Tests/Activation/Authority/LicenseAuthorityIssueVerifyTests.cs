// File: tests/SSP.Tests/Activation/Authority/LicenseAuthorityIssueVerifyTests.cs
//
// P4: issue / inspect / verify / renew against the existing ssp-license v1
// format and LicenseValidator pipeline. Production authority material is
// never used; every key is ephemeral.

using System.Security.Cryptography;
using System.Text.Json;
using SSP.Activation;
using SSP.Core.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Activation.Authority;

public sealed class LicenseAuthorityIssueVerifyTests
{
    [Fact]
    public async Task Issue_ProducesExistingSspLicenseFormat_ThatValidatorAccepts()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        var pub = ws.PathTo("pub.pem");
        var license = ws.PathTo("license.json");
        File.WriteAllText(priv, pair.PrivatePem);
        File.WriteAllText(pub, pair.PublicPem);

        var customerId = Guid.NewGuid();
        var issued = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, license, customerId: customerId, sequence: 7));
        Assert.Equal(0, issued.Exit);
        Assert.True(File.Exists(license));
        Assert.DoesNotContain("BEGIN", issued.Stdout, StringComparison.Ordinal);

        var json = File.ReadAllText(license);
        Assert.Contains("\"format\": \"ssp-license\"", json, StringComparison.Ordinal);
        Assert.Contains("\"artifactVersion\": 1", json, StringComparison.Ordinal);
        Assert.Contains("\"signatureAlgorithm\": \"RSA-PSS-SHA256\"", json, StringComparison.Ordinal);

        Assert.True(LicenseArtifactCodec.TryDecode(json, out var artifact, out var decodeError), decodeError?.Detail);
        Assert.NotNull(artifact);
        Assert.Equal(SspLicensing.ProductId, artifact!.Payload.ProductId);
        Assert.Equal(SspLicensing.ProductName, artifact.Payload.ProductName);
        Assert.Equal(customerId, artifact.Payload.CustomerId);
        Assert.Equal(7, artifact.Payload.SequenceNumber);
        Assert.Equal(LicenseStatus.Active, artifact.Payload.Status);
        Assert.True(artifact.Payload.FeatureSet.Contains("rdp"));
        Assert.True(artifact.Payload.Limits.TryGetValue("max_services", out var maxServices));
        Assert.Equal(3, maxServices);

        var verified = await ws.Run(
            "verify",
            "--license", license,
            "--public-key", pub,
            "--installation-id", "INSTALLATION-A",
            "--now", "2030-06-01T00:00:00Z",
            "--expect-fingerprint", pair.Fingerprint);
        Assert.Equal(0, verified.Exit);
        Assert.Contains("Valid", verified.Stdout, StringComparison.Ordinal);
        Assert.Contains(pair.Fingerprint, verified.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", verified.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_PrintsPayload_WithoutSignatureBytes()
    {
        using var ws = new AuthorityWorkspace();
        var (license, _, _) = await IssueDefaultAsync(ws);

        var inspect = await ws.Run("inspect", "--license", license);
        Assert.Equal(0, inspect.Exit);
        Assert.Contains("ssp-license", inspect.Stdout, StringComparison.Ordinal);
        Assert.Contains("RSA-PSS-SHA256", inspect.Stdout, StringComparison.Ordinal);
        Assert.Contains("INSTALLATION-A", inspect.Stdout, StringComparison.Ordinal);
        Assert.Contains("NOT verified", inspect.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", inspect.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("\"payload\"", inspect.Stdout, StringComparison.Ordinal);
        Assert.Contains("does not prove the signature", inspect.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Inspect_MalformedArtifact_FailsClosed()
    {
        using var ws = new AuthorityWorkspace();
        var path = ws.PathTo("bad.json");
        File.WriteAllText(path, "{ not json");

        var result = await ws.Run("inspect", "--license", path);
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("decoded", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_WrongPublicKey_IsInvalidSignature()
    {
        using var ws = new AuthorityWorkspace();
        var (license, _, _) = await IssueDefaultAsync(ws);
        var foreign = EphemeralAuthorityKeys.CreateForeign();
        var foreignPub = ws.PathTo("foreign.pem");
        File.WriteAllText(foreignPub, foreign.PublicPem);

        var result = await ws.Run(
            "verify",
            "--license", license,
            "--public-key", foreignPub,
            "--installation-id", "INSTALLATION-A",
            "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("invalid_signature", result.Stdout + result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_TamperedPayload_Fails()
    {
        using var ws = new AuthorityWorkspace();
        var (license, pub, _) = await IssueDefaultAsync(ws);
        var json = File.ReadAllText(license);
        var tampered = json.Contains('A') ? json.Replace("A", "B", StringComparison.Ordinal) : json + " ";
        File.WriteAllText(license, tampered);

        var result = await ws.Run(
            "verify",
            "--license", license,
            "--public-key", pub,
            "--installation-id", "INSTALLATION-A",
            "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, result.Exit);
    }

    [Fact]
    public async Task Verify_ExpiredAndNotYetValidAndRevoked_FailClosed()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        var pub = ws.PathTo("pub.pem");
        File.WriteAllText(priv, pair.PrivatePem);
        File.WriteAllText(pub, pair.PublicPem);

        var expiredPath = ws.PathTo("expired.json");
        var expired = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, expiredPath,
            issuedAt: "2028-01-01T00:00:00Z",
            notBefore: "2028-01-01T00:00:00Z",
            expiresAt: "2029-01-01T00:00:00Z"));
        Assert.Equal(0, expired.Exit);

        var expiredVerify = await ws.Run(
            "verify", "--license", expiredPath, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, expiredVerify.Exit);
        Assert.Contains("expired", expiredVerify.Stdout + expiredVerify.Stderr, StringComparison.OrdinalIgnoreCase);

        var futurePath = ws.PathTo("future.json");
        var future = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, futurePath,
            issuedAt: "2030-01-01T00:00:00Z",
            notBefore: "2035-01-01T00:00:00Z",
            expiresAt: "2036-01-01T00:00:00Z"));
        Assert.Equal(0, future.Exit);

        var futureVerify = await ws.Run(
            "verify", "--license", futurePath, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, futureVerify.Exit);
        Assert.Contains("not_yet_valid", futureVerify.Stdout + futureVerify.Stderr, StringComparison.OrdinalIgnoreCase);

        var revokedPath = ws.PathTo("revoked.json");
        var revoked = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, revokedPath, status: "revoked"));
        Assert.Equal(0, revoked.Exit);

        var revokedVerify = await ws.Run(
            "verify", "--license", revokedPath, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, revokedVerify.Exit);
        Assert.Contains("revoked", revokedVerify.Stdout + revokedVerify.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_WrongProduct_AndWrongInstallation_AndIdentityUnavailable()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        var pub = ws.PathTo("pub.pem");
        File.WriteAllText(priv, pair.PrivatePem);
        File.WriteAllText(pub, pair.PublicPem);

        var wrongProduct = ws.PathTo("wrong-product.json");
        var issued = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, wrongProduct, productId: Guid.NewGuid()));
        Assert.Equal(0, issued.Exit);

        var productVerify = await ws.Run(
            "verify", "--license", wrongProduct, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, productVerify.Exit);
        Assert.Contains("wrong_product", productVerify.Stdout + productVerify.Stderr, StringComparison.OrdinalIgnoreCase);

        var bound = ws.PathTo("bound.json");
        var boundIssue = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(priv, bound));
        Assert.Equal(0, boundIssue.Exit);

        var wrongInstall = await ws.Run(
            "verify", "--license", bound, "--public-key", pub,
            "--installation-id", "OTHER-MACHINE", "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, wrongInstall.Exit);
        Assert.Contains("wrong_installation", wrongInstall.Stdout + wrongInstall.Stderr, StringComparison.OrdinalIgnoreCase);

        var noIdentity = await ws.Run(
            "verify", "--license", bound, "--public-key", pub, "--now", "2030-06-01T00:00:00Z");
        Assert.NotEqual(0, noIdentity.Exit);
        Assert.Contains("installation_identity_unavailable", noIdentity.Stdout + noIdentity.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_SupersededSequence_FailsWhenFloorIsSupplied()
    {
        using var ws = new AuthorityWorkspace();
        var (license, pub, _) = await IssueDefaultAsync(ws, sequence: 1);

        var result = await ws.Run(
            "verify",
            "--license", license,
            "--public-key", pub,
            "--installation-id", "INSTALLATION-A",
            "--now", "2030-06-01T00:00:00Z",
            "--highest-accepted-sequence", "5");
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("superseded", result.Stdout + result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_ExpectFingerprintMismatch_FailsBeforeValidation()
    {
        using var ws = new AuthorityWorkspace();
        var (license, pub, _) = await IssueDefaultAsync(ws);
        var other = EphemeralAuthorityKeys.CreateForeign();

        var result = await ws.Run(
            "verify",
            "--license", license,
            "--public-key", pub,
            "--installation-id", "INSTALLATION-A",
            "--now", "2030-06-01T00:00:00Z",
            "--expect-fingerprint", other.Fingerprint);
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("expect-fingerprint", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Renew_RequiresMatchingSignature_AndIncrementsSequence()
    {
        using var ws = new AuthorityWorkspace();
        var (license, pub, priv) = await IssueDefaultAsync(ws, sequence: 3);
        var renewal = ws.PathTo("renewal.json");

        var renewed = await ws.Run(
            "renew",
            "--private-key", priv,
            "--license", license,
            "--output", renewal,
            "--issued-at", "2030-06-01T00:00:00Z",
            "--not-before", "2030-06-01T00:00:00Z",
            "--expires-at", "2032-01-01T00:00:00Z");
        Assert.Equal(0, renewed.Exit);
        Assert.Contains("sequence 3", renewed.Stdout, StringComparison.OrdinalIgnoreCase);

        var verify = await ws.Run(
            "verify", "--license", renewal, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-07-01T00:00:00Z");
        Assert.Equal(0, verify.Exit);

        Assert.True(LicenseArtifactCodec.TryDecode(File.ReadAllText(renewal), out var artifact, out _));
        Assert.Equal(4, artifact!.Payload.SequenceNumber);
        Assert.NotEqual(
            LicenseArtifactCodec.TryDecode(File.ReadAllText(license), out var original, out _) ? original!.Payload.LicenseId : Guid.Empty,
            artifact.Payload.LicenseId);

        var foreign = EphemeralAuthorityKeys.CreateForeign();
        var foreignPriv = ws.PathTo("foreign-priv.pem");
        File.WriteAllText(foreignPriv, foreign.PrivatePem);
        var refused = await ws.Run(
            "renew",
            "--private-key", foreignPriv,
            "--license", license,
            "--output", ws.PathTo("stolen.json"));
        Assert.NotEqual(0, refused.Exit);
        Assert.Contains("Refusing to renew", refused.Stderr, StringComparison.Ordinal);
        Assert.False(File.Exists(ws.PathTo("stolen.json")));
    }

    [Fact]
    public async Task Renew_CanIssueSignedRevocation_WithHigherSequence()
    {
        using var ws = new AuthorityWorkspace();
        var (license, pub, priv) = await IssueDefaultAsync(ws, sequence: 1);
        var revoked = ws.PathTo("revoked.json");

        var result = await ws.Run(
            "renew",
            "--private-key", priv,
            "--license", license,
            "--output", revoked,
            "--status", "revoked",
            "--issued-at", "2030-06-01T00:00:00Z",
            "--not-before", "2030-06-01T00:00:00Z");
        Assert.Equal(0, result.Exit);

        var verify = await ws.Run(
            "verify", "--license", revoked, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-07-01T00:00:00Z");
        Assert.NotEqual(0, verify.Exit);
        Assert.Contains("revoked", verify.Stdout + verify.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Renew_RefusesNonIncreasingSequence()
    {
        using var ws = new AuthorityWorkspace();
        var (license, _, priv) = await IssueDefaultAsync(ws, sequence: 4);

        var result = await ws.Run(
            "renew",
            "--private-key", priv,
            "--license", license,
            "--output", ws.PathTo("bad.json"),
            "--sequence", "4");
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("greater than", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Issue_FromSpecFile_AndFlagsOverrideSpec()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        var pub = ws.PathTo("pub.pem");
        File.WriteAllText(priv, pair.PrivatePem);
        File.WriteAllText(pub, pair.PublicPem);

        var customerId = Guid.NewGuid();
        var spec = new
        {
            customerId,
            customerName = "Spec Customer",
            edition = "Professional",
            issuedAt = "2029-12-01T00:00:00Z",
            notBefore = "2030-01-01T00:00:00Z",
            expiresAt = "2031-01-01T00:00:00Z",
            installationId = "INSTALLATION-A",
            features = new[] { "rdp" },
            limits = new Dictionary<string, long?> { ["max_services"] = 1, ["max_clients"] = null },
            status = "active",
            sequenceNumber = 2
        };
        var specPath = ws.PathTo("spec.json");
        File.WriteAllText(specPath, JsonSerializer.Serialize(spec));

        var license = ws.PathTo("from-spec.json");
        var issued = await ws.Run(
            "issue",
            "--private-key", priv,
            "--output", license,
            "--spec", specPath,
            "--edition", "Enterprise");
        Assert.Equal(0, issued.Exit);
        Assert.Contains("Enterprise", issued.Stdout, StringComparison.Ordinal);
        Assert.Contains("Spec Customer", issued.Stdout, StringComparison.Ordinal);

        Assert.True(LicenseArtifactCodec.TryDecode(File.ReadAllText(license), out var artifact, out _));
        Assert.Equal("Enterprise", artifact!.Payload.Edition);
        Assert.Equal(customerId, artifact.Payload.CustomerId);
        Assert.True(artifact.Payload.Limits.TryGetValue("max_clients", out var clients));
        Assert.Null(clients);

        var artifactAsSpec = await ws.Run(
            "issue",
            "--private-key", priv,
            "--output", ws.PathTo("nope.json"),
            "--spec", license);
        Assert.NotEqual(0, artifactAsSpec.Exit);
        Assert.Contains("ssp-license", artifactAsSpec.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Issue_UnlimitedLimit_AndFloatingLicense_AreRepresented()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        var pub = ws.PathTo("pub.pem");
        File.WriteAllText(priv, pair.PrivatePem);
        File.WriteAllText(pub, pair.PublicPem);

        var license = ws.PathTo("floating.json");
        var issued = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(
            priv, license,
            installationId: null,
            limits: new[] { "max_services=unlimited" }));
        Assert.Equal(0, issued.Exit);
        Assert.Contains("floating", issued.Stderr, StringComparison.OrdinalIgnoreCase);

        Assert.True(LicenseArtifactCodec.TryDecode(File.ReadAllText(license), out var artifact, out _));
        Assert.Null(artifact!.Payload.InstallationId);
        Assert.True(artifact.Payload.Limits.TryGetValue("max_services", out var max));
        Assert.Null(max);

        var verify = await ws.Run(
            "verify", "--license", license, "--public-key", pub, "--now", "2030-06-01T00:00:00Z");
        Assert.Equal(0, verify.Exit);
    }

    [Fact]
    public async Task IssueThenComposeSspActivationService_ValidatesEndToEnd()
    {
        using var ws = new AuthorityWorkspace();
        var (license, pub, _) = await IssueDefaultAsync(ws);
        var pem = File.ReadAllText(pub);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        using var anchor = LicenseTrustAnchor.FromPublicKey(rsa);

        var paths = SspLicensePaths.Resolve(ws.Root);
        File.Copy(license, paths.LicenseFilePath, overwrite: true);

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
    }

    [Fact]
    public async Task KeygenIssueVerify_ProductionSizedRoundTrip()
    {
        using var ws = new AuthorityWorkspace();
        var priv = ws.PathTo("prod-private.pem");
        var pub = ws.PathTo("prod-public.pem");
        var license = ws.PathTo("prod-license.json");

        var keygen = await ws.Run("keygen", "--private-key", priv, "--public-key", pub);
        Assert.Equal(0, keygen.Exit);

        var issued = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(priv, license));
        Assert.Equal(0, issued.Exit);

        var verified = await ws.Run(
            "verify", "--license", license, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-06-01T00:00:00Z");
        Assert.Equal(0, verified.Exit);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(pub));
        Assert.Equal(3072, rsa.KeySize);
        Assert.Contains(SspTrustAnchor.ComputeFingerprint(rsa.ExportSubjectPublicKeyInfo()), keygen.Stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Issue_DoesNotOverwriteWithoutForce()
    {
        using var ws = new AuthorityWorkspace();
        var (license, _, priv) = await IssueDefaultAsync(ws);
        var original = File.ReadAllText(license);

        var again = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(priv, license, sequence: 99));
        Assert.NotEqual(0, again.Exit);
        Assert.Equal(original, File.ReadAllText(license));

        var forced = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(priv, license, sequence: 99, force: true));
        Assert.Equal(0, forced.Exit);
        Assert.True(LicenseArtifactCodec.TryDecode(File.ReadAllText(license), out var artifact, out _));
        Assert.Equal(99, artifact!.Payload.SequenceNumber);
    }

    private static async Task<(string License, string PublicKey, string PrivateKey)> IssueDefaultAsync(
        AuthorityWorkspace ws,
        long sequence = 1)
    {
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv-" + Guid.NewGuid().ToString("N") + ".pem");
        var pub = ws.PathTo("pub-" + Guid.NewGuid().ToString("N") + ".pem");
        var license = ws.PathTo("license-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(priv, pair.PrivatePem);
        File.WriteAllText(pub, pair.PublicPem);

        var issued = await ws.Run(AuthorityTestPayload.DefaultIssueArgs(priv, license, sequence: sequence));
        Assert.Equal(0, issued.Exit);
        return (license, pub, priv);
    }

    private sealed class FixedClock : IClock
    {
        public DateTimeOffset UtcNow { get; } = new(2030, 6, 1, 0, 0, 0, TimeSpan.Zero);
    }
}
