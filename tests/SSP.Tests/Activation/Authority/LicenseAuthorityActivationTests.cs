// File: tests/SSP.Tests/Activation/Authority/LicenseAuthorityActivationTests.cs
//
// Offline activation tooling, end to end: issue-certified (v2 artifact + OTT +
// 10-digit code), the customer's activation request file, and the authority
// `activate` command that matches the OTT and returns the single-use code.
// Production authority material is never used; every key is ephemeral.

using System.Text.Json;
using SSP.Activation;

namespace SSP.Tests.Activation.Authority;

public sealed class LicenseAuthorityActivationTests
{
    private static string[] CertifiedArgs(
        string privateKey,
        string output,
        string? activationRecord = null,
        bool activationRequired = false,
        Guid? customerId = null,
        string? installationId = "INSTALLATION-A",
        string? organizationName = null,
        string? computerName = null)
    {
        var args = new List<string>
        {
            "issue-certified",
            "--private-key", privateKey,
            "--output", output,
            "--customer-id", (customerId ?? Guid.NewGuid()).ToString("D"),
            "--customer-name", "Activation Test Customer",
            "--edition", "Enterprise",
            "--issued-at", "2029-12-01T00:00:00Z",
            "--not-before", "2030-01-01T00:00:00Z",
            "--expires-at", "2031-01-01T00:00:00Z",
        };

        if (!string.IsNullOrEmpty(installationId))
        {
            args.Add("--installation-id");
            args.Add(installationId);
        }

        foreach (var feature in new[] { "rdp", "ssh", "web", "sql" })
        {
            args.Add("--feature");
            args.Add(feature);
        }

        foreach (var limit in new[] { "max_services=3", "max_clients=10", "max_concurrent_tunnels=5" })
        {
            args.Add("--limit");
            args.Add(limit);
        }

        if (!string.IsNullOrEmpty(organizationName))
        {
            args.Add("--organization-name");
            args.Add(organizationName);
        }

        if (!string.IsNullOrEmpty(computerName))
        {
            args.Add("--computer-name");
            args.Add(computerName);
        }

        if (activationRequired || activationRecord is not null)
        {
            args.Add("--activation-required");
        }

        if (activationRecord is not null)
        {
            args.Add("--activation-record");
            args.Add(activationRecord);
        }

        return args.ToArray();
    }

    private static async Task<(AuthorityWorkspace Ws, string License, string Record, string Code, string Ott, Guid LicenseId)>
        IssueActivationRequiredAsync(string? organizationName = null, string? computerName = null)
    {
        var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        File.WriteAllText(priv, pair.PrivatePem);

        var license = ws.PathTo("license.json");
        var record = ws.PathTo("activation-record.json");
        var issued = await ws.Run(CertifiedArgs(priv, license, record,
            organizationName: organizationName, computerName: computerName));
        Assert.Equal(0, issued.Exit);
        Assert.True(File.Exists(license), "certified license was not written");
        Assert.True(File.Exists(record), "activation record was not written");
        Assert.DoesNotContain("BEGIN", issued.Stdout, StringComparison.Ordinal);

        // The code is printed exactly once and is 10 digits; it is NOT in the license.
        var codeLine = issued.Stdout
            .Split('\n')
            .Select(l => l.Trim())
            .First(l => l.StartsWith("Activation code", StringComparison.Ordinal));
        var code = codeLine.Split(':', 2)[1].Trim();
        Assert.Equal(10, code.Length);
        Assert.True(code.All(char.IsAsciiDigit));
        Assert.DoesNotContain(code, File.ReadAllText(license), StringComparison.Ordinal);

        // The record binds the OTT and the code to the license id.
        using var recordDoc = JsonDocument.Parse(File.ReadAllText(record));
        var recordRoot = recordDoc.RootElement;
        Assert.Equal(code, recordRoot.GetProperty("activationCode").GetString());
        var ott = recordRoot.GetProperty("activationOtt").GetString()!;
        var licenseId = Guid.Parse(recordRoot.GetProperty("licenseId").GetString()!);
        Assert.False(recordRoot.GetProperty("consumed").GetBoolean());

        // The OTT is signed into the license's certification; the code hash is too.
        Assert.True(LicenseArtifactCodec.TryDecode(File.ReadAllText(license), out var artifact, out var decodeError), decodeError?.Detail);
        Assert.Equal(2, artifact!.ArtifactVersion);
        Assert.NotNull(artifact.Certification);
        Assert.Equal(ott, artifact.Certification!.ActivationOtt);
        Assert.Equal(LicenseActivation.ComputeActivationCodeHash(code), artifact.Certification.ActivationCodeHash);
        Assert.Equal(licenseId, artifact.Certification.LicenseId);
        Assert.Equal(licenseId, artifact.Payload.LicenseId);

        if (organizationName is not null)
        {
            Assert.Equal(organizationName, artifact.Payload.OrganizationOrPersonName);
        }

        if (computerName is not null)
        {
            Assert.Equal(computerName, artifact.Payload.ComputerName);
        }

        return (ws, license, record, code, ott, licenseId);
    }

    [Fact]
    public async Task IssueCertified_ActivationRequired_BindsOttAndCodeToLicense()
    {
        var (ws, _, _, _, _, _) = await IssueActivationRequiredAsync(
            organizationName: "Contoso R&D", computerName: "TUNNEL-01");
        ws.Dispose();
    }

    [Fact]
    public async Task OfflineRequest_Activate_ReturnsCode_AndConsumesItExactlyOnce()
    {
        var (ws, license, record, code, ott, licenseId) = await IssueActivationRequiredAsync();

        // The customer builds the request from the installed license (identity + OTT).
        Assert.True(LicenseArtifactCodec.TryDecode(File.ReadAllText(license), out var artifact, out _));
        var request = new ActivationRequest
        {
            LicenseId = licenseId,
            ProductId = artifact!.Payload.ProductId,
            CustomerId = artifact.Payload.CustomerId,
            OrganizationOrPersonName = artifact.Payload.OrganizationOrPersonName,
            ComputerName = artifact.Payload.ComputerName,
            InstallationId = artifact.Payload.InstallationId,
            ActivationOtt = ott,
            RequestedAtUtc = AuthorityTestPayload.Now
        };
        var requestPath = ws.PathTo("activation-request.json");
        File.WriteAllText(requestPath, ActivationRequestCodec.Encode(request));

        // Successful activation returns the code.
        var activate = await ws.Run("activate", "--request", requestPath, "--activation-record", record);
        Assert.Equal(0, activate.Exit);
        Assert.Contains(code, activate.Stdout, StringComparison.Ordinal);
        Assert.Contains(licenseId.ToString("D"), activate.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", activate.Stdout, StringComparison.Ordinal);

        // The record is now consumed: a replay of the identical request is refused.
        var replay = await ws.Run("activate", "--request", requestPath, "--activation-record", record);
        Assert.NotEqual(0, replay.Exit);
        Assert.Contains("consumed", replay.Stderr, StringComparison.OrdinalIgnoreCase);

        ws.Dispose();
    }

    [Fact]
    public async Task Activate_RefusesWrongOtt_AndWrongLicense()
    {
        var (ws, _, record, _, _, licenseId) = await IssueActivationRequiredAsync();

        // Wrong OTT (attacker-generated request): refused, record NOT consumed.
        var wrongOtt = ws.PathTo("wrong-ott.json");
        File.WriteAllText(wrongOtt, ActivationRequestCodec.Encode(new ActivationRequest
        {
            LicenseId = licenseId,
            ProductId = Guid.NewGuid(),
            CustomerId = Guid.NewGuid(),
            ActivationOtt = LicenseActivation.GenerateActivationOtt(),
            RequestedAtUtc = AuthorityTestPayload.Now
        }));
        var wrongOttResult = await ws.Run("activate", "--request", wrongOtt, "--activation-record", record);
        Assert.NotEqual(0, wrongOttResult.Exit);
        Assert.Contains("does not match", wrongOttResult.Stderr, StringComparison.OrdinalIgnoreCase);

        // Wrong license id: refused before the OTT is even compared.
        var otherId = ws.PathTo("wrong-license.json");
        File.WriteAllText(otherId, ActivationRequestCodec.Encode(new ActivationRequest
        {
            LicenseId = Guid.NewGuid(),
            ProductId = Guid.NewGuid(),
            CustomerId = Guid.NewGuid(),
            ActivationOtt = LicenseActivation.GenerateActivationOtt(),
            RequestedAtUtc = AuthorityTestPayload.Now
        }));
        var wrongIdResult = await ws.Run("activate", "--request", otherId, "--activation-record", record);
        Assert.NotEqual(0, wrongIdResult.Exit);
        Assert.Contains("is for license", wrongIdResult.Stderr, StringComparison.OrdinalIgnoreCase);

        // The record was never consumed by either failed attempt.
        using var recordDoc = JsonDocument.Parse(File.ReadAllText(record));
        Assert.False(recordDoc.RootElement.GetProperty("consumed").GetBoolean());

        ws.Dispose();
    }

    [Fact]
    public async Task Activate_RefusesMalformedRequest_FailClosed()
    {
        var (ws, _, record, _, _, _) = await IssueActivationRequiredAsync();
        var bad = ws.PathTo("bad-request.json");
        File.WriteAllText(bad, "{ not json");

        var result = await ws.Run("activate", "--request", bad, "--activation-record", record);
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("decoded", result.Stderr, StringComparison.OrdinalIgnoreCase);

        ws.Dispose();
    }

    [Fact]
    public async Task IssueCertified_ActivationRequired_WithoutRecord_Fails()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        File.WriteAllText(priv, pair.PrivatePem);

        // --activation-required WITHOUT --activation-record must fail closed.
        var result = await ws.Run(CertifiedArgs(priv, ws.PathTo("license.json"), activationRequired: true));
        Assert.NotEqual(0, result.Exit);
        Assert.Contains("--activation-record is required", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IssueCertified_PreActivated_VerifiesAgainstRootKey()
    {
        using var ws = new AuthorityWorkspace();
        var pair = EphemeralAuthorityKeys.Create(2048);
        var priv = ws.PathTo("priv.pem");
        var pub = ws.PathTo("pub.pem");
        File.WriteAllText(priv, pair.PrivatePem);
        File.WriteAllText(pub, pair.PublicPem);

        var license = ws.PathTo("preactivated.json");
        var issued = await ws.Run(CertifiedArgs(priv, license, activationRecord: null));
        Assert.Equal(0, issued.Exit);

        // A pre-activated v2 license verifies against the ROOT public key (the
        // root certifies the leaf; the validator walks the chain).
        var verify = await ws.Run(
            "verify", "--license", license, "--public-key", pub,
            "--installation-id", "INSTALLATION-A", "--now", "2030-06-01T00:00:00Z");
        Assert.Equal(0, verify.Exit);
        Assert.Contains("Valid", verify.Stdout, StringComparison.Ordinal);
    }
}
