using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

public sealed class SspLicenseInstallerTests
{
    private static readonly DateTimeOffset Now = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task InstallAsync_ValidArtifact_ReplacesCanonicalLicense()
    {
        using var authority = RSA.Create(2048);
        var dir = TempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            var oldArtifact = Issue(authority, Payload(sequence: 1));
            var newArtifact = Issue(authority, Payload(sequence: 2));
            File.WriteAllText(paths.LicenseFilePath, oldArtifact);
            using var service = Compose(paths, authority);

            var source = Path.Combine(dir, "incoming.json");
            File.WriteAllText(source, newArtifact);
            var result = await SspLicenseInstaller.InstallAsync(service, source);

            Assert.True(result.IsValid);
            Assert.Equal(newArtifact, File.ReadAllText(paths.LicenseFilePath));
        }
        finally { Delete(dir); }
    }

    [Fact]
    public async Task InstallAsync_InvalidArtifact_LeavesExistingLicenseUntouched()
    {
        using var authority = RSA.Create(2048);
        var dir = TempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            var existing = Issue(authority, Payload(sequence: 1));
            File.WriteAllText(paths.LicenseFilePath, existing);
            using var service = Compose(paths, authority);
            var source = Path.Combine(dir, "incoming.json");
            File.WriteAllText(source, "not a license");

            var result = await SspLicenseInstaller.InstallAsync(service, source);

            Assert.False(result.IsValid);
            Assert.Equal(existing, File.ReadAllText(paths.LicenseFilePath));
        }
        finally { Delete(dir); }
    }

    [Theory]
    [InlineData(-1, 0)] // expired at the validation clock
    [InlineData(0, 1)]  // not yet valid at the validation clock
    public async Task InstallAsync_InvalidValidityWindow_IsRejected(int expiryOffsetHours, int notBeforeOffsetHours)
    {
        using var authority = RSA.Create(2048);
        var dir = TempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            var existing = Issue(authority, Payload(sequence: 1));
            File.WriteAllText(paths.LicenseFilePath, existing);
            using var service = Compose(paths, authority);
            var candidate = Payload(sequence: 2);
            if (expiryOffsetHours != 0)
                candidate = candidate with { ExpiresAt = Now.AddHours(expiryOffsetHours) };
            if (notBeforeOffsetHours != 0)
                candidate = candidate with { NotBefore = Now.AddHours(notBeforeOffsetHours) };
            var source = Path.Combine(dir, "incoming.json");
            File.WriteAllText(source, Issue(authority, candidate));

            var result = await SspLicenseInstaller.InstallAsync(service, source);

            Assert.False(result.IsValid);
            Assert.Equal(existing, File.ReadAllText(paths.LicenseFilePath));
        }
        finally { Delete(dir); }
    }

    [Fact]
    public async Task InstallAsync_ProductMismatch_IsRejectedAndDoesNotReplace()
    {
        using var authority = RSA.Create(2048);
        var dir = TempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            var existing = Issue(authority, Payload(sequence: 1));
            File.WriteAllText(paths.LicenseFilePath, existing);
            using var service = Compose(paths, authority);
            var source = Path.Combine(dir, "incoming.json");
            File.WriteAllText(source, Issue(authority, Payload(Guid.NewGuid(), sequence: 2)));

            var result = await SspLicenseInstaller.InstallAsync(service, source);

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.WrongProduct, result.State);
            Assert.Equal(existing, File.ReadAllText(paths.LicenseFilePath));
        }
        finally { Delete(dir); }
    }

    private static SspActivationService Compose(SspLicensePaths paths, RSA authority) =>
        SspActivationService.Compose(
            paths,
            LicenseTrustAnchor.FromPublicKey(authority),
            new StaticInstallationIdentityProvider(null),
            new InMemorySecurityEventSink(),
            new InMemoryLicenseStateStore(),
            new LocalLicenseFileProvider(paths.LicenseFilePath),
            new FixedClock());

    private static LicensePayload Payload(Guid? product = null, long sequence = 1) => new()
    {
        LicenseId = Guid.NewGuid(), ProductId = product ?? SspLicensing.ProductId,
        ProductName = SspLicensing.ProductName, CustomerId = Guid.NewGuid(),
        CustomerName = "Test", Edition = "Enterprise", LicenseVersion = "1.0",
        IssuedAt = Now.AddDays(-1), NotBefore = Now, ExpiresAt = Now.AddDays(30),
        FeatureSet = new LicenseFeatureSet(new[] { "rdp" }), Limits = LicenseLimits.Empty,
        Status = LicenseStatus.Active, SequenceNumber = sequence
    };

    private static string Issue(RSA authority, LicensePayload payload) =>
        LicenseIssuer.EncodeLicenseArtifact(payload, authority);

    private sealed class FixedClock : IClock { public DateTimeOffset UtcNow => Now; }
    private static string TempDir() { var d = Path.Combine(Path.GetTempPath(), "ssp-install-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(d); return d; }
    private static void Delete(string d) { try { Directory.Delete(d, true); } catch { } }
}
