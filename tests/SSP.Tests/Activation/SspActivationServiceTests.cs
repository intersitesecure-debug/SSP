// File: tests/SSP.Tests/Activation/SspActivationServiceTests.cs
//
// Tests for the SSP activation composition root. They prove that
// SspActivationService wires every component of the vendored library
// (LicenseManager -> LicenseValidator, LicenseTrustAnchor, license provider,
// installation identity, state store, event sink, clock, policy) and the
// LicenseEnforcement facade into one working, fail-closed runtime - with an
// ephemeral test authority key, exactly the way the reference test suite
// exercises the library.
//
// Phase 3 scope note: these tests verify composition and lifecycle (load /
// revalidate / status / anti-rollback floor). They deliberately do not test
// any server runtime gate, because no runtime enforcement exists yet.

using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

public class SspActivationServiceTests
{
    private static readonly DateTimeOffset FixedNow = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Create_FailsClosedWhenNoProductionAnchorIsCompiledIn()
    {
        if (SspTrustAnchor.IsCompiledIn)
        {
            // An anchored build must compose successfully; this assertion only
            // applies to builds without a ceremony key (the current dev state).
            return;
        }

        var ex = Assert.Throws<InvalidOperationException>(() => SspActivationService.Create());
        Assert.Contains("trust anchor", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compose_WiresFullPipeline_LoadsValidLicense_AndAuthorizes()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            var payload = CreatePayload(
                SspLicensing.ProductId,
                sequenceNumber: 1,
                limits: (LicenseLimitNames.MaxClients, 2L));
            WriteLicenseFile(dir, payload, authority);

            var paths = SspLicensePaths.Resolve(dir);
            var clock = new FixedClock();
            var events = new InMemorySecurityEventSink();
            using var service = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider(installationId: null),
                events,
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                clock);

            // Every component is wired and visible on the root.
            Assert.Equal(SspLicensing.ProductId, service.ValidationOptions.ExpectedProductId);
            Assert.Same(clock, service.Clock);
            Assert.NotNull(service.TrustAnchor);
            Assert.NotNull(service.Manager);
            Assert.NotNull(service.Enforcement);
            Assert.NotNull(service.IdentityProvider);
            Assert.NotNull(service.EventSink);
            Assert.NotNull(service.StateStore);
            Assert.NotNull(service.LicenseProvider);
            Assert.Equal(LicenseState.Unknown, service.CurrentState);

            var result = service.Load();
            Assert.True(result.IsValid);
            Assert.Equal(LicenseState.Valid, service.CurrentState);
            Assert.NotNull(service.CurrentLicense);

            // The enforcement facade is backed by the same manager.
            Assert.True(service.Enforcement.CanUseFeature("rdp").IsAllowed);
            Assert.False(service.Enforcement.CanUseFeature("not-licensed").IsAllowed);
            Assert.True(service.Enforcement.CanStartProtectedService(0).IsAllowed);
            Assert.True(service.Enforcement.CheckLimit(LicenseLimitNames.MaxClients, 1).IsAllowed);
            Assert.False(service.Enforcement.CheckLimit(LicenseLimitNames.MaxClients, 2).IsAllowed);

            // Validation events flowed into the wired sink.
            Assert.Contains(events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseValidated);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Compose_MissingLicense_FailsClosed_UnknownState()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            // No license.json in the licensing directory.
            var paths = SspLicensePaths.Resolve(dir);
            using var service = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider(installationId: null),
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            var result = service.Load();

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.Unknown, result.State);
            Assert.Equal(LicenseReasons.MissingLicense, result.ReasonCode);
            Assert.Equal(LicenseState.Unknown, service.CurrentState);
            Assert.Null(service.CurrentLicense);
            Assert.False(service.Enforcement.CanUseFeature("rdp").IsAllowed);
            Assert.False(service.Enforcement.CanStartProtectedService(0).IsAllowed);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Compose_WrongProduct_IsRejected_AndLocksDown()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            var payload = CreatePayload(Guid.NewGuid(), sequenceNumber: 1);
            WriteLicenseFile(dir, payload, authority);

            var paths = SspLicensePaths.Resolve(dir);
            using var service = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider(installationId: null),
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            var result = service.Load();

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.WrongProduct, result.State);
            Assert.Equal(LicenseState.LockedDown, service.CurrentState);
            Assert.False(service.Enforcement.CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Compose_InstallationBinding_IsEnforced()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            var payload = CreatePayload(
                SspLicensing.ProductId,
                installationId: "INSTALLATION-A",
                sequenceNumber: 1);
            WriteLicenseFile(dir, payload, authority);

            var paths = SspLicensePaths.Resolve(dir);

            // Matching identity: valid.
            using (var matching = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider("installation-a"), // case-insensitive compare
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock()))
            {
                Assert.True(matching.Load().IsValid);
                Assert.Equal(LicenseState.Valid, matching.CurrentState);
            }

            // Mismatched identity: rejected and locked down.
            using var mismatched = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider("INSTALLATION-B"),
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            var result = mismatched.Load();
            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.WrongInstallation, result.State);
            Assert.Equal(LicenseState.LockedDown, mismatched.CurrentState);
            Assert.False(mismatched.Enforcement.CanEstablishTunnel(0).IsAllowed);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Compose_Revalidate_WithExpiredClock_LocksDown()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            var payload = CreatePayload(SspLicensing.ProductId, sequenceNumber: 1); // expires 2031-01-01
            WriteLicenseFile(dir, payload, authority);

            var paths = SspLicensePaths.Resolve(dir);
            var clock = new FixedClock();
            using var service = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider(installationId: null),
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                clock);

            Assert.True(service.Load().IsValid);

            // The wired clock drives the validator: after the expiry boundary
            // the same artifact revalidates as Expired and locks the runtime.
            clock.UtcNow = new DateTimeOffset(2032, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var result = service.Revalidate();

            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.Expired, result.State);
            Assert.Equal(LicenseState.LockedDown, service.CurrentState);
            Assert.Null(service.CurrentLicense);
            Assert.False(service.Enforcement.CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Compose_AntiRollbackFloor_PersistsThroughSspStateStore()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);

            using (var first = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider(installationId: null),
                new SspSecurityEventSink(paths.SecurityLogDirectory, writeToConsole: false),
                new SspLicenseStateStore(paths.StateStorePath),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock()))
            {
                WriteLicenseFile(dir, CreatePayload(SspLicensing.ProductId, sequenceNumber: 2), authority);
                Assert.True(first.Load().IsValid);
                Assert.True(File.Exists(paths.StateStorePath), "The wired DPAPI state store must persist the accepted floor.");
            }

            // A fresh composition over the same directory (process restart)
            // must reject an older artifact: the floor is enforced through the
            // wired store, not through memory.
            WriteLicenseFile(dir, CreatePayload(SspLicensing.ProductId, sequenceNumber: 1), authority);
            using var restarted = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider(installationId: null),
                new SspSecurityEventSink(paths.SecurityLogDirectory, writeToConsole: false),
                new SspLicenseStateStore(paths.StateStorePath),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            var result = restarted.Load();
            Assert.False(result.IsValid);
            Assert.Equal(LicenseState.Superseded, result.State);
            Assert.Equal(LicenseState.LockedDown, restarted.CurrentState);
            Assert.False(restarted.Enforcement.CanUseFeature("rdp").IsAllowed);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Compose_ProductionSink_WritesSecretFreeSecurityLog()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            var payload = CreatePayload(SspLicensing.ProductId, sequenceNumber: 1);
            WriteLicenseFile(dir, payload, authority);

            var paths = SspLicensePaths.Resolve(dir);
            using var service = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider(installationId: null),
                new SspSecurityEventSink(paths.SecurityLogDirectory, writeToConsole: false),
                new SspLicenseStateStore(paths.StateStorePath),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            Assert.True(service.Load().IsValid);

            var logPath = Path.Combine(paths.SecurityLogDirectory, SspSecurityEventSink.LogFileName);
            Assert.True(File.Exists(logPath));
            var content = File.ReadAllText(logPath);
            Assert.Contains("event=LicenseValidated", content, StringComparison.Ordinal);
            Assert.DoesNotContain("BEGIN", content, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE", content, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void DescribeStatus_ReportsWiredRuntimeAndLicense()
    {
        using var authority = CreateAuthorityKey();
        var dir = CreateTempDir();
        try
        {
            var payload = CreatePayload(
                SspLicensing.ProductId,
                installationId: "INSTALLATION-A",
                sequenceNumber: 3,
                features: new[] { "rdp", "ssh" },
                limits: (LicenseLimitNames.MaxClients, 5L));
            WriteLicenseFile(dir, payload, authority);

            var paths = SspLicensePaths.Resolve(dir);
            using var service = SspActivationService.Compose(
                paths,
                LicenseTrustAnchor.FromPublicKey(authority),
                new StaticInstallationIdentityProvider("INSTALLATION-A"),
                new InMemorySecurityEventSink(),
                new InMemoryLicenseStateStore(),
                new LocalLicenseFileProvider(paths.LicenseFilePath),
                new FixedClock());

            service.Load();
            var text = service.DescribeStatus();

            Assert.Contains("State              : Valid", text, StringComparison.Ordinal);
            Assert.Contains("Reason             : ok", text, StringComparison.Ordinal);
            Assert.Contains("Product            : SSP (" + SspLicensing.ProductId.ToString("D") + ")", text, StringComparison.Ordinal);
            Assert.Contains("Installation id    : INSTALLATION-A", text, StringComparison.Ordinal);
            Assert.Contains("Customer           : Test Customer", text, StringComparison.Ordinal);
            Assert.Contains("Edition            : Enterprise", text, StringComparison.Ordinal);
            Assert.Contains("ExpiresAt          :", text, StringComparison.Ordinal);
            Assert.Contains("Sequence           : 3", text, StringComparison.Ordinal);
            Assert.Contains(paths.LicenseFilePath, text, StringComparison.Ordinal);
            Assert.Contains(paths.StateStorePath, text, StringComparison.Ordinal);
            Assert.DoesNotContain("BEGIN", text, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE", text, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Compose_RejectsMissingRequiredComponents()
    {
        var dir = CreateTempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            using var authority = CreateAuthorityKey();
            using var anchor = LicenseTrustAnchor.FromPublicKey(authority);
            var sink = new InMemorySecurityEventSink();
            var store = new InMemoryLicenseStateStore();
            var provider = new LocalLicenseFileProvider(paths.LicenseFilePath);
            var identity = new StaticInstallationIdentityProvider(installationId: null);

            Assert.Throws<ArgumentNullException>(() => SspActivationService.Compose(
                null!, anchor, identity, sink, store, provider));
            Assert.Throws<ArgumentNullException>(() => SspActivationService.Compose(
                paths, null!, identity, sink, store, provider));
            Assert.Throws<ArgumentNullException>(() => SspActivationService.Compose(
                paths, anchor, null!, sink, store, provider));
            Assert.Throws<ArgumentNullException>(() => SspActivationService.Compose(
                paths, anchor, identity, null!, store, provider));
            Assert.Throws<ArgumentNullException>(() => SspActivationService.Compose(
                paths, anchor, identity, sink, null!, provider));
            Assert.Throws<ArgumentNullException>(() => SspActivationService.Compose(
                paths, anchor, identity, sink, store, null!));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // ------------------------------------------------------------------
    // Test support (ephemeral authority, deterministic payloads, temp dirs)
    // ------------------------------------------------------------------

    private static RSA CreateAuthorityKey() => RSA.Create(2048);

    private static LicensePayload CreatePayload(
        Guid productId,
        string? installationId = null,
        long sequenceNumber = 1,
        string[]? features = null,
        params (string Name, long? Max)[] limits)
    {
        return new LicensePayload
        {
            LicenseId = Guid.NewGuid(),
            ProductId = productId,
            ProductName = SspLicensing.ProductName,
            CustomerId = Guid.NewGuid(),
            CustomerName = "Test Customer",
            Edition = "Enterprise",
            LicenseVersion = "1.0",
            IssuedAt = new DateTimeOffset(2029, 12, 1, 0, 0, 0, TimeSpan.Zero),
            NotBefore = FixedNow,
            ExpiresAt = new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero),
            InstallationId = installationId,
            FeatureSet = new LicenseFeatureSet(features ?? new[] { "rdp" }),
            Limits = new LicenseLimits(limits.Select(l => new KeyValuePair<string, long?>(l.Name, l.Max))),
            Status = LicenseStatus.Active,
            SequenceNumber = sequenceNumber,
        };
    }

    private static void WriteLicenseFile(string dir, LicensePayload payload, RSA authorityKey)
    {
        var artifact = LicenseIssuer.EncodeLicenseArtifact(payload, authorityKey);
        File.WriteAllText(Path.Combine(dir, SspLicensePaths.LicenseFileName), artifact);
    }

    private sealed class FixedClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = FixedNow;
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-activation-service-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
