using System.Security.Cryptography;
using SSP.Activation;
using SSP.Client.Runtime;
using SSP.Core.Activation;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Server.Activation;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation.Runtime;

/// <summary>Phase 6: the existing production admission paths, not an alternate licensing policy.</summary>
public class ClockRollbackEnforcementTests
{
    private static readonly DateTimeOffset Now = LicensedTestOptions.DefaultNow;

    [Theory]
    [InlineData("start")]
    [InlineData("enroll")]
    [InlineData("feature")]
    [InlineData("arbitrary-feature")]
    [InlineData("tunnel")]
    [InlineData("unknown-application-tunnel")]
    public void EveryRuntimeGate_DeniesRollbackWithoutWaitingForRefresh(string entry)
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = entry == "unknown-application-tunnel" ? "CUSTOM" : "RDP"
        });
        Assert.True(env.Load().IsValid);
        Assert.False(env.Activation.IsRevalidationTimerRunning);
        env.Clock.UtcNow = Now.AddTicks(-1);

        var decision = AuthorizeEntry(env.Gate, entry);
        Assert.False(decision.IsAllowed);
        Assert.Equal(LicenseReasons.ClockRollbackDetected, decision.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        Assert.Null(env.Activation.CurrentLicense);
        Assert.Equal(0, env.Gate.ActiveTunnels);
        Assert.Equal(0, env.Gate.ActiveSessions);
        Assert.False(env.Gate.CanStartProtectedService(0).IsAllowed);
        Assert.False(env.Gate.CanEnrollClient(0).IsAllowed);
        Assert.Contains(env.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.ClockRollbackDetected);
        Assert.Contains(env.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EitherSignedValidityWindow_ExpiresIndependently_AndCannotBeRevived(bool certificationExpiresFirst)
    {
        var root = Path.Combine(Path.GetTempPath(), "ssp-clock-window-" + Guid.NewGuid().ToString("N"));
        try
        {
            var paths = SspLicensePaths.Resolve(Path.Combine(root, "licensing"));
            Directory.CreateDirectory(paths.LicenseDirectory);
            using var authority = RSA.Create(2048);
            using var leaf = RSA.Create(2048);
            var payload = LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
            {
                ExpiresAt = Now.AddHours(certificationExpiresFirst ? 2 : 1)
            });
            var certification = new LicenseKeyCertification
            {
                LicenseId = payload.LicenseId, ProductId = payload.ProductId, CustomerId = payload.CustomerId,
                PublicKeySpkiDer = leaf.ExportSubjectPublicKeyInfo(), NotBefore = payload.IssuedAt,
                ExpiresAt = Now.AddHours(certificationExpiresFirst ? 1 : 2)
            };
            var artifact = LicenseCertificationIssuer.EncodeCertifiedLicenseArtifact(payload, certification, authority, leaf);
            File.WriteAllText(paths.LicenseFilePath, artifact);
            var clock = new TestClock(Now);
            using var activation = Compose(paths, authority, clock);
            using var gate = new SspRuntimeLicense(activation, SspLicensing.Features.RemoteDesktopProtocol);
            Assert.True(activation.Load().IsValid);
            clock.UtcNow = Now.AddHours(1); // expiresAt is exclusive for either signed window
            using var denied = gate.AdmitTunnel();
            Assert.False(denied.IsAdmitted);
            Assert.Equal(certificationExpiresFirst ? LicenseReasons.CertificationExpired : LicenseReasons.Expired, denied.ReasonCode);
            Assert.Equal(0, gate.ActiveTunnels);
            Assert.Equal(Now.AddHours(1), activation.StateStore.Load()!.LastObservedUtc);

            using var restarted = Compose(paths, authority, new TestClock(Now.AddMinutes(30)));
            Assert.Equal(LicenseReasons.ClockRollbackDetected, restarted.Load().ReasonCode);
            Assert.False(restarted.Enforcement.RequireValidLicense().IsAllowed);
            Assert.Equal(artifact, File.ReadAllText(paths.LicenseFilePath));
        }
        finally { try { Directory.Delete(root, recursive: true); } catch { /* test cleanup */ } }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PendingActivation_CannotAcceptACodeAfterRollbackOrExpiry(bool expired)
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Certified = true, ActivationRequired = true, ActivationCode = "1234567890",
            ExpiresAt = Now.AddHours(1)
        });
        Assert.Equal(LicenseState.ActivationRequired, env.Load().State);
        env.Clock.UtcNow = expired ? Now.AddHours(2) : Now.AddTicks(-1);
        var result = env.Activation.TryActivate("1234567890");
        Assert.False(result.IsValid);
        Assert.Equal(expired ? LicenseReasons.CertificationExpired : LicenseReasons.ClockRollbackDetected, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        var state = env.StateStore.Load()!;
        Assert.Null(state.ActivatedLicenseId);
        Assert.Null(state.LastAcceptedLicenseId);
        Assert.Null(state.LastValidatedUtc);
        Assert.Equal(0, state.HighestAcceptedSequenceNumber);
        Assert.DoesNotContain(env.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseActivated);
        using var denied = env.Gate.AdmitTunnel();
        Assert.False(denied.IsAdmitted);

        if (expired)
        {
            Assert.Equal(Now.AddHours(2), state.LastObservedUtc);
            env.Clock.UtcNow = Now.AddMinutes(30);
            Assert.Equal(LicenseReasons.ClockRollbackDetected, env.Revalidate().ReasonCode);
        }
        else
        {
            env.Clock.UtcNow = Now;
            Assert.Equal(LicenseState.ActivationRequired, env.Reload().State);
            Assert.True(env.Activation.TryActivate("1234567890").IsValid);
        }
    }

    [Fact]
    public void ActivationCheckpointFailure_NeverPublishesAValidLicense()
    {
        var store = new ActivationFailureStore();
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Certified = true, ActivationRequired = true, ActivationCode = "1234567890", StateStore = store
        });
        Assert.Equal(LicenseState.ActivationRequired, env.Load().State);
        var result = env.Activation.TryActivate("1234567890");
        Assert.Equal(LicenseReasons.StateStoreUnavailable, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        Assert.Null(env.Activation.CurrentLicense);
        Assert.Null(store.Load()!.ActivatedLicenseId);
        Assert.False(env.Gate.CanStartProtectedService(0).IsAllowed);
        Assert.DoesNotContain(env.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseActivated);
    }

    [Fact]
    public void ServiceStartup_WithRetainedFutureTime_IsRefused()
    {
        using var env = LicensedTestEnvironment.Create();
        env.StateStore.Save(new LicenseStateRecord { ClockStateVersion = 1, LastObservedUtc = Now.AddHours(1) });
        var exception = Assert.Throws<SspActivationException>(() =>
            env.Gate.AuthorizeServiceStart(new ServiceConfig { ApplicationName = "RDP" }));
        Assert.Equal(LicenseReasons.ClockRollbackDetected, exception.ReasonCode);
        Assert.Equal(0, env.Gate.ActiveTunnels);
        Assert.Equal(LicenseState.LockedDown, env.State);
    }

    [Fact]
    public async Task Timer_DetectsRollback_AndRecoversThroughFullValidationAtCorrectedTime()
    {
        using var env = LicensedTestEnvironment.Create();
        Assert.True(env.Load().IsValid);
        env.Clock.UtcNow = Now.AddTicks(-1);
        env.Activation.StartRevalidationTimer(TimeSpan.FromMilliseconds(50));
        await WaitUntilAsync(() => env.State == LicenseState.LockedDown);
        Assert.Equal(LicenseReasons.ClockRollbackDetected, env.Activation.LastValidationResult!.ReasonCode);
        Assert.Equal(Now, env.StateStore.Load()!.LastObservedUtc);

        env.Clock.UtcNow = Now.AddMinutes(1);
        await WaitUntilAsync(() => env.State == LicenseState.Valid);
        using var admission = env.Gate.AdmitTunnel();
        Assert.True(admission.IsAdmitted);
        Assert.Contains(env.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseLockdownCleared);
    }

    [Fact]
    public async Task TimerObservedExpiry_CannotBeReversed_AndOnlyAValidRenewalRecovers()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { ExpiresAt = Now.AddHours(1) });
        Assert.True(env.Load().IsValid);
        env.Clock.UtcNow = Now.AddHours(2);
        env.Activation.StartRevalidationTimer(TimeSpan.FromMilliseconds(50));
        await WaitUntilAsync(() => env.Activation.LastValidationResult?.ReasonCode == LicenseReasons.Expired);
        env.Clock.UtcNow = Now.AddMinutes(30);
        await WaitUntilAsync(() => env.Activation.LastValidationResult?.ReasonCode == LicenseReasons.ClockRollbackDetected);
        Assert.Equal(LicenseState.LockedDown, env.State);
        Assert.Equal(Now.AddHours(2), env.StateStore.Load()!.LastObservedUtc);
        using var denied = env.Gate.AdmitTunnel();
        Assert.False(denied.IsAdmitted);

        // Installing a genuine renewal is not a clock reset. First restore UTC,
        // then let the existing provider/timer run full cryptographic validation.
        env.Clock.UtcNow = Now.AddHours(2);
        env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
        {
            Now = Now.AddHours(2), SequenceNumber = 2, ExpiresAt = Now.AddDays(1)
        }));
        await WaitUntilAsync(() => env.State == LicenseState.Valid);
        Assert.Equal(2, env.StateStore.Load()!.HighestAcceptedSequenceNumber);
        Assert.True(env.Gate.CanUseServiceFeature().IsAllowed);
    }

    [Fact]
    public void ClockDenial_DoesNotRewriteLicenseOrUnrelatedCustomerFiles()
    {
        using var env = LicensedTestEnvironment.Create();
        Assert.True(env.Load().IsValid);
        var customerFile = Path.Combine(env.LicenseDirectory, ".cache.dat");
        File.WriteAllText(customerFile, "customer-owned configuration must not change");
        var paths = new[] { env.LicenseFilePath, customerFile, env.StateStorePath, env.Paths.StateWitnessPath };
        var before = paths.ToDictionary(path => path, File.ReadAllBytes);
        env.Clock.UtcNow = Now.AddTicks(-1);
        using var denied = env.Gate.AdmitTunnel();
        Assert.False(denied.IsAdmitted);
        Assert.False(env.Reload().IsValid);
        foreach (var path in paths) Assert.Equal(before[path], File.ReadAllBytes(path));
    }

    [Fact(Timeout = 60_000)]
    public async Task RealAuthenticatedConnection_AfterRollback_IsDeniedWithoutReservingAnotherSlot()
    {
        using var env = LicensedTestEnvironment.Create();
        Assert.True(env.Load().IsValid);
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP", env.Gate);
        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var enrolled = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);
        await WaitUntilAsync(() => env.Gate.ActiveTunnels == 0);
        var (existing, key) = await new ClientProtocol(enrolled).ConnectAndAuthenticateAsync();
        using (existing)
        {
            Assert.NotEmpty(key);
            Assert.Equal(1, env.Gate.ActiveTunnels);
            env.Clock.UtcNow = Now.AddTicks(-1);
            var error = await Assert.ThrowsAnyAsync<Exception>(() => new ClientProtocol(enrolled).ConnectAndAuthenticateAsync());
            Assert.Contains("authorization failed", error.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(LicenseState.LockedDown, env.State);
            Assert.Equal(LicenseReasons.ClockRollbackDetected, env.Activation.LastValidationResult!.ReasonCode);
            // Phase 6 gates NEW admissions; it does not forcibly terminate a
            // tunnel which was already admitted (existing resource semantics).
            Assert.Equal(1, env.Gate.ActiveTunnels);
            Assert.Equal(1, env.Gate.ActiveSessions);
            Assert.Equal(1, harness.Gateway.ActiveTunnels);
        }
        await WaitUntilAsync(() => env.Gate.ActiveTunnels == 0);
    }

    [Fact(Timeout = 60_000)]
    public async Task RealEnrollment_AfterRollback_DoesNotIssueACodeOrMutateEnrollmentState()
    {
        using var env = LicensedTestEnvironment.Create();
        Assert.True(env.Load().IsValid);
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP", env.Gate);
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        var configPath = Path.Combine(harness.ServiceDir, ".cache.dat");
        var usersPath = Path.Combine(harness.ServiceDir, ".index.dat");
        var configBefore = File.ReadAllBytes(configPath);
        var usersBefore = File.ReadAllBytes(usersPath);
        var requestedCode = false;
        var protocol = new ClientProtocol(runtime, () =>
        {
            requestedCode = true;
            return Task.FromResult("0000000000");
        });
        env.Clock.UtcNow = Now.AddTicks(-1);
        await Assert.ThrowsAnyAsync<Exception>(() => protocol.ConnectAndAuthenticateAsync());
        Assert.False(requestedCode);
        Assert.Equal(LicenseReasons.ClockRollbackDetected, env.Activation.LastValidationResult!.ReasonCode);
        Assert.Equal(configBefore, File.ReadAllBytes(configPath));
        Assert.Equal(usersBefore, File.ReadAllBytes(usersPath));
        Assert.Empty((await AuthorisedUsersStore.LoadAsync(usersPath)).Users);
        Assert.Equal(0, env.Gate.ActiveTunnels);
        Assert.Equal(0, env.Gate.ActiveSessions);
        Assert.Equal(0, harness.Gateway.ActiveTunnels);
    }

    private static AuthorizationDecision AuthorizeEntry(ISspLicenseGate gate, string entry)
    {
        switch (entry)
        {
            case "start": return gate.CanStartProtectedService(0);
            case "enroll": return gate.CanEnrollClient(0);
            case "feature": return gate.CanUseServiceFeature();
            case "arbitrary-feature": return gate.CanUseFeature(SspLicensing.Features.RemoteDesktopProtocol);
            default:
                using (var admission = gate.AdmitTunnel()) return admission.Decision;
        }
    }

    private static SspActivationService Compose(SspLicensePaths paths, RSA authority, IClock clock)
        => SspActivationService.Compose(paths, LicenseTrustAnchor.FromPublicKey(authority),
            new StaticInstallationIdentityProvider(null), new InMemorySecurityEventSink(),
            new SspLicenseStateStore(paths.StateStorePath), new LocalLicenseFileProvider(paths.LicenseFilePath), clock);

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = Environment.TickCount64 + 10_000;
        while (!condition())
        {
            Assert.True(Environment.TickCount64 < deadline, "Timed out waiting for the controlled runtime transition.");
            await Task.Delay(25);
        }
    }

    private sealed class ActivationFailureStore : ILicenseStateStore
    {
        private readonly InMemoryLicenseStateStore _inner = new();
        public LicenseStateRecord? Load() => _inner.Load();
        public void Save(LicenseStateRecord record)
        {
            if (record.ActivatedLicenseId is not null) throw new IOException("activation write unavailable");
            _inner.Save(record);
        }
    }
}
