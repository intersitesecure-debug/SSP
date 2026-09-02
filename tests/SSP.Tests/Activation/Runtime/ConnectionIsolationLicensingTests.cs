// File: tests/SSP.Tests/Activation/Runtime/ConnectionIsolationLicensingTests.cs
//
// §13 of the P3 hardening task: SSP connection identities are per
// Server/Service/Client triple - ServerA/RDP and ServerA/WEB are different
// connections - and licensing must respect that boundary.
//
// Two things are shared and two are not:
//
//   SHARED   the signed license artifact and the encrypted anti-rollback floor
//            (one machine, one authority, one installation identity);
//   SHARED   the trust anchor and the installation identity;
//   NOT      the licensing state machine (each protected service process owns
//            its own LicenseManager, so one process's transition is observed by
//            another only through the artifact on disk, never through a cached
//            verdict);
//   NOT      the usage counters (a WEB tunnel must never consume an RDP slot).

using System.Collections.Concurrent;
using System.Reflection;
using SSP.Activation;
using SSP.Client.Runtime;
using SSP.Core.Activation;
using SSP.Core.Crypto;
using SSP.Server.Activation;
using SSP.Server.Runtime;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation.Runtime;

public class ConnectionIsolationLicensingTests
{
    [Fact]
    public void TwoServiceProcessesOnOneHost_ShareTheArtifact_ButNotTheUsageCounters()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[]
            {
                SspLicensing.Features.RemoteDesktopProtocol,
                SspLicensing.Features.Web,
            },
            Limits = { [LicenseLimitNames.MaxConcurrentTunnels] = 1 },
        });
        Assert.True(env.Load().IsValid);

        using var webGate = env.CreateAdditionalServiceGate("WEB");
        Assert.True(webGate.Reload().IsValid);

        Assert.Equal(SspLicensing.Features.RemoteDesktopProtocol, env.Gate.Feature);
        Assert.Equal(SspLicensing.Features.Web, webGate.Feature);

        // Each service reserves against ITS OWN counter, so a single licensed
        // tunnel slot per service is not a single slot per machine.
        using var rdpTunnel = env.Gate.AdmitTunnel();
        using var webTunnel = webGate.AdmitTunnel();

        Assert.True(rdpTunnel.IsAdmitted);
        Assert.True(webTunnel.IsAdmitted);

        // Each service counts only its own tunnels/sessions.
        Assert.Equal(1L, env.Gate.ActiveTunnels);
        Assert.Equal(1L, env.Gate.ActiveSessions);
        Assert.Equal(1L, webGate.ActiveTunnels);
        Assert.Equal(1L, webGate.ActiveSessions);

        // And each is now at ITS OWN limit: a second RDP tunnel is refused
        // without touching the WEB service's counter.
        var secondRdp = env.Gate.AdmitTunnel();
        Assert.False(secondRdp.IsAdmitted);
        Assert.Equal(LicenseReasons.LimitExceeded, secondRdp.ReasonCode);
        Assert.Equal(1L, webGate.ActiveTunnels);
    }

    [Fact]
    public void FeatureIdentityIsPerConnection_NotPerMachine()
    {
        // One artifact licensing RDP only. Two services in the same process read
        // the same artifact; the WEB service must still be refused, because the
        // feature identity belongs to the connection being protected.
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[] { SspLicensing.Features.RemoteDesktopProtocol },
        });
        Assert.True(env.Load().IsValid);

        using var webGate = env.CreateAdditionalServiceGate("WEB");
        using var sshGate = env.CreateAdditionalServiceGate("SSH");
        Assert.True(webGate.Reload().IsValid);

        Assert.Equal(LicenseState.Valid, env.State);
        Assert.True(env.Gate.CanUseServiceFeature().IsAllowed);

        Assert.Equal(LicenseState.Valid, webGate.CurrentState);
        var webDecision = webGate.CanUseServiceFeature();
        Assert.False(webDecision.IsAllowed);
        Assert.Equal(LicenseReasons.FeatureNotLicensed, webDecision.ReasonCode);

        // SSH is a third connection on the same host and the same artifact: it
        // is Valid, and still refused for its own feature identity.
        Assert.True(sshGate.Reload().IsValid);
        Assert.Equal(LicenseState.Valid, sshGate.CurrentState);
        Assert.Equal(LicenseReasons.FeatureNotLicensed, sshGate.CanUseServiceFeature().ReasonCode);
        Assert.False(sshGate.CanUseServiceFeature().IsAllowed);

        // And a Valid license for another connection never widens the denied one.
        Assert.False(webGate.AdmitTunnel().IsAdmitted);
        using var rdpAdmission = env.Gate.AdmitTunnel();
        Assert.True(rdpAdmission.IsAdmitted);
    }

    [Fact]
    public void AnExpiredArtifact_IsSeenByEveryServiceProcessOnTheHost_AfterItsOwnRefresh()
    {
        var now = LicensedTestOptions.DefaultNow;
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Now = now,
            NotBefore = now.AddDays(-1),
            IssuedAt = now.AddDays(-2),
            ExpiresAt = now.AddHours(1),
            Features = new[]
            {
                SspLicensing.Features.RemoteDesktopProtocol,
                SspLicensing.Features.Web,
            },
        });
        Assert.True(env.Load().IsValid);

        using var webGate = env.CreateAdditionalServiceGate("WEB");
        Assert.True(webGate.Reload().IsValid);

        env.Clock.Advance(TimeSpan.FromHours(2));

        // The RDP service refreshes first and locks down.
        Assert.False(env.Reload().IsValid);
        Assert.Equal(LicenseState.LockedDown, env.State);
        Assert.False(env.Gate.AdmitTunnel().IsAdmitted);

        // The WEB service has its own state machine: it is still serving on the
        // last verdict it loaded, which is exactly why no cached verdict may
        // exist and why the periodic refresh is mandatory in production.
        Assert.Equal(LicenseState.Valid, webGate.CurrentState);

        // Its own refresh reads the same artifact and reaches the same answer.
        Assert.False(webGate.Reload().IsValid);
        Assert.Equal(LicenseState.LockedDown, webGate.CurrentState);
        Assert.False(webGate.AdmitTunnel().IsAdmitted);
        Assert.False(webGate.CanUseServiceFeature().IsAllowed);
    }

    [Fact(Timeout = 90_000)]
    public async Task EnrollmentLockIsScopedPerServiceDirectory_AndALicensingDenialReleasesIt()
    {
        // EP2 measures max_clients inside the per-service enrollment lock, so
        // the check and the commit to .index.dat are serialized per service and
        // never across services. A licensing denial must leave that lock exactly
        // as it found it: a denial that leaked the semaphore would turn one
        // refused enrollment into a permanent hang for every later client.
        await using var rdp = await ArrangeAsync("RDP", new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Limits = { [LicenseLimitNames.MaxClients] = 1 },
        });
        await using var web = await ArrangeAsync("WEB", new LicensedTestOptions
        {
            ApplicationName = "WEB",
        });

        var locks = ReadEnrollmentLocks();

        Assert.True(locks.ContainsKey(Path.GetFullPath(rdp.Harness.ServiceDir)),
            "the RDP service directory must own its enrollment lock");
        Assert.True(locks.ContainsKey(Path.GetFullPath(web.Harness.ServiceDir)),
            "the WEB service directory must own its enrollment lock");
        Assert.NotSame(
            locks[Path.GetFullPath(rdp.Harness.ServiceDir)],
            locks[Path.GetFullPath(web.Harness.ServiceDir)]);

        // A second RDP client is refused by max_clients ...
        await Assert.ThrowsAnyAsync<Exception>(() => EnrollSecondClientAsync(rdp));

        // ... and the lock is released, so the RDP service is still answering
        // enrollments (with a licensing denial) rather than hanging.
        Assert.Equal(1, locks[Path.GetFullPath(rdp.Harness.ServiceDir)].CurrentCount);
        Assert.Equal(1, locks[Path.GetFullPath(web.Harness.ServiceDir)].CurrentCount);

        var secondDenialTask = EnrollSecondClientAsync(rdp);
        var completed = await Task.WhenAny(secondDenialTask, Task.Delay(15_000));
        Assert.Same(secondDenialTask, completed);
        await Assert.ThrowsAnyAsync<Exception>(() => secondDenialTask);

        Assert.Equal(1, locks[Path.GetFullPath(rdp.Harness.ServiceDir)].CurrentCount);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private sealed class LicensedService : IAsyncDisposable
    {
        public LicensedService(LicensedTestEnvironment env, SspTestHarness harness)
        {
            Env = env;
            Harness = harness;
        }

        public LicensedTestEnvironment Env { get; }
        public SspTestHarness Harness { get; }

        public async ValueTask DisposeAsync()
        {
            await Harness.DisposeAsync();
            Env.Dispose();
        }
    }

    private static async Task<LicensedService> ArrangeAsync(string appName, LicensedTestOptions options)
    {
        var env = LicensedTestEnvironment.Create(options);
        env.Load();

        var ott = TokenGenerator.GenerateOneTimeToken();
        var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, appName, env.Gate);
        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        return new LicensedService(env, harness);
    }

    /// <summary>Provisions and runs a second client enrollment against a service.</summary>
    private static async Task EnrollSecondClientAsync(LicensedService service)
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        var cachePath = Path.Combine(service.Harness.ServiceDir, ".cache.dat");
        var config = await SSP.Core.IO.ServiceConfigStore.LoadAsync(cachePath);
        config.PendingOneTimeTokens.Add(new SSP.Core.Models.PendingOneTimeToken
        {
            ClientName = "Client-" + Guid.NewGuid().ToString("N")[..6],
            OneTimeTokenHash = TokenGenerator.HashOneTimeToken(ott),
            CreatedAtUtc = DateTime.UtcNow.ToString("o"),
        });
        await SSP.Core.IO.ServiceConfigStore.SaveAsync(cachePath, config);

        var (runtime, clientDir) = await service.Harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);
    }

    private static ConcurrentDictionary<string, SemaphoreSlim> ReadEnrollmentLocks()
    {
        var field = typeof(ServerProtocol).GetField(
            "EnrollmentLocks", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);
        return (ConcurrentDictionary<string, SemaphoreSlim>)field!.GetValue(null)!;
    }
}
