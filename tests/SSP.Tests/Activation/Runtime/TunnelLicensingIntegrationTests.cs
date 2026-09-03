// File: tests/SSP.Tests/Activation/Runtime/TunnelLicensingIntegrationTests.cs
//
// §15 of the P3 hardening task: REAL SSP runtime behavior, not unit tests about
// a mock. Each test here stands up
//
//   a real signed license artifact on disk
//     -> the real SspActivationService composition (SspLicensePaths,
//        SspLicenseStateStore, LocalLicenseFileProvider, LicenseTrustAnchor over
//        an ephemeral authority key, controllable IClock)
//     -> the real production gate SspRuntimeLicense
//     -> a real ServerGateway listening on a real TCP port
//     -> a real ServerProtocol handling a real client handshake
//     -> a real ClientRuntime / ClientProtocol speaking the real wire protocol
//
// and then asserts what a client experiences: traffic flows when the license
// allows it, and the connection is refused when it does not.

using System.Net.Sockets;
using SSP.Activation;
using SSP.Client.Runtime;
using SSP.Core.Activation;
using SSP.Core.Crypto;
using SSP.Server.Activation;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation.Runtime;

public class TunnelLicensingIntegrationTests
{
    // ------------------------------------------------------------------
    // Fixture
    // ------------------------------------------------------------------

    private sealed class LicensedService : IAsyncDisposable
    {
        public LicensedService(
            LicensedTestEnvironment env,
            SspTestHarness harness,
            ClientRuntime enrolledRuntime)
        {
            Env = env;
            Harness = harness;
            EnrolledRuntime = enrolledRuntime;
        }

        public LicensedTestEnvironment Env { get; }
        public SspTestHarness Harness { get; }
        public ClientRuntime EnrolledRuntime { get; }
        public SspRuntimeLicense Gate => Env.Gate;

        /// <summary>Opens one authenticated future-authorization connection (and holds its tunnel slot).</summary>
        public async Task<TcpClient> OpenAuthenticatedConnectionAsync()
        {
            var protocol = new ClientProtocol(EnrolledRuntime);
            var (tcp, sessionKey) = await protocol.ConnectAndAuthenticateAsync();
            Assert.NotEmpty(sessionKey);
            return tcp;
        }

        public async ValueTask DisposeAsync()
        {
            // The gateway holds the gate, so the harness goes first.
            await Harness.DisposeAsync();
            Env.Dispose();
        }
    }

    /// <summary>
    /// Brings up a licensed service with one enrolled client. Enrollment itself
    /// is part of the protected runtime, so when the license denies the data
    /// plane the enrollment socket's session-key offer is refused too: the
    /// client is still stored server-side (its identity was authorized), it just
    /// gets no tunnel. <paramref name="expectEnrollmentTunnel"/> says which of
    /// the two outcomes the test expects.
    /// </summary>
    private static async Task<LicensedService> ArrangeAsync(
        LicensedTestOptions options,
        bool expectEnrollmentTunnel = true)
    {
        var env = LicensedTestEnvironment.Create(options);
        env.Load();

        var ott = TokenGenerator.GenerateOneTimeToken();
        var harness = await SspTestHarness.CreateWithExplicitTokenAsync(
            ott, options.ApplicationName, env.Gate);

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);

        try
        {
            await EnrollmentHelper.EnrollAsync(runtime);
        }
        catch (Exception) when (!expectEnrollmentTunnel)
        {
            // Expected: the server refused the session key on the enrollment
            // socket because the license does not permit a data plane.
        }

        var enrolled = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);

        // The enrollment socket also negotiated a session key (that is what
        // ClientProtocol.ConnectAndAuthenticateAsync does), so it briefly held a
        // licensed tunnel slot. Wait for the gateway to release it before the
        // measured part of the test starts, so limit assertions are exact.
        await WaitForTunnelsAsync(env.Gate, 0);

        return new LicensedService(env, harness, enrolled);
    }

    private static async Task WaitForTunnelsAsync(ISspLicenseGate gate, long expected, int timeoutMs = 10_000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (gate.ActiveTunnels != expected)
        {
            if (Environment.TickCount64 > deadline)
            {
                Assert.Fail($"Timed out waiting for ActiveTunnels to reach {expected}; it is {gate.ActiveTunnels}.");
            }

            await Task.Delay(25);
        }
    }

    // ------------------------------------------------------------------
    // Valid feature -> allowed
    // ------------------------------------------------------------------

    [Fact(Timeout = 60_000)]
    public async Task LicenseWithRdpFeature_RdpTunnelIsEstablished()
    {
        await using var svc = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[] { SspLicensing.Features.RemoteDesktopProtocol },
        });

        Assert.Equal(LicenseState.Valid, svc.Env.State);
        Assert.Equal(SspLicensing.Features.RemoteDesktopProtocol, svc.Gate.Feature);

        using var tcp = await svc.OpenAuthenticatedConnectionAsync();

        Assert.True(tcp.Connected);
        Assert.Equal(1L, svc.Gate.ActiveTunnels);
        Assert.Equal(1L, svc.Gate.ActiveSessions);
        Assert.Equal(1L, svc.Harness.Gateway.ActiveTunnels);

        // The slot is given back when the connection goes away.
        tcp.Dispose();
        await WaitForTunnelsAsync(svc.Gate, 0);
    }

    [Fact(Timeout = 60_000)]
    public async Task LicenseWithSshFeature_SshTunnelIsEstablished()
    {
        await using var svc = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "SSH",
            Features = new[] { SspLicensing.Features.SecureShell },
        });

        Assert.Equal(SspLicensing.Features.SecureShell, svc.Gate.Feature);
        using var tcp = await svc.OpenAuthenticatedConnectionAsync();
        Assert.True(tcp.Connected);
    }

    // ------------------------------------------------------------------
    // Wrong feature -> denied
    // ------------------------------------------------------------------

    [Fact(Timeout = 60_000)]
    public async Task LicenseWithoutRdpFeature_RdpTunnelIsDenied()
    {
        // The license is Valid but covers ssh/web only - the classic
        // "customer paid for the wrong protocol" case.
        await using var svc = await ArrangeAsync(
            new LicensedTestOptions
            {
                ApplicationName = "RDP",
                Features = new[]
                {
                    SspLicensing.Features.SecureShell,
                    SspLicensing.Features.Web,
                },
            },
            expectEnrollmentTunnel: false);

        Assert.Equal(LicenseState.Valid, svc.Env.State);
        Assert.Equal(SspLicensing.Features.RemoteDesktopProtocol, svc.Gate.Feature);

        // The client is enrolled (identity authorized) but no data plane may open.
        Assert.True(svc.EnrolledRuntime.IsEnrolled);

        var ex = await Assert.ThrowsAnyAsync<Exception>(() => svc.OpenAuthenticatedConnectionAsync());
        Assert.Contains("authorization failed", ex.Message, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(0L, svc.Gate.ActiveTunnels);
        Assert.Contains(
            svc.Env.Events.Snapshot(),
            e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied
                 && e.ReasonCode == LicenseReasons.FeatureNotLicensed);
    }

    [Fact(Timeout = 60_000)]
    public async Task EnrollmentSocket_CannotOpenADataPlane_WhenTheFeatureIsNotLicensed()
    {
        // §7: there must be no ALTERNATE path to an authenticated tunnel. The
        // enrollment flow also negotiates a session key, and ServerGateway
        // bridges whatever session key it gets back - so the enrollment socket
        // is gated by the same single choke point (ReceiveSessionKeyAsync).
        // ArrangeAsync already ran that enrollment with expectEnrollmentTunnel:
        // false; this test asserts the server-side outcome explicitly.
        await using var svc = await ArrangeAsync(
            new LicensedTestOptions
            {
                ApplicationName = "WEB",
                Features = new[] { SspLicensing.Features.RemoteDesktopProtocol },
            },
            expectEnrollmentTunnel: false);

        Assert.Equal(LicenseState.Valid, svc.Env.State);

        // No tunnel slot was ever reserved for the enrollment socket.
        Assert.Equal(0L, svc.Gate.ActiveTunnels);
        Assert.Equal(0L, svc.Gate.ActiveSessions);

        // And the feature denial is what stopped it, not a transport accident.
        Assert.Contains(
            svc.Env.Events.Snapshot(),
            e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied
                 && e.ReasonCode == LicenseReasons.FeatureNotLicensed);
    }

    // ------------------------------------------------------------------
    // Missing / invalid / expired license -> denied
    // ------------------------------------------------------------------

    [Fact(Timeout = 60_000)]
    public async Task MissingLicense_TunnelIsDenied()
    {
        var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            OmitLicenseFile = true,
        });
        using (env)
        {
            env.Load();
            Assert.Equal(LicenseState.Unknown, env.State);

            var ott = TokenGenerator.GenerateOneTimeToken();
            await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP", env.Gate);
            var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);

            // Enrollment cannot even start: max_clients is denied in the
            // Unknown state, and the One-Time Token is NOT consumed by a
            // licensing denial.
            var ex = await Assert.ThrowsAnyAsync<Exception>(() => EnrollmentHelper.EnrollAsync(runtime));
            Assert.NotNull(ex);

            Assert.Equal(0L, env.Gate.ActiveTunnels);
            Assert.Contains(
                env.Events.Snapshot(),
                e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied
                     && e.ReasonCode == LicenseReasons.LicenseNotValid);
        }
    }

    [Fact(Timeout = 60_000)]
    public async Task TamperedLicense_TunnelIsDenied()
    {
        var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            CorruptArtifact = true,
        });
        using (env)
        {
            Assert.False(env.Load().IsValid);
            Assert.Equal(LicenseState.LockedDown, env.State);

            var ott = TokenGenerator.GenerateOneTimeToken();
            await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP", env.Gate);
            var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);

            await Assert.ThrowsAnyAsync<Exception>(() => EnrollmentHelper.EnrollAsync(runtime));
            Assert.Equal(0L, env.Gate.ActiveTunnels);
        }
    }

    [Fact(Timeout = 60_000)]
    public async Task ExpiredLicense_TunnelIsDenied()
    {
        var now = LicensedTestOptions.DefaultNow;
        var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Now = now,
            NotBefore = now.AddDays(-30),
            IssuedAt = now.AddDays(-40),
            ExpiresAt = now.AddHours(-1),
        });
        using (env)
        {
            var result = env.Load();
            Assert.False(result.IsValid);
            Assert.Equal(LicenseReasons.Expired, result.ReasonCode);
            Assert.Equal(LicenseState.LockedDown, env.State);

            var ott = TokenGenerator.GenerateOneTimeToken();
            await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP", env.Gate);
            var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);

            await Assert.ThrowsAnyAsync<Exception>(() => EnrollmentHelper.EnrollAsync(runtime));
            Assert.Equal(0L, env.Gate.ActiveTunnels);
            Assert.False((await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config)).IsEnrolled);
        }
    }

    // ------------------------------------------------------------------
    // EP2 - concurrent tunnel limit
    // ------------------------------------------------------------------

    [Fact(Timeout = 90_000)]
    public async Task MaxConcurrentTunnels_NActive_ThenNPlusOneIsDenied_AndReleasedOnDisconnect()
    {
        const long limit = 2;

        await using var svc = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[] { SspLicensing.Features.RemoteDesktopProtocol },
            Limits = { [LicenseLimitNames.MaxConcurrentTunnels] = limit },
        });

        Assert.Equal(LicenseState.Valid, svc.Env.State);
        await WaitForTunnelsAsync(svc.Gate, 0);

        // Fill the licensed capacity.
        var held = new List<TcpClient>();
        try
        {
            for (long i = 0; i < limit; i++)
            {
                held.Add(await svc.OpenAuthenticatedConnectionAsync());
                Assert.Equal(i + 1, svc.Gate.ActiveTunnels);
            }

            Assert.Equal(limit, svc.Gate.ActiveTunnels);
            Assert.Equal(limit, svc.Gate.ActiveSessions);

            // N+1 must be refused, and must not consume a slot.
            await Assert.ThrowsAnyAsync<Exception>(() => svc.OpenAuthenticatedConnectionAsync());
            Assert.Equal(limit, svc.Gate.ActiveTunnels);

            Assert.Contains(
                svc.Env.Events.Snapshot(),
                e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied
                     && e.ReasonCode == LicenseReasons.LimitExceeded);
        }
        finally
        {
            foreach (var client in held)
            {
                client.Dispose();
            }
        }

        // Disconnecting gives the slots back, so the (limit+1)-th connection is
        // then admitted: the counter is a real reserve/release, not a latch.
        await WaitForTunnelsAsync(svc.Gate, 0);
        using var afterRelease = await svc.OpenAuthenticatedConnectionAsync();
        Assert.Equal(1L, svc.Gate.ActiveTunnels);
    }

    [Fact(Timeout = 60_000)]
    public async Task MaxConcurrentSessions_IsEnforcedOnTheSameAdmission()
    {
        // In SSP one authenticated data-plane connection is both the session and
        // the tunnel, so a license that constrains either one must be honored.
        await using var svc = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Limits = { [LicenseLimitNames.MaxConcurrentSessions] = 1 },
        });

        using var first = await svc.OpenAuthenticatedConnectionAsync();
        Assert.Equal(1L, svc.Gate.ActiveSessions);

        await Assert.ThrowsAnyAsync<Exception>(() => svc.OpenAuthenticatedConnectionAsync());
        Assert.Equal(1L, svc.Gate.ActiveSessions);
    }

    [Fact(Timeout = 60_000)]
    public async Task MaxClients_EnrollmentIsRefusedOnceTheLimitIsReached()
    {
        await using var svc = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Limits = { [LicenseLimitNames.MaxClients] = 1 },
        });

        // One client is already authorized (.index.dat holds exactly one entry),
        // so a second enrollment must be refused - and the refused enrollment
        // must not consume the second One-Time Token.
        var secondOtt = TokenGenerator.GenerateOneTimeToken();
        var serviceDir = svc.Harness.ServiceDir;
        var config = await SSP.Core.IO.ServiceConfigStore.LoadAsync(
            System.IO.Path.Combine(serviceDir, ".cache.dat"));
        config.PendingOneTimeTokens.Add(new SSP.Core.Models.PendingOneTimeToken
        {
            ClientName = "Client02",
            OneTimeTokenHash = TokenGenerator.HashOneTimeToken(secondOtt),
            CreatedAtUtc = DateTime.UtcNow.ToString("o"),
        });
        await SSP.Core.IO.ServiceConfigStore.SaveAsync(
            System.IO.Path.Combine(serviceDir, ".cache.dat"), config);

        var (secondRuntime, secondDir) = await svc.Harness.CreateClientRuntimeAsync(secondOtt);
        await Assert.ThrowsAnyAsync<Exception>(() => EnrollmentHelper.EnrollAsync(secondRuntime));

        var reloaded = await ClientRuntime.LoadOrCreateAsync(secondDir, secondRuntime.Config);
        Assert.False(reloaded.IsEnrolled);

        Assert.Contains(
            svc.Env.Events.Snapshot(),
            e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied
                 && e.ReasonCode == LicenseReasons.LimitExceeded);
    }

    // ------------------------------------------------------------------
    // §9 - lockdown propagation into the live runtime
    // ------------------------------------------------------------------

    [Fact(Timeout = 90_000)]
    public async Task LockdownAfterStartup_DeniesSubsequentTunnels_WithoutARestart()
    {
        var now = LicensedTestOptions.DefaultNow;
        await using var svc = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Now = now,
            NotBefore = now.AddDays(-1),
            IssuedAt = now.AddDays(-2),
            ExpiresAt = now.AddHours(1),
        });

        // Licensed: a tunnel works.
        using (var allowed = await svc.OpenAuthenticatedConnectionAsync())
        {
            Assert.True(allowed.Connected);
        }

        await WaitForTunnelsAsync(svc.Gate, 0);

        // The license expires while the service keeps running. The periodic
        // refresh (or any reload) moves the runtime to LockedDown.
        svc.Env.Clock.Advance(TimeSpan.FromHours(2));
        Assert.False(svc.Env.Reload().IsValid);
        Assert.Equal(LicenseState.LockedDown, svc.Env.State);

        // No cached "isLicensed" flag anywhere: the very next connection is
        // refused by the same gateway process that just served one.
        await Assert.ThrowsAnyAsync<Exception>(() => svc.OpenAuthenticatedConnectionAsync());
        Assert.Equal(0L, svc.Gate.ActiveTunnels);
    }

    [Fact(Timeout = 90_000)]
    public async Task RecoveryAfterLockdown_AllowsTunnelsAgain_WithoutARestart()
    {
        var now = LicensedTestOptions.DefaultNow;
        await using var svc = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Now = now,
            NotBefore = now.AddDays(-1),
            IssuedAt = now.AddDays(-2),
            ExpiresAt = now.AddHours(1),
        });

        svc.Env.Clock.Advance(TimeSpan.FromHours(2));
        Assert.False(svc.Env.Reload().IsValid);
        Assert.Equal(LicenseState.LockedDown, svc.Env.State);
        await Assert.ThrowsAnyAsync<Exception>(() => svc.OpenAuthenticatedConnectionAsync());

        // Operator installs a renewed artifact; the periodic refresh picks it up.
        Assert.True(svc.Env.InstallRenewal().IsValid);
        Assert.Equal(LicenseState.Valid, svc.Env.State);

        using var recovered = await svc.OpenAuthenticatedConnectionAsync();
        Assert.True(recovered.Connected);
        Assert.Equal(1L, svc.Gate.ActiveTunnels);
    }

    // ------------------------------------------------------------------
    // §13 - connection identity isolation under licensing
    // ------------------------------------------------------------------

    [Fact(Timeout = 90_000)]
    public async Task TwoServicesInOneProcess_HaveIndependentLicensingAndCounters()
    {
        // ServerA/RDP and ServerA/WEB are independent SSP connection identities.
        // Each service process owns its own gate, its own license evaluation and
        // its own usage counters: exhausting or locking down one must not
        // authorize or deny the other.
        await using var rdp = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[] { SspLicensing.Features.RemoteDesktopProtocol },
            Limits = { [LicenseLimitNames.MaxConcurrentTunnels] = 1 },
        });

        var webEnv = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "WEB",
            Features = new[] { SspLicensing.Features.Web },
            Limits = { [LicenseLimitNames.MaxConcurrentTunnels] = 1 },
        });
        using (webEnv)
        {
            webEnv.Load();
            Assert.Equal(LicenseState.Valid, webEnv.State);

            var webOtt = TokenGenerator.GenerateOneTimeToken();
            await using var webHarness = await SspTestHarness.CreateWithExplicitTokenAsync(
                webOtt, "WEB", webEnv.Gate);
            var (webRuntime, webClientDir) = await webHarness.CreateClientRuntimeAsync(webOtt);
            await EnrollmentHelper.EnrollAsync(webRuntime);
            var webEnrolled = await ClientRuntime.LoadOrCreateAsync(webClientDir, webRuntime.Config);
            await WaitForTunnelsAsync(webEnv.Gate, 0);

            // Exhaust the RDP license slot.
            using var rdpTunnel = await rdp.OpenAuthenticatedConnectionAsync();
            Assert.Equal(1L, rdp.Gate.ActiveTunnels);
            Assert.Equal(0L, webEnv.Gate.ActiveTunnels);

            // The WEB service is unaffected: its own license still admits a tunnel.
            var webProtocol = new ClientProtocol(webEnrolled);
            var (webTcp, webSessionKey) = await webProtocol.ConnectAndAuthenticateAsync();
            using (webTcp)
            {
                Assert.NotEmpty(webSessionKey);
                Assert.Equal(1L, webEnv.Gate.ActiveTunnels);
                Assert.Equal(1L, rdp.Gate.ActiveTunnels);
            }

            // RDP is still at its limit, and the WEB connection did not consume
            // RDP's slot (no cross-connection authorization bleed).
            await Assert.ThrowsAnyAsync<Exception>(() => rdp.OpenAuthenticatedConnectionAsync());
        }
    }

    [Fact(Timeout = 60_000)]
    public async Task LockingDownOneService_DoesNotAffectAnotherServiceInSameProcess()
    {
        await using var rdp = await ArrangeAsync(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[] { SspLicensing.Features.RemoteDesktopProtocol },
        });

        var sqlEnv = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "SQL",
            Features = new[] { SspLicensing.Features.Sql },
        });
        using (sqlEnv)
        {
            sqlEnv.Load();
            Assert.Equal(LicenseState.Valid, sqlEnv.State);

            // Lock the RDP service down by expiring its license.
            // .NET 8 has no TimeSpan.FromYears; the test's default license is
            // valid for 365 days from the test clock, so advancing by a fixed
            // 5 * 365 days is deterministically far past expiry and avoids any
            // leap-year/calendar-boundary dependence.
            rdp.Env.Clock.Advance(TimeSpan.FromDays(365 * 5));
            Assert.False(rdp.Env.Reload().IsValid);
            Assert.Equal(LicenseState.LockedDown, rdp.Env.State);
            Assert.False(rdp.Gate.AdmitTunnel().IsAdmitted);

            // The SQL service has its own license, its own clock reading and its
            // own state: it is still Valid and still admits tunnels.
            Assert.Equal(LicenseState.Valid, sqlEnv.State);
            using var sqlAdmission = sqlEnv.Gate.AdmitTunnel();
            Assert.True(sqlAdmission.IsAdmitted);
        }
    }

    // ------------------------------------------------------------------
    // The test seam itself must be explicit and observable
    // ------------------------------------------------------------------

    [Fact(Timeout = 60_000)]
    public async Task UnlicensedTestGate_IsConsultedOnTheRealRuntimePath()
    {
        // Proves the seam is a gate that the runtime actually calls (so a test
        // using it is exercising the same code path as production, with a
        // different answer), and that the runtime never bypasses it.
        var gate = new UnlicensedTestGate();
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP", gate);
        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);
        var enrolled = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);
        await WaitForTunnelsAsync(gate, 0);

        var protocol = new ClientProtocol(enrolled);
        var (tcp, _) = await protocol.ConnectAndAuthenticateAsync();
        using (tcp)
        {
            Assert.Equal(1L, gate.ActiveTunnels);
        }

        await WaitForTunnelsAsync(gate, 0);
        Assert.Contains(gate.Calls, c => c.StartsWith(nameof(UnlicensedTestGate.CanEnrollClient), StringComparison.Ordinal));
        Assert.Contains(gate.Calls, c => c == nameof(UnlicensedTestGate.AdmitTunnel));
        Assert.True(gate.AdmittedTunnels >= 2, "enrollment socket + future-auth socket each admit one tunnel");
    }
}
