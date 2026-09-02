// File: tests/SSP.Tests/Activation/Runtime/LicensingCompositionTests.cs
//
// §17 of the P3 hardening task, dedicated to the question that broke the first
// integration: "what happens in PRODUCTION when there is no enforcement?"
//
// The answer these tests lock in is structural, not behavioural-by-hope:
//
//   * SSP runtime components cannot be constructed without a license gate. The
//     parameter is mandatory and non-nullable, so `enforcement: null` is not a
//     representable production composition (§3).
//   * The only production factory for a gate, SspRuntimeLicense.CreateForService,
//     throws instead of returning an unlicensed gate when the build has no
//     compiled-in trust anchor. An empty anchor therefore fails CLOSED (§11).
//   * No component caches a licensing verdict, so Valid -> LockedDown is seen by
//     the very next protected operation (§9).
//   * Composition never starts background work; the single revalidation loop is
//     explicit, idempotent, non-overlapping and joined on Dispose (§8).

using System.Reflection;
using SSP.Activation;
using SSP.Core.Activation;
using SSP.Core.Models;
using SSP.Server.Activation;
using SSP.Server.Runtime;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation.Runtime;

public class LicensingCompositionTests
{
    private static readonly NullabilityInfoContext Nullability = new();

    // ------------------------------------------------------------------
    // §3 / §17 - "no enforcement" is not representable in production
    // ------------------------------------------------------------------

    [Fact]
    public void ServerGateway_RefusesToRunWithoutALicenseGate()
    {
        var config = new ServiceConfig { ApplicationName = "RDP", WindowsServiceName = "SSP Test RDP" };
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var pem = SSP.Core.Crypto.RsaCrypto.ExportPublicKeyPem(rsa);

        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ServerGateway(config, rsa, pem, Path.GetTempPath(), null!));

        Assert.Equal("license", ex.ParamName);
        Assert.Contains("licensing gate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ServerProtocol_RefusesToRunWithoutALicenseGate()
    {
        var config = new ServiceConfig { ApplicationName = "RDP", WindowsServiceName = "SSP Test RDP" };
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var pem = SSP.Core.Crypto.RsaCrypto.ExportPublicKeyPem(rsa);

        var ex = Assert.Throws<ArgumentNullException>(() =>
            new ServerProtocol(config, rsa, pem, Path.GetTempPath(), null!));

        Assert.Equal("license", ex.ParamName);
        Assert.Contains("licensing gate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The structural guarantee behind the two tests above: every constructor of
    /// the protected runtime components takes exactly one <see cref="ISspLicenseGate"/>
    /// that is non-nullable and has no default value. A future overload that
    /// makes the gate optional (the exact shape of the original defect) fails
    /// this test at build-review time rather than shipping a fail-open path.
    /// </summary>
    [Theory]
    [InlineData(typeof(ServerGateway))]
    [InlineData(typeof(ServerProtocol))]
    public void ProtectedRuntimeComponents_HaveNoConstructorWithoutAMandatoryGate(Type component)
    {
        var constructors = component.GetConstructors(
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotEmpty(constructors);

        foreach (var ctor in constructors)
        {
            var gateParameters = ctor.GetParameters()
                .Where(p => p.ParameterType == typeof(ISspLicenseGate))
                .ToArray();

            Assert.Single(gateParameters);

            var gate = gateParameters[0];
            Assert.False(gate.HasDefaultValue,
                $"{component.Name} must not give the license gate a default value.");
            Assert.False(gate.IsOptional,
                $"{component.Name} must not make the license gate optional.");
            Assert.Equal(NullabilityState.NotNull, Nullability.Create(gate).ReadState);
        }
    }

    /// <summary>
    /// §9's structural guarantee: no runtime component may hold a cached
    /// licensing verdict. The only permissible cached licensing value is the
    /// feature identity (an immutable property of the protected application, not
    /// of the license state) and the usage counters.
    /// </summary>
    [Theory]
    [InlineData(typeof(ServerGateway))]
    [InlineData(typeof(ServerProtocol))]
    [InlineData(typeof(SspRuntimeLicense))]
    [InlineData(typeof(SSP.Server.ServiceHost.SspWindowsService))]
    public void NoRuntimeComponent_CachesALicensingVerdict(Type component)
    {
        var forbidden = new[]
        {
            "islicensed", "licensed", "licensevalid", "licenseok", "haslicense",
            "enforcementpresent", "enforcementavailable", "licensechecked",
            "activationok", "validlicense", "licensingenabled",
        };

        var suspects = component
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(bool))
            .Select(f => f.Name)
            .Concat(component
                .GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
                .Where(p => p.PropertyType == typeof(bool))
                .Select(p => p.Name))
            .Where(name => forbidden.Contains(
                name.TrimStart('_').Replace("s_", string.Empty, StringComparison.Ordinal).ToLowerInvariant(),
                StringComparer.Ordinal))
            .ToArray();

        Assert.Empty(suspects);
    }

    [Fact]
    public void SspRuntimeLicense_RequiresAnActivationService()
    {
        Assert.Throws<ArgumentNullException>(() => new SspRuntimeLicense(null!, SspLicensing.Features.RemoteDesktopProtocol));
    }

    // ------------------------------------------------------------------
    // §11 / §17 - the production path with no licensing fails closed
    // ------------------------------------------------------------------

    /// <summary>
    /// THE dedicated §17 test. This build ships an empty trust anchor
    /// (documented release blocker, §11). With no root of trust, no artifact can
    /// ever validate, so the production factory must refuse to hand out a gate at
    /// all - and it must say why. The alternative (returning a gate whose
    /// decisions silently allow) is precisely the fail-open defect this task
    /// exists to remove.
    /// </summary>
    [Fact]
    public void ProductionServiceStart_FailsClosed_WhenNoTrustAnchorIsCompiledIn()
    {
        Assert.False(SspTrustAnchor.IsCompiledIn,
            "If a real authority key has been compiled in, this test's premise has changed: " +
            "rewrite it to assert that CreateForService still refuses without a valid license.");

        var config = new ServiceConfig { ApplicationName = "RDP", WindowsServiceName = "SSP Test RDP" };

        var ex = Assert.Throws<SspActivationException>(() => SspRuntimeLicense.CreateForService(config));

        Assert.Equal(SspActivationException.TrustAnchorMissingReason, ex.ReasonCode);
        Assert.Contains("trust anchor", ex.Message, StringComparison.OrdinalIgnoreCase);

        // A refused composition must not leak a half-built gate: the anchor
        // itself refuses to exist in this build.
        Assert.Throws<InvalidOperationException>(() => SspTrustAnchor.Create());
    }

    /// <summary>
    /// Provisioning is allowed to run without licensing knowledge - it creates
    /// directories and keys, not tunnels - but it must say so loudly and must
    /// return null rather than a gate that appears to authorize.
    /// </summary>
    [Fact]
    public void ProvisioningWithoutATrustAnchor_ReturnsNull_Loudly_AndNeverAGate()
    {
        Assert.Null(SspRuntimeLicense.TryCreateForProvisioning("RDP"));
    }

    /// <summary>
    /// Even when the licensing runtime composes, an absent license file is a
    /// hard stop for the service-start authorization: EP1 must refuse.
    /// </summary>
    [Fact]
    public void ServiceStartAuthorization_RefusesWithoutAValidLicense()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            OmitLicenseFile = true,
        });

        var config = new ServiceConfig { ApplicationName = "RDP", WindowsServiceName = "SSP Test RDP" };

        var ex = Assert.Throws<SspActivationException>(() => env.Gate.AuthorizeServiceStart(config));
        Assert.NotEqual(SspActivationException.TrustAnchorMissingReason, ex.ReasonCode);
        Assert.Equal(LicenseState.Unknown, env.State);
    }

    /// <summary>
    /// EP1 also refuses when the license is Valid but does not cover this
    /// service's protocol, or when max_services is exhausted - i.e. a Valid
    /// license is necessary but not sufficient.
    /// </summary>
    [Fact]
    public void ServiceStartAuthorization_RefusesAnUnlicensedFeature_AndAnExhaustedServiceLimit()
    {
        using var wrongFeature = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[] { SspLicensing.Features.Web },
        });
        wrongFeature.Load();
        Assert.Equal(LicenseState.Valid, wrongFeature.State);

        var rdpConfig = new ServiceConfig { ApplicationName = "RDP", WindowsServiceName = "SSP Test RDP" };
        var featureEx = Assert.Throws<SspActivationException>(
            () => wrongFeature.Gate.AuthorizeServiceStart(rdpConfig));
        Assert.Equal(LicenseReasons.FeatureNotLicensed, featureEx.ReasonCode);

        using var limitReached = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Limits = { [LicenseLimitNames.MaxServices] = 0 },
        });
        limitReached.Load();
        Assert.Equal(LicenseState.Valid, limitReached.State);

        var limitEx = Assert.Throws<SspActivationException>(
            () => limitReached.Gate.AuthorizeServiceStart(rdpConfig));
        Assert.Equal(LicenseReasons.LimitExceeded, limitEx.ReasonCode);
    }

    // ------------------------------------------------------------------
    // §8 - the single revalidation loop
    // ------------------------------------------------------------------

    [Fact]
    public void Composition_NeverStartsBackgroundWork()
    {
        using var env = LicensedTestEnvironment.Create();

        Assert.False(env.Activation.IsRevalidationTimerRunning);
        env.Load();
        Assert.False(env.Activation.IsRevalidationTimerRunning);
        env.Gate.AdmitTunnel().Dispose();
        Assert.False(env.Activation.IsRevalidationTimerRunning);
    }

    [Fact]
    public void RevalidationTimer_IsExplicitIdempotentAndRejectsNonPositiveIntervals()
    {
        using var env = LicensedTestEnvironment.Create();
        env.Load();

        Assert.Throws<ArgumentOutOfRangeException>(() => env.Activation.StartRevalidationTimer(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => env.Activation.StartRevalidationTimer(TimeSpan.FromSeconds(-1)));
        Assert.False(env.Activation.IsRevalidationTimerRunning);

        env.Activation.StartRevalidationTimer(TimeSpan.FromMinutes(30));
        Assert.True(env.Activation.IsRevalidationTimerRunning);

        // Idempotent: a second start must not create a second loop.
        env.Activation.StartRevalidationTimer(TimeSpan.FromMinutes(1));
        Assert.True(env.Activation.IsRevalidationTimerRunning);

        env.Activation.Dispose();
        Assert.False(env.Activation.IsRevalidationTimerRunning);

        // After shutdown the timer cannot be restarted on a disposed service.
        Assert.Throws<ObjectDisposedException>(() => env.Activation.StartRevalidationTimer(TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public async Task RevalidationTimer_DetectsExpiry_AtRuntime_AndPropagatesTheLockdown()
    {
        var now = LicensedTestOptions.DefaultNow;
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Now = now,
            NotBefore = now.AddDays(-1),
            IssuedAt = now.AddDays(-2),
            ExpiresAt = now.AddMinutes(5),
        });

        Assert.True(env.Load().IsValid);
        Assert.Equal(LicenseState.Valid, env.State);
        using (var admitted = env.Gate.AdmitTunnel())
        {
            Assert.True(admitted.IsAdmitted);
        }

        env.Activation.StartRevalidationTimer(TimeSpan.FromMilliseconds(50));
        try
        {
            // The license expires while the service keeps running. Nobody calls
            // Reload() here: only the owned background loop does.
            env.Clock.Advance(TimeSpan.FromMinutes(10));

            await WaitForStateAsync(env, LicenseState.LockedDown);

            // No cached verdict survived the transition.
            Assert.False(env.Gate.AdmitTunnel().IsAdmitted);
            Assert.False(env.Gate.CanStartProtectedService(0).IsAllowed);
            Assert.False(env.Gate.CanEnrollClient(0).IsAllowed);
        }
        finally
        {
            env.Activation.Dispose();
        }

        Assert.False(env.Activation.IsRevalidationTimerRunning);
    }

    [Fact]
    public async Task RevalidationTimer_DetectsAnInstalledRenewal_AndClearsTheLockdown()
    {
        var now = LicensedTestOptions.DefaultNow;
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Now = now,
            NotBefore = now.AddDays(-1),
            IssuedAt = now.AddDays(-2),
            ExpiresAt = now.AddMinutes(5),
        });

        Assert.True(env.Load().IsValid);
        env.Clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False(env.Reload().IsValid);
        Assert.Equal(LicenseState.LockedDown, env.State);

        env.Activation.StartRevalidationTimer(TimeSpan.FromMilliseconds(50));
        try
        {
            // The operator installs a renewed artifact. The loop must notice it
            // by re-reading the provider (Load, not Revalidate) - a lockdown is
            // only ever cleared by loading a valid artifact.
            env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
            {
                ApplicationName = "RDP",
                Now = env.Clock.UtcNow,
                NotBefore = env.Clock.UtcNow.AddMinutes(-1),
                IssuedAt = env.Clock.UtcNow,
                ExpiresAt = env.Clock.UtcNow.AddDays(365),
                SequenceNumber = 9999,
            }));

            await WaitForStateAsync(env, LicenseState.Valid);

            using var admitted = env.Gate.AdmitTunnel();
            Assert.True(admitted.IsAdmitted);
            Assert.Contains(
                env.Events.Snapshot(),
                e => e.EventType == LicenseSecurityEventType.LicenseLockdownCleared);
        }
        finally
        {
            env.Activation.Dispose();
        }
    }

    /// <summary>
    /// A background refresh that throws (unreadable provider, transient I/O
    /// failure) must not fault the owned loop, must not stop later refreshes and
    /// must never widen authorization: the manager keeps its last authoritative
    /// state and the gates keep denying.
    /// </summary>
    [Fact]
    public async Task RevalidationTimer_SurvivesAProviderFailure_WithoutFailingOpen()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { OmitLicenseFile = true });
        Assert.False(env.Load().IsValid);

        var failures = new FailingProvider(env.LicenseFilePath);
        using var activation = SspActivationService.Compose(
            env.Paths,
            LicenseTrustAnchor.FromPublicKey(System.Security.Cryptography.RSA.Create(2048)),
            new StaticInstallationIdentityProvider(null),
            env.Events,
            env.StateStore,
            failures,
            env.Clock);
        using var gate = new SspRuntimeLicense(activation, SspLicensing.Features.RemoteDesktopProtocol);

        Assert.False(activation.Load().IsValid);

        activation.StartRevalidationTimer(TimeSpan.FromMilliseconds(25));
        await Task.Delay(300);

        // Asserted while the runtime is still alive: Dispose also disposes the
        // trust anchor, so a post-dispose decision would be testing disposal
        // rather than fail-closed licensing.
        Assert.True(failures.Calls >= 2, $"the loop stopped after {failures.Calls} refresh(es)");
        Assert.False(gate.AdmitTunnel().IsAdmitted);
        Assert.False(gate.CanStartProtectedService(0).IsAllowed);

        activation.Dispose();
        Assert.False(activation.IsRevalidationTimerRunning);
    }

    // ------------------------------------------------------------------
    // §10 - the license artifact and state store on disk
    // ------------------------------------------------------------------

    [Fact]
    public void LicenseArtifact_IsPublicSignedMaterial_AndTheStateStoreHoldsNoSecrets()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            UseDurableStateStore = true,
        });
        Assert.True(env.Load().IsValid);

        var artifact = File.ReadAllText(env.LicenseFilePath);
        Assert.Contains("\"signature\"", artifact, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", artifact, StringComparison.Ordinal);

        // The anti-rollback floor is persisted through the production encrypted
        // store (.license-state.dat is on ProtectedFileStore's protected-name
        // list), so the record is not readable as plaintext on disk and carries
        // no key material - only sequence/license identity.
        Assert.True(File.Exists(env.StateStorePath));
        var stored = System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(env.StateStorePath));
        Assert.DoesNotContain("PRIVATE KEY", stored, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HighestAcceptedSequenceNumber", stored, StringComparison.Ordinal);
        Assert.True(SSP.Core.IO.ProtectedFileStore.HasEncryptedEnvelope(File.ReadAllBytes(env.StateStorePath)),
            "the anti-rollback store must be written in the SSP encrypted-at-rest envelope");

        var record = env.StateStore.Load();
        Assert.NotNull(record);
        Assert.Equal(1L, record!.HighestAcceptedSequenceNumber);
    }

    [Fact]
    public void LicenseFileWritesAreAtomic_NoPartialArtifactIsEverLeftReadable()
    {
        using var env = LicensedTestEnvironment.Create();
        Assert.True(env.Load().IsValid);

        // Rewriting the artifact must leave either the old or the new complete
        // file - never a truncated one that a validator might mistake for a
        // different license.
        for (var i = 0; i < 5; i++)
        {
            env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
            {
                SequenceNumber = 10 + i,
            }));

            var result = env.Reload();
            Assert.True(result.IsValid, $"rewrite {i} left an unreadable artifact: {result.ReasonCode}");
        }

        Assert.Equal(14L, env.StateStore.Load()!.HighestAcceptedSequenceNumber);
    }

    // ------------------------------------------------------------------
    // §14 - security events carry no secrets
    // ------------------------------------------------------------------

    [Fact]
    public void SecurityEvents_NeverContainKeyMaterialOrArtifactContent()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            // The production provider hashes the raw MachineGuid with a purpose
            // tag, so an event can only ever carry the derived identifier. This
            // test uses the derived form and asserts the raw source never leaks.
            HostInstallationId = SspInstallationIdentityProvider.ComputeInstallationId(RawMachineGuid),
            InstallationId = SspInstallationIdentityProvider.ComputeInstallationId(RawMachineGuid),
        });

        Assert.True(env.Load().IsValid);
        env.Gate.AdmitTunnel().Dispose();
        env.Gate.CanEnrollClient(99);

        env.Clock.Advance(TimeSpan.FromDays(400));
        Assert.False(env.Reload().IsValid);
        env.Gate.AdmitTunnel().Dispose();

        var artifact = File.ReadAllText(env.LicenseFilePath);
        var events = env.Events.Snapshot();
        Assert.NotEmpty(events);

        foreach (var securityEvent in events)
        {
            var text = string.Join("|",
                securityEvent.EventType.ToString(),
                securityEvent.ReasonCode ?? string.Empty,
                securityEvent.Detail ?? string.Empty,
                securityEvent.LicenseId?.ToString() ?? string.Empty);

            Assert.DoesNotContain(RawMachineGuid, text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("BEGIN", text, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE KEY", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("PUBLIC KEY", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("one-time", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("\"payload\":", text, StringComparison.Ordinal);
            Assert.DoesNotContain(artifact, text, StringComparison.Ordinal);
        }
    }

    // ------------------------------------------------------------------
    // §12 - installation identity is stable, hashed and purpose-bound
    // ------------------------------------------------------------------

    private const string RawMachineGuid = "1f0e3c2b-4d5a-6e7f-8091-a2b3c4d5e6f7";

    /// <summary>
    /// Complements tests/SSP.Tests/Activation/SspInstallationIdentityProviderTests
    /// (determinism, hex SHA-256 shape, sensitivity to the source value) with the
    /// two properties §12 requires and that suite does not assert: the identifier
    /// is PURPOSE-BOUND (domain-separated by SspLicensing.InstallationBindingPurposeTag)
    /// and it never contains the raw identity source.
    /// </summary>
    [Fact]
    public void InstallationIdentity_IsPurposeBound_AndNeverExposesTheRawSource()
    {
        var derived = SspInstallationIdentityProvider.ComputeInstallationId(RawMachineGuid);

        Assert.DoesNotContain(RawMachineGuid, derived, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(RawMachineGuid, derived, StringComparer.OrdinalIgnoreCase);

        // Purpose-bound: the digest is over the source PLUS SSP's domain
        // separation tag, so the same MachineGuid used for any other purpose
        // yields a different identifier, and an identifier leaked from a license
        // artifact or security event cannot be replayed against another subsystem.
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(RawMachineGuid + SspLicensing.InstallationBindingPurposeTag)))
            .ToLowerInvariant();
        Assert.Equal(expected, derived);

        var bareDigest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(RawMachineGuid))).ToLowerInvariant();
        Assert.NotEqual(bareDigest, derived);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static async Task WaitForStateAsync(LicensedTestEnvironment env, LicenseState expected, int timeoutMs = 10_000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (env.State != expected)
        {
            if (Environment.TickCount64 > deadline)
            {
                Assert.True(false, $"Timed out waiting for licensing state {expected}; it is {env.State}.");
            }

            await Task.Delay(25);
        }
    }

    private sealed class FailingProvider : ILicenseProvider
    {
        private readonly LocalLicenseFileProvider _inner;
        private int _calls;

        public FailingProvider(string licenseFilePath)
            => _inner = new LocalLicenseFileProvider(licenseFilePath);

        public int Calls => Volatile.Read(ref _calls);

        public LicenseFetchResult FetchLicense()
        {
            if (Interlocked.Increment(ref _calls) % 2 == 0)
            {
                // A transport failure must be absorbed by the validator as
                // provider_error (never as "no license is fine") and must never
                // fault the owned refresh loop.
                throw new IOException("license file is momentarily unreadable");
            }

            return _inner.FetchLicense();
        }
    }
}
