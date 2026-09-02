// File: tests/SSP.Tests/Activation/Runtime/LicensingFailClosedMatrixTests.cs
//
// §16 of the P3 hardening task: for EVERY way a license can fail, the protected
// operation must be DENIED. These tests run the real production gate
// (SspRuntimeLicense -> SspActivationService -> LicenseManager ->
// DefaultLicensePolicy) over real signed artifacts on disk, read through the
// real SSP adapters (SspLicensePaths, SspLicenseStateStore,
// LocalLicenseFileProvider, SspSecurityEventSink-compatible in-memory sink).
//
// Nothing here is mocked except the authority key (ephemeral, test-only) and the
// clock (so expiry is deterministic).

using SSP.Activation;
using SSP.Core.Activation;
using SSP.Server.Activation;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation.Runtime;

public class LicensingFailClosedMatrixTests
{
    /// <summary>
    /// Every protected-operation decision the gate can make. A fail-closed
    /// assertion must cover all of them: a license failure that only denies
    /// tunnels but still allows enrollment would be a hole.
    /// </summary>
    private static void AssertEveryProtectedOperationDenied(SspRuntimeLicense gate)
    {
        Assert.False(gate.AdmitTunnel().IsAdmitted, "tunnel admission must be denied");
        Assert.False(gate.CanStartProtectedService(0).IsAllowed, "service start must be denied");
        Assert.False(gate.CanEnrollClient(0).IsAllowed, "client enrollment must be denied");
        Assert.False(gate.CanUseFeature(SspLicensing.Features.RemoteDesktopProtocol).IsAllowed, "rdp feature must be denied");
        Assert.False(gate.CanUseFeature(SspLicensing.Features.SecureShell).IsAllowed, "ssh feature must be denied");
        Assert.False(gate.CanUseFeature(SspLicensing.Features.Web).IsAllowed, "web feature must be denied");
        Assert.False(gate.CanUseFeature(SspLicensing.Features.Sql).IsAllowed, "sql feature must be denied");
        if (gate.Feature is not null)
        {
            Assert.False(gate.CanUseServiceFeature().IsAllowed,
                "the service feature check must be denied whenever a feature identity exists");
        }
        Assert.False(gate.CanStartProtectedService(long.MaxValue).IsAllowed, "max_services must be denied");
        Assert.False(gate.CanEnrollClient(long.MaxValue).IsAllowed, "max_clients must be denied");
        Assert.Equal(0L, gate.ActiveTunnels);
        Assert.Equal(0L, gate.ActiveSessions);
    }

    [Fact]
    public void MissingLicense_EveryProtectedOperationIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { OmitLicenseFile = true });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.MissingLicense, result.ReasonCode);
        Assert.Equal(LicenseState.Unknown, env.State);
        Assert.NotEqual(LicenseState.Valid, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void TamperedLicense_EveryProtectedOperationIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { CorruptArtifact = true });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.NotEqual(LicenseState.Valid, env.State);
        // A corrupted canonical payload either fails to decode (malformed) or
        // fails signature verification. Both are fail-closed; neither is Valid.
        Assert.Contains(result.ReasonCode, new[]
        {
            LicenseReasons.InvalidSignature,
            LicenseReasons.MalformedArtifact,
            LicenseReasons.InvalidSchema,
        });
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void SignedByAnUntrustedAuthority_EveryProtectedOperationIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { SignWithForeignAuthority = true });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.InvalidSignature, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void MalformedArtifact_EveryProtectedOperationIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { OmitLicenseFile = true });
        env.WriteRawArtifact("{\"format\":\"ssp-license\",\"this-field\":\"is-not-in-the-schema\"}");

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void ExpiredLicense_EveryProtectedOperationIsDenied()
    {
        var now = LicensedTestOptions.DefaultNow;
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Now = now,
            ExpiresAt = now.AddHours(-1),
            NotBefore = now.AddDays(-30),
            IssuedAt = now.AddDays(-40),
        });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.Expired, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void NotYetValidLicense_EveryProtectedOperationIsDenied()
    {
        var now = LicensedTestOptions.DefaultNow;
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Now = now,
            NotBefore = now.AddDays(1),
            ExpiresAt = now.AddDays(365),
        });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.NotYetValid, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void RevokedLicense_EveryProtectedOperationIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Status = LicenseStatus.Revoked,
        });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.Revoked, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void WrongProduct_EveryProtectedOperationIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ProductId = Guid.NewGuid(),
        });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.WrongProduct, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void WrongInstallation_EveryProtectedOperationIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            InstallationId = "INSTALLATION-THAT-IS-NOT-THIS-HOST",
            HostInstallationId = "THIS-HOST",
        });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.WrongInstallation, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void InstallationIdentityUnavailable_BoundLicenseIsDenied()
    {
        // A license bound to an installation cannot be honored when the host
        // cannot produce its identity (this is exactly the non-Windows posture of
        // SspInstallationIdentityProvider).
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            InstallationId = "INSTALLATION-A",
            HostInstallationId = null,
        });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.IdentityUnavailable, result.ReasonCode);
        Assert.NotEqual(LicenseState.Valid, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void SupersededLicense_AntiRollbackFloorDeniesTheOlderArtifact()
    {
        var options = new LicensedTestOptions { SequenceNumber = 5 };
        using var env = LicensedTestEnvironment.Create(options);

        // Accept the newer artifact first, establishing the durable floor.
        Assert.True(env.Load().IsValid);
        Assert.Equal(LicenseState.Valid, env.State);

        // Then present an older one. The DPAPI/AES-GCM state store must refuse it.
        env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
        {
            SequenceNumber = 4,
            ApplicationName = options.ApplicationName,
        }));

        var result = env.Reload();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.Superseded, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void StateStoreFailure_FailsClosed()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            StateStore = new ThrowingStateStore(),
        });

        var result = env.Load();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.StateStoreUnavailable, result.ReasonCode);
        Assert.NotEqual(LicenseState.Valid, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void ThrowingPolicy_DeniesInsteadOfFailingOpen()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Policy = new ThrowingPolicy(),
        });

        Assert.True(env.Load().IsValid, "the artifact itself is valid; only the policy is broken");

        var tunnel = env.Gate.AdmitTunnel();
        Assert.False(tunnel.IsAdmitted);
        Assert.Equal(LicenseReasons.InternalError, tunnel.ReasonCode);

        Assert.False(env.Gate.CanStartProtectedService(0).IsAllowed);
        Assert.False(env.Gate.CanEnrollClient(0).IsAllowed);
        Assert.False(env.Gate.CanUseFeature(SspLicensing.Features.RemoteDesktopProtocol).IsAllowed);
    }

    [Fact]
    public void DeletingTheLicense_NeverRecoversALockdown()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { CorruptArtifact = true });
        Assert.True(env.Load().IsValid == false);
        Assert.Equal(LicenseState.LockedDown, env.State);

        env.DeleteLicense();
        var afterDeletion = env.Reload();

        Assert.False(afterDeletion.IsValid);
        Assert.Equal(LicenseState.LockedDown, env.State);
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    [Fact]
    public void ValidLicense_AuthorizesEverythingThePayloadCovers()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            ApplicationName = "RDP",
            Features = new[] { SspLicensing.Features.RemoteDesktopProtocol },
            Limits =
            {
                [LicenseLimitNames.MaxClients] = 3,
                [LicenseLimitNames.MaxConcurrentTunnels] = 2,
            },
        });

        var result = env.Load();

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, env.State);
        Assert.Equal(SspLicensing.Features.RemoteDesktopProtocol, env.Gate.Feature);

        Assert.True(env.Gate.CanUseServiceFeature().IsAllowed);
        Assert.True(env.Gate.CanUseFeature("rdp").IsAllowed);
        Assert.True(env.Gate.CanStartProtectedService(0).IsAllowed);
        Assert.True(env.Gate.CanEnrollClient(2).IsAllowed);
        Assert.False(env.Gate.CanEnrollClient(3).IsAllowed);

        // Features outside the licensed set stay denied even in the Valid state.
        Assert.False(env.Gate.CanUseFeature(SspLicensing.Features.SecureShell).IsAllowed);
        Assert.False(env.Gate.CanUseFeature(SspLicensing.Features.Web).IsAllowed);
        Assert.False(env.Gate.CanUseFeature(SspLicensing.Features.Sql).IsAllowed);
        Assert.False(env.Gate.CanUseFeature("not-a-real-feature").IsAllowed);
    }

    /// <summary>
    /// §9 lockdown propagation: a runtime that was Valid must start denying the
    /// instant revalidation fails, with no restart and no cached flag in between.
    /// </summary>
    [Fact]
    public void Lockdown_PropagatesImmediatelyToEveryRuntimeGate()
    {
        var now = LicensedTestOptions.DefaultNow;
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Now = now,
            NotBefore = now.AddDays(-1),
            ExpiresAt = now.AddHours(1),
        });

        Assert.True(env.Load().IsValid);
        Assert.Equal(LicenseState.Valid, env.State);

        using (var admitted = env.Gate.AdmitTunnel())
        {
            Assert.True(admitted.IsAdmitted);
            Assert.Equal(1L, env.Gate.ActiveTunnels);
        }

        Assert.Equal(0L, env.Gate.ActiveTunnels);

        // The license expires while the process is running.
        env.Clock.Advance(TimeSpan.FromHours(2));
        var revalidation = env.Reload();

        Assert.False(revalidation.IsValid);
        Assert.Equal(LicenseState.LockedDown, env.State);
        Assert.False(revalidation.IsValid);

        // Every gate consults the manager live: the very next decision denies.
        AssertEveryProtectedOperationDenied(env.Gate);
    }

    /// <summary>
    /// §15 recovery: the reference state machine clears a lockdown only by
    /// loading a cryptographically valid artifact. Installing a newer, valid
    /// license must restore authorization without a restart.
    /// </summary>
    [Fact]
    public void Recovery_LockedDownThenValidNewerLicense_AllowsProtectedOperationsAgain()
    {
        var now = LicensedTestOptions.DefaultNow;
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Now = now,
            NotBefore = now.AddDays(-1),
            ExpiresAt = now.AddHours(1),
            SequenceNumber = 1,
        });

        Assert.True(env.Load().IsValid);
        Assert.Equal(LicenseState.Valid, env.State);

        env.Clock.Advance(TimeSpan.FromHours(2));
        var expired = env.Reload();

        Assert.False(expired.IsValid);
        Assert.Equal(LicenseState.LockedDown, env.State);
        Assert.False(env.Gate.AdmitTunnel().IsAdmitted);

        // Operator installs a renewed license (higher sequence, new window).
        var renewal = env.InstallRenewal();

        Assert.True(renewal.IsValid);
        Assert.Equal(LicenseState.Valid, env.State);

        var admission = env.Gate.AdmitTunnel();
        Assert.True(admission.IsAdmitted);
        admission.Dispose();
        Assert.True(env.Gate.CanStartProtectedService(0).IsAllowed);
        Assert.Contains(env.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseLockdownCleared);
    }

    /// <summary>
    /// A denial must be observable (§14) without leaking anything secret: the
    /// emitted events carry only state, license id, reason code and safe detail.
    /// </summary>
    [Fact]
    public void Denials_AreReportedAsSecurityEvents_WithoutSecrets()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions { OmitLicenseFile = true });
        env.Load();

        var denied = env.Gate.AdmitTunnel();
        Assert.False(denied.IsAdmitted);

        var denialEvents = env.Events.Snapshot()
            .Where(e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied)
            .ToArray();
        Assert.NotEmpty(denialEvents);
        Assert.All(denialEvents, e => Assert.Equal(LicenseReasons.LicenseNotValid, e.ReasonCode));

        foreach (var e in env.Events.Snapshot())
        {
            Assert.DoesNotContain("BEGIN", e.Detail ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE", e.Detail ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain("signature", e.Detail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
    }

    private sealed class ThrowingStateStore : ILicenseStateStore
    {
        public LicenseStateRecord? Load()
            => throw new InvalidDataException("state store is unreadable");

        public void Save(LicenseStateRecord record)
            => throw new InvalidDataException("state store is unwritable");
    }

    private sealed class ThrowingPolicy : ILicensePolicy
    {
        public AuthorizationDecision Evaluate(LicenseEvaluationContext context)
            => throw new InvalidOperationException("policy failure must never fail open");
    }
}
