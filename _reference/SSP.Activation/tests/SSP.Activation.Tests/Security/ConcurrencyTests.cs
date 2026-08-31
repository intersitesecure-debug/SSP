using System.Threading;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Security;

/// <summary>
/// Concurrency tests. The licensing runtime is designed for use inside a Windows service,
/// so it must remain correct under concurrent validation, authorization and license
/// replacement. These tests exercise the two races that matter:
///   - two concurrent validations must never install an older (already-superseded) license
///     as current after a newer one has persisted its anti-rollback floor;
///   - an authorization decision must be atomic with respect to a concurrent license
///     invalidation (no fail-open TOCTOU).
/// </summary>
public class ConcurrencyTests
{
    [Fact]
    public async Task ConcurrentLoads_NeverLeaveLowerSequenceLicenseCurrent()
    {
        using var system = new TestLicenseSystem();

        for (var iteration = 0; iteration < 100; iteration++)
        {
            var low = system.Authority.Issue(system.License().WithSequence(3).Build());
            var high = system.Authority.Issue(system.License().WithSequence(5).Build());

            var t1 = Task.Run(() => system.Manager.LoadLicense(low));
            var t2 = Task.Run(() => system.Manager.LoadLicense(high));
            await Task.WhenAll(t1, t2);

            var floor = system.StateStore.Load()?.HighestAcceptedSequenceNumber ?? 0;

            // The manager may be Valid (the newest sequence) or LockedDown (a supersede was
            // applied last). It must NEVER be Valid with a sequence older than the floor.
            if (system.Manager.CurrentState == LicenseState.Valid)
            {
                var currentSequence = system.Manager.CurrentLicense!.Payload.SequenceNumber;
                Assert.True(
                    currentSequence >= floor,
                    $"iteration {iteration}: current sequence {currentSequence} is below the anti-rollback floor {floor}");
                Assert.Equal(5L, currentSequence);
            }
        }
    }

    [Fact]
    public async Task Authorize_DecisionIsAtomicWithLicenseInvalidation()
    {
        var policy = new BlockingPolicy();
        using var system = new TestLicenseSystem(policy: policy);

        var valid = system.Authority.Issue(system.License().Build());
        Assert.True(system.Manager.LoadLicense(valid).IsValid);

        var revoked = system.Authority.Issue(system.License().WithStatus(LicenseStatus.Revoked).Build());

        // Start an authorization; the policy blocks mid-evaluation while the Manager lock is
        // held (the fix evaluates the policy under the same lock as state transitions).
        var authorizeTask = Task.Run(() => system.Enforcement().CanUseFeature("rdp"));
        Assert.True(policy.ValidEntered.Wait(TimeSpan.FromSeconds(5)), "The policy should have begun evaluating a Valid license.");

        // Start a concurrent license replacement. It must block behind the in-flight
        // authorization (it cannot observe a half-torn-down valid state).
        var invalidateTask = Task.Run(() => system.Manager.LoadLicense(revoked));
        var invalidateFinished = await Task.WhenAny(invalidateTask, Task.Delay(TimeSpan.FromMilliseconds(150)));
        Assert.False(
            invalidateFinished == invalidateTask,
            "A license replacement must wait for the in-flight authorization to release the manager lock.");

        // The license is still valid while the authorization is being decided.
        Assert.Equal(LicenseState.Valid, system.Manager.CurrentState);

        policy.Release.Set();

        var authorization = await authorizeTask;
        Assert.True(authorization.IsAllowed, "The operation was authorized against a genuinely Valid state.");

        var invalidateResult = await invalidateTask;
        Assert.False(invalidateResult.IsValid);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);

        // After the invalidation completes, nothing is authorized.
        Assert.False(system.Enforcement().CanUseFeature("rdp").IsAllowed);
    }

    [Fact]
    public void ThrowingPolicy_FailsClosed_AndDoesNotPropagate()
    {
        using var system = new TestLicenseSystem(policy: new ThrowingPolicy());
        system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));

        AuthorizationDecision? decision = null;
        var ex = Record.Exception(() => decision = system.Enforcement().CanUseFeature("rdp"));

        Assert.Null(ex);
        Assert.NotNull(decision);
        Assert.False(decision!.IsAllowed);
        Assert.Equal(LicenseReasons.InternalError, decision.ReasonCode);
        Assert.Contains(
            system.Events.Snapshot(),
            e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied);
    }

    private sealed class BlockingPolicy : ILicensePolicy
    {
        public ManualResetEventSlim ValidEntered { get; } = new(false);
        public ManualResetEventSlim Release { get; } = new(false);

        public AuthorizationDecision Evaluate(LicenseEvaluationContext context)
        {
            if (context.ManagerState == LicenseState.Valid)
            {
                ValidEntered.Set();
                Release.Wait();
            }

            return context.ManagerState == LicenseState.Valid && context.License is not null
                ? AuthorizationDecision.Allow()
                : AuthorizationDecision.Deny(LicenseReasons.LicenseNotValid, "not valid");
        }
    }

    private sealed class ThrowingPolicy : ILicensePolicy
    {
        public AuthorizationDecision Evaluate(LicenseEvaluationContext context)
            => throw new InvalidOperationException("policy blew up");
    }
}
