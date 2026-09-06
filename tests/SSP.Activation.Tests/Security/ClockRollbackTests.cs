using System.Text.Json;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Security;

/// <summary>Phase 6 / M-6. All clocks and keys are test-owned; the OS clock is never changed.</summary>
public class ClockRollbackTests
{
    private static readonly DateTimeOffset Now = LicensePayloadFactory.BaseTime;

    [Fact]
    public void ForwardAndEqualTime_RefreshTheCheckpointForTheSameLicense()
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().Build();
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(payload)).IsValid);

        foreach (var advance in new[] { TimeSpan.Zero, TimeSpan.FromSeconds(1), TimeSpan.FromHours(1) })
        {
            system.Clock.Advance(advance);
            Assert.True(system.Manager.Revalidate().IsValid);
            var state = Assert.IsType<LicenseStateRecord>(system.StateStore.Load());
            Assert.Equal(1, state.ClockStateVersion);
            Assert.Equal(system.Clock.UtcNow, state.LastObservedUtc);
            Assert.Equal(system.Clock.UtcNow, state.LastValidatedUtc);
            Assert.Equal(payload.SequenceNumber, state.HighestAcceptedSequenceNumber);
            Assert.Equal(payload.LicenseId, state.LastAcceptedLicenseId);
        }

        // A UTC offset / DST representation change is not a clock regression.
        system.Clock.Set(system.Clock.UtcNow.ToOffset(TimeSpan.FromHours(3.5)));
        Assert.True(system.Manager.Revalidate().IsValid);
        Assert.DoesNotContain(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.ClockRollbackDetected);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExpiredLicense_CannotBeRevivedByRollbackInTheSameManager(bool certified)
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().WithExpiresAt(Now.AddHours(1)).Build();
        Assert.True(system.Manager.LoadLicense(Issue(system.Authority, payload, certified)).IsValid);

        system.Clock.Set(Now.AddHours(2));
        Assert.Equal(LicenseState.Expired, system.Manager.Revalidate().State);
        Assert.Equal(Now.AddHours(2), system.StateStore.Load()!.LastObservedUtc);
        Assert.Equal(Now, system.StateStore.Load()!.LastValidatedUtc);

        // Still AFTER the last successful validation: remembering successful
        // validations alone would miss precisely this attack.
        system.Clock.Set(Now.AddMinutes(30));
        var result = system.Manager.Revalidate();
        Assert.Equal(LicenseReasons.ClockRollbackDetected, result.ReasonCode);
        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        AssertEveryOperationDenied(system.Enforcement());
        Assert.Equal(Now.AddHours(2), system.StateStore.Load()!.LastObservedUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExpiredOnFirstLoad_RecordsTimeWithoutAcceptingOrActivatingTheLicense(bool certified)
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().WithSequence(9).WithExpiresAt(Now.AddTicks(-1)).Build();
        Assert.Equal(LicenseState.Expired, system.Manager.LoadLicense(Issue(system.Authority, payload, certified)).State);

        var state = Assert.IsType<LicenseStateRecord>(system.StateStore.Load());
        Assert.Equal(Now, state.LastObservedUtc);
        Assert.Equal(0, state.HighestAcceptedSequenceNumber);
        Assert.Null(state.LastValidatedUtc);
        Assert.Null(state.LastAcceptedLicenseId);
        Assert.Null(state.ActivatedLicenseId);

        system.Clock.Set(Now.AddHours(-1));
        Assert.Equal(LicenseReasons.ClockRollbackDetected, system.Manager.Revalidate().ReasonCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DurableExpiryObservation_SurvivesNewManagerAndStore(bool certified)
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            using var authority = new TestAuthority();
            var path = Path.Combine(dir, "state.json");
            var clock = new FixedClock(Now);
            var artifact = Issue(authority, LicensePayloadFactory.For(authority).WithExpiresAt(Now.AddHours(1)).Build(), certified);
            var first = Manager(authority, clock, new FileLicenseStateStore(path));
            Assert.True(first.LoadLicense(artifact).IsValid);
            clock.Set(Now.AddHours(2));
            Assert.Equal(LicenseState.Expired, first.Revalidate().State);

            var restarted = Manager(authority, new FixedClock(Now.AddMinutes(30)), new FileLicenseStateStore(path));
            Assert.Equal(LicenseReasons.ClockRollbackDetected, restarted.LoadLicense(artifact).ReasonCode);
            AssertEveryOperationDenied(new LicenseEnforcement(restarted));
        }
        finally { TestPaths.DeleteDirectory(dir); }
    }

    [Fact]
    public void Rollback_DeniesEveryOperationWithoutExplicitRevalidation()
    {
        using var system = new TestLicenseSystem();
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(system.License().Build())).IsValid);
        var before = system.StateStore.Load();
        system.Clock.Set(Now.AddTicks(-1)); // strict: even one tick is a regression

        AssertEveryOperationDenied(system.Enforcement());
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.Null(system.Manager.CurrentLicense);
        Assert.Equal(LicenseReasons.ClockRollbackDetected, system.Manager.LastValidationResult!.ReasonCode);
        Assert.Equal(before, system.StateStore.Load()); // never write the rolled-back time
        Assert.Contains(system.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.ProtectedOperationDenied);
    }

    [Fact]
    public void Expiry_DeniesAuthorizationAtTheExactBoundaryWithoutWaitingForTheTimer()
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().WithExpiresAt(Now.AddHours(1)).Build();
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(payload)).IsValid);
        system.Clock.Set(payload.ExpiresAt);
        var denied = system.Enforcement().RequireValidLicense();
        Assert.False(denied.IsAllowed);
        Assert.Equal(LicenseReasons.Expired, denied.ReasonCode);
        Assert.Equal(payload.ExpiresAt, system.StateStore.Load()!.LastObservedUtc);

        system.Clock.Set(Now.AddMinutes(30));
        Assert.Equal(LicenseReasons.ClockRollbackDetected, system.Manager.Revalidate().ReasonCode);
    }

    [Fact]
    public void NotBeforeRemainsInclusive_WithForwardProgression()
    {
        using var system = new TestLicenseSystem();
        var payload = system.License().WithNotBefore(Now.AddHours(1)).Build();
        Assert.Equal(LicenseState.NotYetValid, system.Manager.LoadLicense(system.Authority.Issue(payload)).State);
        system.Clock.Set(payload.NotBefore);
        Assert.True(system.Manager.Revalidate().IsValid);
        Assert.True(system.Enforcement().RequireValidLicense().IsAllowed);
    }

    [Fact]
    public void CertificationAndPayloadWindows_UseOneClockSample()
    {
        using var authority = new TestAuthority();
        using var leaf = TestAuthority.CreateLeafKey();
        var payload = LicensePayloadFactory.For(authority).WithWindow(Now, Now.AddSeconds(1)).Build();
        var certification = authority.Certify(payload, leaf) with { NotBefore = Now };
        var clock = new SteppingClock();
        var validator = new LicenseValidator(authority.TrustAnchor, new LicenseValidationOptions(authority.ProductId), clock);
        var artifact = authority.IssueCertified(payload, certification, leaf);

        Assert.True(validator.Validate(artifact).IsValid);
        Assert.Equal(1, clock.Reads);
        Assert.Equal(LicenseReasons.CertificationExpired, validator.Validate(artifact).ReasonCode);
        Assert.Equal(2, clock.Reads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ThrowingClock_DeniesAnAlreadyValidRuntime_WithoutEscaping(bool authorize)
    {
        using var authority = new TestAuthority();
        var clock = new FaultClock();
        var events = new InMemorySecurityEventSink();
        var manager = Manager(authority, clock, new InMemoryLicenseStateStore(), events);
        Assert.True(manager.LoadLicense(authority.Issue(LicensePayloadFactory.For(authority).Build())).IsValid);
        clock.Throw = true;

        var exception = Record.Exception(() =>
        {
            if (authorize) Assert.False(new LicenseEnforcement(manager).RequireValidLicense().IsAllowed);
            else Assert.False(manager.Revalidate().IsValid);
        });
        Assert.Null(exception);
        Assert.Equal(LicenseState.LockedDown, manager.CurrentState);
        Assert.Equal(LicenseReasons.TimeIntegrityUnavailable, manager.LastValidationResult!.ReasonCode);
        Assert.Contains(events.Snapshot(), e => e.EventType == LicenseSecurityEventType.TimeIntegrityUnavailable);
        Assert.DoesNotContain("sensitive clock error", JsonSerializer.Serialize(events.Snapshot()), StringComparison.Ordinal);
    }

    [Fact]
    public void ThrowingClock_StandaloneValidatorReturnsFailure()
    {
        using var authority = new TestAuthority();
        var validator = new LicenseValidator(authority.TrustAnchor, new LicenseValidationOptions(authority.ProductId),
            new FaultClock { Throw = true });
        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).Build()));
        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.TimeIntegrityUnavailable, result.ReasonCode);
    }

    [Fact]
    public void FailedInitialCheckpoint_NeverPublishesValid()
    {
        using var system = new TestLicenseSystem(stateStore: new FaultStore { FailWrites = true });
        var result = system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));
        Assert.Equal(LicenseReasons.StateStoreUnavailable, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
        Assert.Null(system.Manager.CurrentLicense);
        AssertEveryOperationDenied(system.Enforcement());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CheckpointReadOrWriteFailure_DeniesPreviouslyValidAuthorization(bool failRead)
    {
        var store = new FaultStore();
        using var system = new TestLicenseSystem(stateStore: store);
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(system.License().Build())).IsValid);
        store.FailReads = failRead;
        store.FailWrites = !failRead;
        system.Clock.Advance(TimeSpan.FromMinutes(1));

        AssertEveryOperationDenied(system.Enforcement());
        Assert.Equal(LicenseReasons.StateStoreUnavailable, system.Manager.LastValidationResult!.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, system.Manager.CurrentState);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailureBetweenValidationAndApply_CannotPublishValid(bool failRead)
    {
        using var authority = new TestAuthority();
        var store = new FaultStore();
        var events = new CallbackSink(e =>
        {
            if (e.EventType != LicenseSecurityEventType.LicenseValidated) return;
            store.FailReads = failRead;
            store.FailWrites = !failRead;
        });
        var manager = Manager(authority, new FixedClock(Now), store, events);
        var result = manager.LoadLicense(authority.Issue(LicensePayloadFactory.For(authority).Build()));
        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.StateStoreUnavailable, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, manager.CurrentState);
        Assert.Null(manager.CurrentLicense);
    }

    [Fact]
    public void RollbackBetweenValidationAndApply_CannotPublishValid()
    {
        using var authority = new TestAuthority();
        var clock = new FixedClock(Now);
        var events = new CallbackSink(e =>
        {
            if (e.EventType == LicenseSecurityEventType.LicenseValidated) clock.Set(Now.AddTicks(-1));
        });
        var manager = Manager(authority, clock, new InMemoryLicenseStateStore(), events);
        Assert.Equal(LicenseReasons.ClockRollbackDetected,
            manager.LoadLicense(authority.Issue(LicensePayloadFactory.For(authority).Build())).ReasonCode);
        Assert.Equal(LicenseState.LockedDown, manager.CurrentState);
    }

    [Fact]
    public async Task DelayedSuccessfulValidation_CannotClearARollbackLockdown()
    {
        using var authority = new TestAuthority();
        var clock = new FixedClock(Now);
        using var validated = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var count = 0;
        var events = new CallbackSink(e =>
        {
            if (e.EventType == LicenseSecurityEventType.LicenseValidated && Interlocked.Increment(ref count) == 2)
            {
                validated.Set();
                release.Wait(TimeSpan.FromSeconds(10));
            }
        });
        var manager = Manager(authority, clock, new InMemoryLicenseStateStore(), events);
        Assert.True(manager.LoadLicense(authority.Issue(LicensePayloadFactory.For(authority).Build())).IsValid);
        var delayed = Task.Run(manager.Revalidate);
        try
        {
            Assert.True(validated.Wait(TimeSpan.FromSeconds(5)), "The validation did not reach its Apply boundary.");
            clock.Set(Now.AddTicks(-1));
            Assert.False(new LicenseEnforcement(manager).RequireValidLicense().IsAllowed);
            Assert.Equal(LicenseState.LockedDown, manager.CurrentState);
        }
        finally { release.Set(); }

        var result = await delayed.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(LicenseReasons.ClockRollbackDetected, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, manager.CurrentState);
    }

    [Fact]
    public async Task ConcurrentForwardObservations_AreNotMistakenForRollback()
    {
        using var authority = new TestAuthority();
        var clock = new IncrementingClock();
        var store = new InMemoryLicenseStateStore();
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());
        var managers = new[] { Manager(authority, clock, store), Manager(authority, clock, store) };
        foreach (var manager in managers) Assert.True(manager.LoadLicense(artifact).IsValid);

        var results = await Task.WhenAll(Enumerable.Range(0, 40)
            .Select(i => Task.Run(() => managers[i % managers.Length].Revalidate())));
        Assert.All(results, result => Assert.True(result.IsValid, result.Detail));
        Assert.True(store.Load()!.LastObservedUtc > Now);
        Assert.Equal(1, store.Load()!.HighestAcceptedSequenceNumber);
    }

    [Fact]
    public void CorrectedClock_StillRequiresFullRevalidation()
    {
        using var system = new TestLicenseSystem();
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(system.License().Build())).IsValid);
        system.Clock.Set(Now.AddTicks(-1));
        Assert.False(system.Enforcement().RequireValidLicense().IsAllowed);
        system.Clock.Set(Now);
        Assert.False(system.Enforcement().RequireValidLicense().IsAllowed);
        Assert.True(system.Manager.Revalidate().IsValid);
        Assert.True(system.Enforcement().RequireValidLicense().IsAllowed);
    }

    [Fact]
    public void RenewalCannotClearRollbackUntilTimeIsCorrected()
    {
        using var system = new TestLicenseSystem();
        var expiring = system.License().WithExpiresAt(Now.AddHours(1)).Build();
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(expiring)).IsValid);
        system.Clock.Set(Now.AddHours(2));
        Assert.Equal(LicenseState.Expired, system.Manager.Revalidate().State);
        system.Clock.Set(Now.AddMinutes(30));
        var renewal = system.Authority.Issue(system.License().WithSequence(2).Build());
        Assert.Equal(LicenseReasons.ClockRollbackDetected, system.Manager.LoadLicense(renewal).ReasonCode);
        system.Clock.Set(Now.AddHours(2));
        Assert.True(system.Manager.LoadLicense(renewal).IsValid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LegacyState_MigratesWithoutLosingActivationOrLicenseIdentity(bool hasTimestamp)
    {
        using var authority = new TestAuthority();
        using var leaf = TestAuthority.CreateLeafKey();
        var payload = LicensePayloadFactory.For(authority).WithSequence(7).Build();
        var cert = authority.Certify(payload, leaf, activationCodeHash: LicenseActivation.ComputeActivationCodeHash("1234567890"));
        var store = new InMemoryLicenseStateStore();
        store.Save(new LicenseStateRecord
        {
            HighestAcceptedSequenceNumber = 7,
            LastAcceptedLicenseId = payload.LicenseId,
            ActivatedLicenseId = payload.LicenseId,
            LastValidatedUtc = hasTimestamp ? Now.AddHours(-1) : null
        });
        var manager = Manager(authority, new FixedClock(Now), store);
        Assert.True(manager.LoadLicense(authority.IssueCertified(payload, cert, leaf)).IsValid);
        var state = store.Load()!;
        Assert.Equal(1, state.ClockStateVersion);
        Assert.Equal(Now, state.LastObservedUtc);
        Assert.Equal(payload.LicenseId, state.LastAcceptedLicenseId);
        Assert.Equal(payload.LicenseId, state.ActivatedLicenseId);
        Assert.Equal(7, state.HighestAcceptedSequenceNumber);
    }

    [Fact]
    public void LegacyValidationTime_IsUsedAsARollbackLowerBound()
    {
        var store = new InMemoryLicenseStateStore();
        store.Save(new LicenseStateRecord { LastValidatedUtc = Now.AddHours(1) });
        using var system = new TestLicenseSystem(stateStore: store);
        var result = system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));
        Assert.Equal(LicenseReasons.ClockRollbackDetected, result.ReasonCode);
        Assert.Equal(Now.AddHours(1), store.Load()!.LastValidatedUtc);
        Assert.Equal(0, store.Load()!.ClockStateVersion); // denial does not replace evidence
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(2, true)]
    [InlineData(1, false)]
    [InlineData(0, true)]
    public void InvalidClockMetadata_IsNotTreatedAsLegacy(int version, bool hasTime)
    {
        var store = new InMemoryLicenseStateStore();
        store.Save(new LicenseStateRecord { ClockStateVersion = version, LastObservedUtc = hasTime ? Now : null });
        using var system = new TestLicenseSystem(stateStore: store);
        var result = system.Manager.LoadLicense(system.Authority.Issue(system.License().Build()));
        Assert.Equal(LicenseReasons.StateStoreUnavailable, result.ReasonCode);
        Assert.False(result.IsValid);
        AssertEveryOperationDenied(system.Enforcement());
    }

    [Fact]
    public void FailedCheckpoint_DoesNotForgetObservedForwardTimeInProcess()
    {
        var store = new FaultStore();
        using var system = new TestLicenseSystem(stateStore: store);
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(system.License().WithExpiresAt(Now.AddHours(1)).Build())).IsValid);
        store.FailWrites = true;
        system.Clock.Set(Now.AddHours(2));
        Assert.Equal(LicenseReasons.StateStoreUnavailable, system.Manager.Revalidate().ReasonCode);
        store.FailWrites = false;
        system.Clock.Set(Now.AddMinutes(30));
        Assert.Equal(LicenseReasons.ClockRollbackDetected, system.Manager.Revalidate().ReasonCode);
        Assert.Equal(Now, store.Load()!.LastObservedUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void HigherLoadedFloor_IsRememberedEvenAfterARejectedObservation(bool clockThrows)
    {
        using var authority = new TestAuthority();
        var store = new InMemoryLicenseStateStore();
        store.Save(new LicenseStateRecord { ClockStateVersion = 1, LastObservedUtc = Now.AddHours(1) });
        var clock = new FaultClock { Throw = clockThrows };
        var manager = Manager(authority, clock, store);
        Assert.False(manager.LoadLicense(authority.Issue(LicensePayloadFactory.For(authority).Build())).IsValid);

        // Simulate loss/replay outside this in-memory replacement store's
        // synchronization contract. The running manager still remembers evidence.
        store.Save(new LicenseStateRecord());
        clock.Throw = false;
        Assert.Equal(LicenseReasons.ClockRollbackDetected, manager.Revalidate().ReasonCode);
    }

    [Fact]
    public void HigherReadbackFloor_CannotAuthorizeTheEarlierSample_AndIsRemembered()
    {
        var store = new FaultStore();
        using var system = new TestLicenseSystem(stateStore: store);
        Assert.True(system.Manager.LoadLicense(system.Authority.Issue(system.License().Build())).IsValid);
        store.MoveCheckpointAheadOnSave = true;
        system.Clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False(system.Enforcement().RequireValidLicense().IsAllowed);
        Assert.Equal(LicenseReasons.StateStoreUnavailable, system.Manager.LastValidationResult!.ReasonCode);

        store.MoveCheckpointAheadOnSave = false;
        store.Save(new LicenseStateRecord()); // even subsequent loss cannot erase remembered evidence
        Assert.Equal(LicenseReasons.ClockRollbackDetected, system.Manager.Revalidate().ReasonCode);
    }

    [Fact]
    public void DiscardedCheckpointWrite_FailsClosed()
    {
        using var system = new TestLicenseSystem(stateStore: new DiscardingStore());
        Assert.Equal(LicenseReasons.StateStoreUnavailable,
            system.Manager.LoadLicense(system.Authority.Issue(system.License().Build())).ReasonCode);
        AssertEveryOperationDenied(system.Enforcement());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LoggingFailureAndCustomPolicy_CannotOverrideTimeDenial(bool expired)
    {
        using var authority = new TestAuthority();
        var clock = new FixedClock(Now);
        var manager = new LicenseManager(new LicenseValidationOptions(authority.ProductId), authority.TrustAnchor,
            new StaticInstallationIdentityProvider(null), clock,
            policy: new AllowingPolicy(), eventSink: new CallbackSink(_ => throw new IOException("log unavailable")));
        Assert.True(manager.LoadLicense(authority.Issue(LicensePayloadFactory.For(authority).WithExpiresAt(Now.AddHours(1)).Build())).IsValid);
        clock.Set(expired ? Now.AddHours(2) : Now.AddTicks(-1));
        AssertEveryOperationDenied(new LicenseEnforcement(manager));
        Assert.Equal(LicenseState.LockedDown, manager.CurrentState);
        Assert.False(manager.LoadLicense("not a license").IsValid);
        AssertEveryOperationDenied(new LicenseEnforcement(manager));
        Assert.False(manager.LoadLicense(" ").IsValid);
        AssertEveryOperationDenied(new LicenseEnforcement(manager));
    }

    [Fact]
    public void RollbackEvents_CarrySafeObservedAndRetainedTimes()
    {
        using var system = new TestLicenseSystem();
        var artifact = system.Authority.Issue(system.License().Build());
        Assert.True(system.Manager.LoadLicense(artifact).IsValid);
        system.Clock.Set(Now.AddMinutes(-1));
        system.Manager.Revalidate();
        var securityEvent = Assert.Single(system.Events.Snapshot().Where(e => e.EventType == LicenseSecurityEventType.ClockRollbackDetected));
        Assert.Equal(Now.AddMinutes(-1), securityEvent.OccurredAtUtc);
        Assert.Equal(LicenseReasons.ClockRollbackDetected, securityEvent.ReasonCode);
        Assert.Contains(Now.ToString("o"), securityEvent.Detail!, StringComparison.Ordinal);
        var json = JsonSerializer.Serialize(system.Events.Snapshot());
        Assert.DoesNotContain(artifact, json, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", json, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", json, StringComparison.Ordinal);
    }

    [Fact]
    public void WrongSigningKey_CannotInitializeClockOrAuthorize()
    {
        using var authority = new TestAuthority();
        using var foreign = new TestAuthority();
        var store = new InMemoryLicenseStateStore();
        var clock = new FaultClock { Throw = true };
        var manager = Manager(authority, clock, store);
        var result = manager.LoadLicense(foreign.Issue(LicensePayloadFactory.For(authority).Build()));
        Assert.Equal(LicenseReasons.InvalidSignature, result.ReasonCode);
        Assert.Null(store.Load());
        AssertEveryOperationDenied(new LicenseEnforcement(manager));
    }

    private static LicenseManager Manager(TestAuthority authority, IClock clock, ILicenseStateStore store, ISecurityEventSink? events = null)
        => new(new LicenseValidationOptions(authority.ProductId), authority.TrustAnchor,
            new StaticInstallationIdentityProvider(null), clock, stateStore: store, eventSink: events);

    private static string Issue(TestAuthority authority, LicensePayload payload, bool certified)
    {
        if (!certified) return authority.Issue(payload);
        using var leaf = TestAuthority.CreateLeafKey();
        return authority.IssueCertified(payload, authority.Certify(payload, leaf), leaf);
    }

    private static void AssertEveryOperationDenied(LicenseEnforcement enforcement)
    {
        Assert.False(enforcement.RequireValidLicense().IsAllowed);
        Assert.False(enforcement.CanUseFeature("rdp").IsAllowed);
        Assert.False(enforcement.CanStartProtectedService(0).IsAllowed);
        Assert.False(enforcement.CanCreateSession(0).IsAllowed);
        Assert.False(enforcement.CanEstablishTunnel(0).IsAllowed);
        Assert.False(enforcement.CheckLimit(LicenseLimitNames.MaxClients, 0).IsAllowed);
    }

    private sealed class FaultStore : ILicenseStateStore
    {
        private readonly InMemoryLicenseStateStore _inner = new();
        internal bool FailReads { get; set; }
        internal bool FailWrites { get; set; }
        internal bool MoveCheckpointAheadOnSave { get; set; }
        public LicenseStateRecord? Load() => FailReads ? throw new IOException("read unavailable") : _inner.Load();
        public void Save(LicenseStateRecord record)
        {
            if (FailWrites) throw new IOException("write unavailable");
            _inner.Save(MoveCheckpointAheadOnSave
                ? record with { LastObservedUtc = record.LastObservedUtc?.AddHours(1) }
                : record);
        }
    }

    private sealed class DiscardingStore : ILicenseStateStore
    {
        public LicenseStateRecord? Load() => null;
        public void Save(LicenseStateRecord record) { }
    }

    private sealed class FaultClock : IClock
    {
        internal bool Throw { get; set; }
        public DateTimeOffset UtcNow => Throw ? throw new InvalidOperationException("sensitive clock error") : Now;
    }

    private sealed class SteppingClock : IClock
    {
        internal int Reads { get; private set; }
        public DateTimeOffset UtcNow => Now.AddSeconds(2 * Reads++);
    }

    private sealed class IncrementingClock : IClock
    {
        private long _ticks = Now.Ticks;
        public DateTimeOffset UtcNow => new(Interlocked.Increment(ref _ticks), TimeSpan.Zero);
    }

    private sealed class CallbackSink : ISecurityEventSink
    {
        private readonly Action<LicenseSecurityEvent> _callback;
        internal CallbackSink(Action<LicenseSecurityEvent> callback) => _callback = callback;
        public void Report(LicenseSecurityEvent securityEvent) => _callback(securityEvent);
    }

    private sealed class AllowingPolicy : ILicensePolicy
    {
        public AuthorizationDecision Evaluate(LicenseEvaluationContext context) => AuthorizationDecision.Allow();
    }
}
