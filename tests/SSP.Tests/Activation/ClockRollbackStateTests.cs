using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSP.Activation;
using SSP.Core.IO;
using SSP.Server.Activation;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation;

/// <summary>Phase 6: real protected primary/witness files, fresh stores and cooperating writers.</summary>
public class ClockRollbackStateTests
{
    private static readonly DateTimeOffset Now = LicensedTestOptions.DefaultNow;

    [Fact]
    public void BothCopies_AreEncrypted_AndTimeNeverRegressesOnSave()
    {
        using var fixture = new NativeFixture();
        var id = Guid.NewGuid();
        var state = new LicenseStateRecord
        {
            ClockStateVersion = 1, LastObservedUtc = Now,
            HighestAcceptedSequenceNumber = 7, LastAcceptedLicenseId = id, ActivatedLicenseId = id
        };
        fixture.NewStore().Save(state);
        fixture.NewStore().Save(state with { LastObservedUtc = Now.AddHours(2) });
        fixture.NewStore().Save(state); // a stale timestamp cannot replace a newer one
        fixture.NewStore().Save(state with { ClockStateVersion = 0, LastObservedUtc = null });

        var loaded = fixture.NewStore().Load()!;
        var witness = SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!;
        Assert.Equal(Now.AddHours(2), loaded.LastObservedUtc);
        Assert.Equal(loaded.LastObservedUtc, witness.LastObservedUtc);
        Assert.Equal(1, loaded.ClockStateVersion);
        Assert.Equal(1, witness.ClockStateVersion);
        Assert.Equal(7, loaded.HighestAcceptedSequenceNumber);
        Assert.Equal(id, loaded.LastAcceptedLicenseId);
        Assert.Equal(id, loaded.ActivatedLicenseId);
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(File.ReadAllBytes(fixture.Paths.StateStorePath)));
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(File.ReadAllBytes(fixture.Paths.StateWitnessPath)));
        Assert.DoesNotContain("LastObservedUtc", Encoding.UTF8.GetString(File.ReadAllBytes(fixture.Paths.StateStorePath)));
        Assert.DoesNotContain(Now.AddHours(2).ToString("o"), Encoding.UTF8.GetString(File.ReadAllBytes(fixture.Paths.StateWitnessPath)));
    }

    [Fact]
    public void HigherWitnessTime_IsMaxMergedIndependentlyOfSequenceAndEpoch()
    {
        using var fixture = new NativeFixture();
        fixture.NewStore().Save(new LicenseStateRecord { ClockStateVersion = 1, LastObservedUtc = Now });
        var witness = SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!;
        SspLicenseStateWitnessStore.Save(fixture.Paths.StateWitnessPath, witness with { LastObservedUtc = Now.AddHours(2) });
        var loaded = fixture.NewStore().Load()!;
        Assert.Equal(Now.AddHours(2), loaded.LastObservedUtc);
        fixture.NewStore().Save(loaded with { LastObservedUtc = Now.AddHours(1) });
        Assert.Equal(Now.AddHours(2), fixture.NewStore().Load()!.LastObservedUtc);
        Assert.Equal(Now.AddHours(2), SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!.LastObservedUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ObservedExpiry_SurvivesFreshComposition_AndPrimaryDeletion(bool deletePrimary)
    {
        using var fixture = new NativeFixture();
        fixture.WriteLicense(fixture.Payload with { ExpiresAt = Now.AddHours(1) });
        Guid? accepted;
        using (var first = fixture.NewService())
        {
            Assert.True(first.Load().IsValid);
            accepted = first.CurrentLicense!.Payload.LicenseId;
            fixture.Clock.UtcNow = Now.AddHours(2);
            Assert.Equal(LicenseState.Expired, first.Revalidate().State);
        }

        if (deletePrimary)
        {
            File.Delete(fixture.Paths.StateStorePath);
            var recovered = fixture.NewStore().Load()!;
            Assert.Null(recovered.LastValidatedUtc);
            Assert.Equal(Now.AddHours(2), recovered.LastObservedUtc);
            Assert.Equal(accepted, recovered.LastAcceptedLicenseId);
        }

        var restartedClock = new TestClock(Now.AddMinutes(30));
        using var restarted = fixture.NewService(clock: restartedClock);
        Assert.Equal(LicenseReasons.ClockRollbackDetected, restarted.Load().ReasonCode);
        Assert.False(restarted.Enforcement.RequireValidLicense().IsAllowed);
        Assert.Equal(LicenseState.LockedDown, restarted.CurrentState);
        Assert.Equal(Now.AddHours(2), SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!.LastObservedUtc);
        if (deletePrimary)
            Assert.Contains(fixture.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseStateDeletionRecovered);

        restartedClock.UtcNow = Now.AddHours(3);
        Assert.Equal(LicenseState.Expired, restarted.Revalidate().State); // forward time cannot revive expiry either
    }

    [Fact]
    public void MissingWitness_IsRepairedBeforeAuthorization_WithoutLosingPrimaryTime()
    {
        using var fixture = new NativeFixture();
        using var service = fixture.NewService();
        Assert.True(service.Load().IsValid);
        File.Delete(fixture.Paths.StateWitnessPath);
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.True(service.Enforcement.RequireValidLicense().IsAllowed);
        Assert.Equal(fixture.Clock.UtcNow, SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!.LastObservedUtc);

        File.Delete(fixture.Paths.StateWitnessPath);
        fixture.Clock.UtcNow = Now;
        using var restarted = fixture.NewService();
        Assert.Equal(LicenseReasons.ClockRollbackDetected, restarted.Load().ReasonCode);
        Assert.Equal(Now.AddMinutes(1), fixture.NewStore().Load()!.LastObservedUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LegacyPrimaryAndWitness_MigrateWithoutReactivation(bool hasValidationTime)
    {
        using var fixture = new NativeFixture();
        var payload = fixture.Payload with { SequenceNumber = 7 };
        fixture.WriteLicense(payload, activationCode: "1234567890");
        File.WriteAllText(fixture.Paths.StateStorePath, JsonSerializer.Serialize(new LicenseStateRecord
        {
            HighestAcceptedSequenceNumber = 7,
            LastAcceptedLicenseId = payload.LicenseId,
            ActivatedLicenseId = payload.LicenseId,
            LastValidatedUtc = hasValidationTime ? Now.AddHours(-1) : null
        }));
        SspLicenseStateWitnessStore.Save(fixture.Paths.StateWitnessPath, new LicenseStateWitness
        {
            HighestAcceptedSequenceNumber = 7,
            LastAcceptedLicenseId = payload.LicenseId,
            ActivatedLicenseId = payload.LicenseId
        });

        using var service = fixture.NewService();
        Assert.True(service.Load().IsValid);
        var migrated = fixture.NewStore().Load()!;
        var witnessed = SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!;
        Assert.Equal(1, migrated.ClockStateVersion);
        Assert.Equal(1, witnessed.ClockStateVersion);
        Assert.Equal(Now, migrated.LastObservedUtc);
        Assert.Equal(Now, witnessed.LastObservedUtc);
        Assert.Equal("installation-a", migrated.InstallationId);
        Assert.Equal(7, migrated.HighestAcceptedSequenceNumber);
        Assert.Equal(payload.LicenseId, migrated.LastAcceptedLicenseId);
        Assert.Equal(payload.LicenseId, migrated.ActivatedLicenseId);
        Assert.Equal(payload.LicenseId, witnessed.ActivatedLicenseId);
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(File.ReadAllBytes(fixture.Paths.StateStorePath)));
    }

    [Fact]
    public void LegacyFutureValidationTime_CannotBeReplacedByMigration()
    {
        using var fixture = new NativeFixture();
        File.WriteAllText(fixture.Paths.StateStorePath, JsonSerializer.Serialize(new LicenseStateRecord
        {
            LastValidatedUtc = Now.AddHours(1)
        }));
        using var service = fixture.NewService();
        Assert.Equal(LicenseReasons.ClockRollbackDetected, service.Load().ReasonCode);
        var retained = fixture.NewStore().Load()!;
        Assert.Equal(Now.AddHours(1), retained.LastValidatedUtc);
        Assert.Equal(0, retained.ClockStateVersion);
    }

    [Theory]
    [InlineData(1, null, false, false)]
    [InlineData(2, "2030-01-01T00:00:00Z", false, false)]
    [InlineData(0, "2030-01-01T00:00:00Z", false, false)]
    [InlineData(1, "invalid-time", false, false)]
    [InlineData(1, "2030-01-01T00:00:00Z", true, false)]
    [InlineData(1, null, false, true)]
    [InlineData(2, "2030-01-01T00:00:00Z", false, true)]
    [InlineData(0, "2030-01-01T00:00:00Z", false, true)]
    [InlineData(1, "invalid-time", false, true)]
    [InlineData(1, "2030-01-01T00:00:00Z", true, true)]
    public async Task InvalidOrUnprotectedClockMetadata_FailsClosedWithoutReset(
        int version, string? timestamp, bool plaintext, bool inWitness)
    {
        using var fixture = new NativeFixture();
        var path = inWitness ? fixture.Paths.StateWitnessPath : fixture.Paths.StateStorePath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(new { ClockStateVersion = version, LastObservedUtc = timestamp });
        if (plaintext) File.WriteAllText(path, json);
        else await ProtectedFileStore.WriteTextAsync(path, json);
        var original = File.ReadAllBytes(path);

        using var service = fixture.NewService();
        Assert.Equal(LicenseReasons.StateStoreUnavailable, service.Load().ReasonCode);
        Assert.Equal(LicenseState.LockedDown, service.CurrentState);
        Assert.False(service.Enforcement.RequireValidLicense().IsAllowed);
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CorruptClockHistory_CannotBeHealedBySavingALegacyRecord(bool corruptWitness)
    {
        using var fixture = new NativeFixture();
        fixture.NewStore().Save(new LicenseStateRecord { ClockStateVersion = 1, LastObservedUtc = Now.AddHours(2) });
        var corruptPath = corruptWitness ? fixture.Paths.StateWitnessPath : fixture.Paths.StateStorePath;
        var intactPath = corruptWitness ? fixture.Paths.StateStorePath : fixture.Paths.StateWitnessPath;
        var intact = File.ReadAllBytes(intactPath);
        File.WriteAllText(corruptPath, "corrupt protected history");
        Assert.Throws<InvalidDataException>(() => fixture.NewStore().Save(new LicenseStateRecord()));
        Assert.Equal("corrupt protected history", File.ReadAllText(corruptPath));
        Assert.Equal(intact, File.ReadAllBytes(intactPath));
    }

    [Fact]
    public void ForeignWitnessTime_FailsClosedWithoutReplacingEitherCopy()
    {
        using var fixture = new NativeFixture();
        fixture.NewStore().Save(new LicenseStateRecord { ClockStateVersion = 1, LastObservedUtc = Now });
        var witness = SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!;
        SspLicenseStateWitnessStore.Save(fixture.Paths.StateWitnessPath, witness with { InstallationId = "foreign-installation" });
        var primaryBytes = File.ReadAllBytes(fixture.Paths.StateStorePath);
        var witnessBytes = File.ReadAllBytes(fixture.Paths.StateWitnessPath);
        using var service = fixture.NewService();
        Assert.Equal(LicenseReasons.StateStoreUnavailable, service.Load().ReasonCode);
        Assert.Equal(primaryBytes, File.ReadAllBytes(fixture.Paths.StateStorePath));
        Assert.Equal(witnessBytes, File.ReadAllBytes(fixture.Paths.StateWitnessPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReplayingEitherCopy_CannotLowerRetainedTime(bool replayPrimary)
    {
        using var fixture = new NativeFixture();
        using var first = fixture.NewService();
        Assert.True(first.Load().IsValid);
        var replayPath = replayPrimary ? fixture.Paths.StateStorePath : fixture.Paths.StateWitnessPath;
        var oldBytes = File.ReadAllBytes(replayPath);
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        Assert.True(first.Enforcement.RequireValidLicense().IsAllowed);
        File.WriteAllBytes(replayPath, oldBytes);
        fixture.Clock.UtcNow = Now.AddMinutes(30);

        using var restarted = fixture.NewService();
        var result = restarted.Load();
        Assert.Equal(replayPrimary ? LicenseReasons.StateStoreUnavailable : LicenseReasons.ClockRollbackDetected, result.ReasonCode);
        Assert.False(result.IsValid);
        if (replayPrimary)
            Assert.Contains(fixture.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.LicenseStateRollbackDetected);
        else
            Assert.Equal(Now.AddHours(1), fixture.NewStore().Load()!.LastObservedUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ActualPrimaryOrWitnessWriteFailure_DeniesAnAlreadyValidRuntime(bool failWitness)
    {
        using var fixture = new NativeFixture();
        using var service = fixture.NewService();
        Assert.True(service.Load().IsValid);
        var primaryBefore = File.ReadAllBytes(fixture.Paths.StateStorePath);
        var witnessBefore = File.ReadAllBytes(fixture.Paths.StateWitnessPath);

        // AtomicFile uses path + ".tmp". A directory there deterministically
        // fails the WRITE, not Load, on Windows and Unix, even for an admin.
        var blockedTemp = (failWitness ? fixture.Paths.StateWitnessPath : fixture.Paths.StateStorePath) + ".tmp";
        Directory.CreateDirectory(blockedTemp);
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        Assert.False(service.Enforcement.RequireValidLicense().IsAllowed);
        Assert.Equal(LicenseReasons.StateStoreUnavailable, service.LastValidationResult!.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, service.CurrentState);
        Assert.Null(service.CurrentLicense);
        Assert.Equal(witnessBefore, File.ReadAllBytes(fixture.Paths.StateWitnessPath));
        if (!failWitness) Assert.Equal(primaryBefore, File.ReadAllBytes(fixture.Paths.StateStorePath));
        else Assert.Equal(Now.AddHours(1), fixture.NewStore().Load()!.LastObservedUtc);

        Directory.Delete(blockedTemp);
        fixture.Clock.UtcNow = Now.AddMinutes(30);
        Assert.Equal(LicenseReasons.ClockRollbackDetected, service.Revalidate().ReasonCode); // also retains failed-write time in memory
        fixture.Clock.UtcNow = Now.AddHours(1);
        Assert.True(service.Revalidate().IsValid);
        Assert.Equal(Now.AddHours(1), SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!.LastObservedUtc);
    }

    [Fact]
    public void MissingWitnessWithFailedRepair_NeverAuthorizes()
    {
        using var fixture = new NativeFixture();
        using var service = fixture.NewService();
        Assert.True(service.Load().IsValid);
        File.Delete(fixture.Paths.StateWitnessPath);
        Directory.CreateDirectory(fixture.Paths.StateWitnessPath + ".tmp");
        Assert.False(service.Enforcement.RequireValidLicense().IsAllowed);
        Assert.Equal(LicenseReasons.StateStoreUnavailable, service.LastValidationResult!.ReasonCode);
        Assert.False(File.Exists(fixture.Paths.StateWitnessPath));
    }

    [Fact]
    public void UnavailableStateLease_FailsClosed()
    {
        using var fixture = new NativeFixture();
        Directory.CreateDirectory(fixture.Paths.StateStorePath + ".lock");
        using var service = fixture.NewService();
        Assert.Equal(LicenseReasons.StateStoreUnavailable, service.Load().ReasonCode);
        Assert.False(service.Enforcement.RequireValidLicense().IsAllowed);
    }

    [Fact]
    public async Task SeparateStoreInstances_SerializeForwardSamplesWithoutFalseRollback()
    {
        using var fixture = new NativeFixture();
        var clock = new IncrementingClock();
        using var first = fixture.NewService(clock: clock);
        var aliasPath = Path.Combine(fixture.Paths.LicenseDirectory, ".", SspLicenseStateStore.DefaultFileName);
        using var second = fixture.NewService(new SspLicenseStateStore(aliasPath, "installation-a"), clock);
        Assert.True(first.Load().IsValid);
        Assert.True(second.Load().IsValid);
        var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(i => Task.Run(() =>
            (i % 2 == 0 ? first : second).Enforcement.RequireValidLicense())));
        Assert.All(results, result => Assert.True(result.IsAllowed, result.Detail));
        Assert.True(fixture.NewStore().Load()!.LastObservedUtc > Now);
        Assert.DoesNotContain(fixture.Events.Snapshot(), e => e.EventType == LicenseSecurityEventType.ClockRollbackDetected);
    }

    [Fact]
    public async Task DelayedTimeOnlyWriter_CannotEraseConcurrentRenewalOrActivation()
    {
        using var fixture = new NativeFixture();
        using var enteredSave = new ManualResetEventSlim();
        using var releaseSave = new ManualResetEventSlim();
        using var enteredOtherLease = new ManualResetEventSlim();
        var timeStore = new ObservedStore(fixture.NewStore());
        var otherStore = new ObservedStore(fixture.NewStore());
        using var first = fixture.NewService(timeStore);
        using var second = fixture.NewService(otherStore);
        Assert.True(first.Load().IsValid);
        var renewal = fixture.Payload with { LicenseId = Guid.NewGuid(), SequenceNumber = 2 };
        fixture.WriteLicense(renewal, activationCode: "1234567890");
        Assert.Equal(LicenseState.ActivationRequired, second.Load().State);
        fixture.Clock.Advance(TimeSpan.FromHours(1));

        timeStore.BeforeSave = _ =>
        {
            enteredSave.Set();
            if (!releaseSave.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("test writer was not released");
        };
        otherStore.BeforeLease = enteredOtherLease.Set;
        var timeWriter = Task.Run(() => first.Enforcement.RequireValidLicense());
        Task<LicenseValidationResult>? activation = null;
        try
        {
            Assert.True(enteredSave.Wait(TimeSpan.FromSeconds(5)));
            activation = Task.Run(() => second.TryActivate("1234567890"));
            Assert.True(enteredOtherLease.Wait(TimeSpan.FromSeconds(5)));
            var completed = await Task.WhenAny(activation, Task.Delay(150));
            Assert.NotSame(activation, completed); // the full RMW lease, not just Save, is held
        }
        finally { releaseSave.Set(); }

        Assert.True((await timeWriter.WaitAsync(TimeSpan.FromSeconds(10))).IsAllowed);
        Assert.True((await activation!.WaitAsync(TimeSpan.FromSeconds(10))).IsValid);
        var state = fixture.NewStore().Load()!;
        var witness = SspLicenseStateWitnessStore.Load(fixture.Paths.StateWitnessPath)!;
        Assert.Equal(2, state.HighestAcceptedSequenceNumber);
        Assert.Equal(renewal.LicenseId, state.LastAcceptedLicenseId);
        Assert.Equal(renewal.LicenseId, state.ActivatedLicenseId);
        Assert.Equal(state.ActivatedLicenseId, witness.ActivatedLicenseId);
        Assert.Equal(Now.AddHours(1), state.LastObservedUtc);
        Assert.Equal(state.LastObservedUtc, witness.LastObservedUtc);
    }

    // The same test in a filtered child testhost is a small test-only lock probe.
    // This exercises the actual .NET file lease across PROCESSES, without adding
    // a production CLI switch, native utility, shell, or another build project.
    private const string ProbePipeVariable = "SSP_TEST_CLOCK_LOCK_PROBE_PIPE";
    private const string ProbeStateVariable = "SSP_TEST_CLOCK_LOCK_PROBE_STATE";

    // The child is a second full `dotnet vstest` host. Under the parallel
    // suite that host can take tens of seconds just to start (testhost
    // spawn + discovery on a loaded machine), and the assertions below must
    // stay sequential. Every per-step window is therefore sized for a loaded
    // machine; the Fact timeout is only the final backstop against a child
    // that never connects at all.
    [Fact(Timeout = 300_000)]
    public async Task FileLease_IsExclusiveAcrossProcesses()
    {
        if (Environment.GetEnvironmentVariable(ProbePipeVariable) is { } childPipe)
        {
            RunLockProbe(childPipe, Environment.GetEnvironmentVariable(ProbeStateVariable)!);
            return;
        }

        using var fixture = new NativeFixture();
        using var service = fixture.NewService();
        Assert.True(service.Load().IsValid);
        var pipeName = "ssp-clock-lock-" + Guid.NewGuid().ToString("N");
        using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("vstest");
        start.ArgumentList.Add(typeof(ClockRollbackStateTests).Assembly.Location);
        start.ArgumentList.Add("/TestCaseFilter:FullyQualifiedName=SSP.Tests.Activation.ClockRollbackStateTests.FileLease_IsExclusiveAcrossProcesses");
        start.Environment[ProbePipeVariable] = pipeName;
        start.Environment[ProbeStateVariable] = fixture.Paths.StateStorePath;
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start lock-probe testhost.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            // The child testhost is only expected to connect once its full
            // discovery pass has run; under the parallel suite that alone can
            // take tens of seconds, so the connect window is the largest one.
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(100));
            await pipe.WaitForConnectionAsync(connectTimeout.Token);
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            using var writer = new StreamWriter(pipe, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
            Assert.Equal("locked", await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(30)));

            // The parent's lease acquisition is bounded (it must fail closed
            // while the child holds the lease), so the decision itself takes
            // the full acquisition bound; the cap only covers scheduling lag.
            var decision = await Task.Run(() => service.Enforcement.RequireValidLicense()).WaitAsync(TimeSpan.FromSeconds(60));
            Assert.False(decision.IsAllowed);
            Assert.Equal(LicenseReasons.StateStoreUnavailable, service.LastValidationResult!.ReasonCode);
            await writer.WriteLineAsync("release");
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));
            if (process.ExitCode != 0)
                Assert.True(false, await CollectChildOutputAsync(stdout, stderr));
            Assert.True(service.Revalidate().IsValid); // a stale empty .lock file is not a lock
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
            }
        }
    }

    private static void RunLockProbe(string pipeName, string statePath)
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
        pipe.Connect(60_000);
        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        using var writer = new StreamWriter(pipe, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
        // Synchronous lease: acquire and dispose on the same thread, no await.
        using var lease = ((ILicenseTimeStateLock)new SspLicenseStateStore(statePath)).AcquireTimeStateLock();
        writer.WriteLine("locked");
        Assert.Equal("release", reader.ReadLine());
    }

    /// <summary>
    /// Child stdout/stderr are only diagnostic text for the exit-code
    /// assertion. After the process exits the pipes close, but a lingering
    /// child (for example a testhost grandchild kept alive by a failed run)
    /// can hold them open, so the read must never block the test itself.
    /// </summary>
    private static async Task<string> CollectChildOutputAsync(Task<string> stdout, Task<string> stderr)
    {
        try
        {
            var output = await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(30));
            return output[0] + output[1];
        }
        catch (Exception ex)
        {
            return $"(child output unavailable: {ex.GetType().Name})";
        }
    }

    private sealed class ObservedStore : ILicenseStateStore, ILicenseTimeStateLock
    {
        private readonly SspLicenseStateStore _inner;
        internal ObservedStore(SspLicenseStateStore inner) => _inner = inner;
        internal Action<LicenseStateRecord>? BeforeSave { get; set; }
        internal Action? BeforeLease { get; set; }
        public LicenseStateRecord? Load() => _inner.Load();
        public void Save(LicenseStateRecord record) { BeforeSave?.Invoke(record); _inner.Save(record); }
        public IDisposable AcquireTimeStateLock()
        {
            BeforeLease?.Invoke();
            return ((ILicenseTimeStateLock)_inner).AcquireTimeStateLock();
        }
    }

    private sealed class IncrementingClock : IClock
    {
        private long _ticks = Now.Ticks;
        public DateTimeOffset UtcNow => new(Interlocked.Increment(ref _ticks), TimeSpan.Zero);
    }

    private sealed class NativeFixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "ssp-clock-state-" + Guid.NewGuid().ToString("N"));
        private readonly RSA _authority = RSA.Create(2048);
        internal NativeFixture()
        {
            Paths = SspLicensePaths.Resolve(Path.Combine(_root, "licensing"));
            Directory.CreateDirectory(Paths.LicenseDirectory);
            Payload = LicensedTestEnvironment.BuildPayload(new LicensedTestOptions { ExpiresAt = Now.AddDays(1) });
            WriteLicense(Payload);
        }

        internal SspLicensePaths Paths { get; }
        internal LicensePayload Payload { get; }
        internal TestClock Clock { get; } = new(Now);
        internal InMemorySecurityEventSink Events { get; } = new();
        internal SspLicenseStateStore NewStore(IClock? clock = null)
            => new(Paths.StateStorePath, "installation-a", Events, clock ?? Clock);
        internal SspActivationService NewService(ILicenseStateStore? store = null, IClock? clock = null)
            => SspActivationService.Compose(Paths, LicenseTrustAnchor.FromPublicKey(_authority),
                new StaticInstallationIdentityProvider("installation-a"), Events,
                store ?? NewStore(clock), new LocalLicenseFileProvider(Paths.LicenseFilePath), clock ?? Clock);

        internal void WriteLicense(LicensePayload payload, string? activationCode = null)
        {
            string artifact;
            if (activationCode is null) artifact = LicenseIssuer.EncodeLicenseArtifact(payload, _authority);
            else
            {
                using var leaf = RSA.Create(2048);
                var certification = new LicenseKeyCertification
                {
                    LicenseId = payload.LicenseId, ProductId = payload.ProductId, CustomerId = payload.CustomerId,
                    NotBefore = payload.IssuedAt, ExpiresAt = payload.ExpiresAt,
                    PublicKeySpkiDer = leaf.ExportSubjectPublicKeyInfo(),
                    ActivationCodeHash = LicenseActivation.ComputeActivationCodeHash(activationCode)
                };
                artifact = LicenseCertificationIssuer.EncodeCertifiedLicenseArtifact(payload, certification, _authority, leaf);
            }
            File.WriteAllText(Paths.LicenseFilePath, artifact);
        }

        public void Dispose()
        {
            _authority.Dispose();
            try { Directory.Delete(_root, recursive: true); } catch { /* test cleanup only */ }
        }
    }
}
