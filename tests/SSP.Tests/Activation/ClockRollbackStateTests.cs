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

    // The probe is a second genuine process: the lease is reentrant per
    // thread and its acquisition map is thread-local, so a second thread of
    // this process cannot stand in for a holder in another process. It is
    // this assembly's own entry point, started as the test apphost (or
    // `dotnet exec -- <dll>`), so it needs no production CLI switch, native
    // utility, shell or another build project, and - unlike a second
    // `dotnet vstest` host - no adapter discovery or test enumeration
    // before it begins holding the lease. DOTNET_HOST_PATH is not used as
    // the child image: under `dotnet test` it can point at testhost, which
    // waits for a runner that never connects. All steps below are
    // hard-bounded independently of named-pipe cancellation semantics, so a
    // dead probe fails fast with its captured output instead of hanging
    // until the Fact timeout.
    [Fact(Timeout = 120_000)]
    public async Task FileLease_IsExclusiveAcrossProcesses()
    {
        using var fixture = new NativeFixture();
        using var service = fixture.NewService();
        Assert.True(service.Load().IsValid);
        var pipeName = "ssp-clock-lock-" + Guid.NewGuid().ToString("N");
        using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var process = Process.Start(CreateProbeStartInfo(pipeName, fixture.Paths.StateStorePath))
            ?? throw new InvalidOperationException("Cannot start clock-lock probe.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            // Named-pipe wait cancellation depends on the pipe's overlapped
            // I/O mode, so a token alone is not a hard bound. Racing the
            // connect against a plain timer and the probe exit bounds the
            // wait regardless, and a probe that died early surfaces its
            // captured output instead of a silent hang.
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connect = pipe.WaitForConnectionAsync(connectTimeout.Token);
            var winner = await Task.WhenAny(connect, process.WaitForExitAsync(), Task.Delay(TimeSpan.FromSeconds(31)));
            if (winner != connect)
                Assert.Fail($"Clock-lock probe did not connect within 30 s:{Environment.NewLine}{await CollectChildOutputAsync(stdout, stderr)}");
            await connect;

            var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            using var reader = new StreamReader(pipe, utf8, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
            using var writer = new StreamWriter(pipe, utf8, bufferSize: 1024, leaveOpen: true) { AutoFlush = true };
            using var lockedTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            Assert.Equal("locked", await reader.ReadLineAsync(lockedTimeout.Token).AsTask());

            // The parent's lease acquisition is bounded (it must fail closed
            // while the child holds the lease), so the decision itself takes
            // the full acquisition bound; the cap only covers scheduling lag.
            var decision = await Task.Run(() => service.Enforcement.RequireValidLicense())
                .WaitAsync(TimeSpan.FromSeconds(45));
            Assert.False(decision.IsAllowed);
            Assert.Equal(LicenseReasons.StateStoreUnavailable, service.LastValidationResult!.ReasonCode);
            await writer.WriteLineAsync("release");
            await writer.FlushAsync();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
            if (process.ExitCode != 0)
                Assert.Fail(await CollectChildOutputAsync(stdout, stderr));
            Assert.True(service.Revalidate().IsValid); // a stale empty .lock file is not a lock
        }
        finally
        {
            TryStopProbe(process);
        }
    }

    /// <summary>
    /// Launch this assembly's own entry point without going through testhost.
    /// Prefer the apphost emitted because OutputType=Exe; fall back to the
    /// dotnet muxer (never testhost via DOTNET_HOST_PATH). Strip VSTest
    /// hooks so the child cannot wait for a debugger or runner.
    /// </summary>
    private static ProcessStartInfo CreateProbeStartInfo(string pipeName, string statePath)
    {
        var assemblyPath = typeof(ClockRollbackStateTests).Assembly.Location;
        var directory = Path.GetDirectoryName(assemblyPath);
        if (string.IsNullOrEmpty(directory) || !File.Exists(assemblyPath))
        {
            directory = AppContext.BaseDirectory;
            assemblyPath = Path.Combine(directory, "SSP.Tests.dll");
        }

        var start = new ProcessStartInfo
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = directory
        };

        var apphost = Path.Combine(directory, OperatingSystem.IsWindows() ? "SSP.Tests.exe" : "SSP.Tests");
        if (File.Exists(apphost))
        {
            start.FileName = apphost;
        }
        else
        {
            start.FileName = ResolveDotnetMuxer();
            start.ArgumentList.Add("exec");
            start.ArgumentList.Add(assemblyPath);
            start.ArgumentList.Add("--");
        }

        start.ArgumentList.Add(ClockLockProbe.Command);
        start.ArgumentList.Add(pipeName);
        start.ArgumentList.Add(statePath);

        start.Environment.Remove("DOTNET_STARTUP_HOOKS");
        start.Environment.Remove("DOTNET_INSERT_LIBC_HOOKS");
        start.Environment.Remove("VSTEST_HOST_DEBUG");
        start.Environment.Remove("VSTEST_RUNNER_DEBUG");
        start.Environment.Remove("VSTEST_CONNECTION_TIMEOUT");
        return start;
    }

    private static string ResolveDotnetMuxer()
    {
        var configured = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured))
        {
            var name = Path.GetFileNameWithoutExtension(configured);
            if (string.Equals(name, "dotnet", StringComparison.OrdinalIgnoreCase))
                return configured;
        }

        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath) &&
            string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase) &&
            File.Exists(processPath))
        {
            return processPath;
        }

        return OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
    }

    private static void TryStopProbe(Process process)
    {
        try
        {
            if (process.HasExited) return;
        }
        catch { return; }

        try
        {
            var stop = Task.Run(() =>
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { /* best effort */ }
                try { process.WaitForExit(5_000); } catch { /* best effort */ }
            });
            stop.Wait(TimeSpan.FromSeconds(8));
        }
        catch
        {
            // A stuck kill must not keep the test running until the Fact timeout.
        }
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
            var output = await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(5));
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
