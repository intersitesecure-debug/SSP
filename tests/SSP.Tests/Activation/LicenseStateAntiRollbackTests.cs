// File: tests/SSP.Tests/Activation/LicenseStateAntiRollbackTests.cs
//
// Phase 4 (M-3) of the Security Correction roadmap: license state
// anti-rollback protection. These tests pin the three attacks a single
// durable state file could not answer:
//
//   * DELETION  - deleting .license-state.dat must NOT turn the machine into
//     a fresh installation: the floor is recovered from the redundant
//     witness (stored OUTSIDE the licensing directory) and an old license
//     stays denied.
//   * ROLLBACK  - restoring an older copy of .license-state.dat is detected
//     through the monotonic state epoch (the witnessed epoch is higher than
//     the file's) and fails closed.
//   * REVIVAL   - end to end, an older artifact presented after a deletion
//     or rollback attempt must never reach LicenseState.Valid.
//
// Plus the integrity failure modes: corrupt / plaintext / foreign witness
// material fails closed; a missing witness is never a violation; the witness
// write is monotonic and never regresses; the witness is encrypted at rest;
// and a genuinely fresh installation (no state file, no witness) still sees
// a null floor.

using System.Text;
using SSP.Activation;
using SSP.Core.IO;
using SSP.Server.Activation;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation;

public class LicenseStateAntiRollbackTests
{
    // ────────────────────────────────────────────────────────────────
    // Store-level: deletion, recovery, integrity
    // ────────────────────────────────────────────────────────────────

    [Fact]
    public void StateFileDeleted_WitnessRecoversFloorAndReportsEvent()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var witnessPath = WitnessPathFor(dir);
            var events = new InMemorySecurityEventSink();
            var store = new SspLicenseStateStore(statePath, "installation-a", events);

            // Sanity: the store's auto-derived witness path matches the
            // canonical derivation (SspLicensePaths.StateWitnessPath is
            // defined through the same helper).
            Assert.Equal(witnessPath, store.WitnessPath);

            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 7 });
            Assert.True(File.Exists(witnessPath), "A save must establish the witness.");

            // The attack: delete only the state file.
            File.Delete(statePath);

            var recovered = store.Load();

            // The floor is recovered from the witness — the deletion did NOT
            // reset the machine to a fresh installation.
            Assert.NotNull(recovered);
            Assert.Equal(7, recovered!.HighestAcceptedSequenceNumber);
            Assert.Equal("installation-a", recovered.InstallationId);

            Assert.Contains(events.Snapshot(), e =>
                e.EventType == LicenseSecurityEventType.LicenseStateDeletionRecovered);
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void StateFileDeleted_ActivationStateIsRecoveredFromWitness()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var activated = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");
            var store = new SspLicenseStateStore(statePath, "installation-a");

            store.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = 3,
                ActivatedLicenseId = activated,
            });

            File.Delete(statePath);

            var recovered = store.Load();
            Assert.NotNull(recovered);
            Assert.Equal(activated, recovered!.ActivatedLicenseId);
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void StateFileRolledBack_FailsClosedAndReportsEvent()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var events = new InMemorySecurityEventSink();
            var store = new SspLicenseStateStore(statePath, "installation-a", events);

            // An older state of the world (floor 2, epoch 1)...
            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 2 });
            var olderBytes = File.ReadAllBytes(statePath);

            // ...superseded by a newer one (floor 5, epoch 2).
            store.Save(store.Load()! with { HighestAcceptedSequenceNumber = 5 });
            Assert.True(File.Exists(WitnessPathFor(dir)));

            // The attack: restore the older copy over the newer file.
            File.WriteAllBytes(statePath, olderBytes);

            var ex = Assert.Throws<InvalidDataException>(() => store.Load());
            Assert.Contains("rollback", ex.Message, StringComparison.OrdinalIgnoreCase);

            Assert.Contains(events.Snapshot(), e =>
                e.EventType == LicenseSecurityEventType.LicenseStateRollbackDetected);
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void MissingWitness_IsNotAViolation_PrimaryStaysAuthoritative()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(statePath, "installation-a");

            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 7 });

            // The attack (weak variant): remove only the witness. The primary
            // is intact and consistent, so the state still loads; the next
            // save re-establishes the witness.
            File.Delete(WitnessPathFor(dir));

            var loaded = store.Load();
            Assert.NotNull(loaded);
            Assert.Equal(7, loaded!.HighestAcceptedSequenceNumber);

            store.Save(loaded! with { HighestAcceptedSequenceNumber = 9 });
            Assert.True(File.Exists(WitnessPathFor(dir)));
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void CorruptWitness_FailsClosed()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(statePath, "installation-a");
            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 7 });

            // The attack: corrupt the witness in place.
            File.WriteAllBytes(WitnessPathFor(dir), "not-an-envelope"u8.ToArray());

            Assert.Throws<InvalidDataException>(() => store.Load());
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void PlaintextWitness_FailsClosed()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(statePath, "installation-a");
            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 7 });

            // The attack: hand-craft a plaintext (valid-JSON) witness. A
            // legitimate witness is always envelope-encrypted, so plaintext
            // material in the witness slot is tampering and fails closed.
            File.WriteAllText(
                WitnessPathFor(dir),
                "{\"installationId\":\"installation-a\",\"stateEpoch\":99,\"highestAcceptedSequenceNumber\":99}");

            Assert.Throws<InvalidDataException>(() => store.Load());
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void ForeignWitness_FailsClosed()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);

            // Witness written while bound to installation A...
            new SspLicenseStateStore(statePath, "installation-a")
                .Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 7 });

            // ...presented to installation B: foreign witness material fails
            // closed instead of being trusted for recovery.
            var foreign = new SspLicenseStateStore(statePath, "installation-b");
            Assert.Throws<InvalidDataException>(() => foreign.Load());
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void Witness_NeverRegresses_EpochOrFloor()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var witnessPath = WitnessPathFor(dir);
            var store = new SspLicenseStateStore(statePath, "installation-a");

            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 5 });
            var witnessed = SspLicenseStateWitnessStore.Load(witnessPath);
            Assert.NotNull(witnessed);
            Assert.Equal(5, witnessed!.HighestAcceptedSequenceNumber);

            // A stale (or tampered) primary save must never drag the witness
            // backwards: the write max-merges with the durable witness.
            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 3 });

            var after = SspLicenseStateWitnessStore.Load(witnessPath);
            Assert.NotNull(after);
            Assert.True(after!.HighestAcceptedSequenceNumber >= 5,
                $"Witness floor regressed to {after.HighestAcceptedSequenceNumber}.");
            Assert.True(after.StateEpoch > witnessed.StateEpoch,
                "Witness epoch must advance on every save.");
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void WitnessFile_IsEncryptedAtRest()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var licenseId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");
            var store = new SspLicenseStateStore(statePath, "installation-a");

            store.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = 7,
                LastAcceptedLicenseId = licenseId,
            });

            var bytes = File.ReadAllBytes(WitnessPathFor(dir));
            Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes),
                "Witness file is not in the SSP encrypted-at-rest envelope.");

            var directText = Encoding.UTF8.GetString(bytes);
            Assert.DoesNotContain("HighestAcceptedSequenceNumber", directText, StringComparison.Ordinal);
            Assert.DoesNotContain("installation-a", directText, StringComparison.Ordinal);
            Assert.DoesNotContain(licenseId.ToString(), directText, StringComparison.Ordinal);
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void FreshInstallation_NoStateNoWitness_ReturnsNullFloor()
    {
        var dir = CreateTempDir();
        try
        {
            var statePath = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(statePath, "installation-a");

            Assert.Null(store.Load());
            Assert.False(File.Exists(WitnessPathFor(dir)));
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public void CanonicalWitnessPath_MatchesSspLicensePathsDerivation()
    {
        var dir = CreateTempDir();
        try
        {
            var paths = SspLicensePaths.Resolve(dir);
            var store = new SspLicenseStateStore(paths.StateStorePath, "installation-a");

            // The composition root (SspActivationService.Create) passes
            // paths.StateWitnessPath explicitly; a bare store derives the
            // same path from the state file. The two must never disagree.
            Assert.Equal(paths.StateWitnessPath, store.WitnessPath);
        }
        finally
        {
            Cleanup(dir);
        }
    }

    // ────────────────────────────────────────────────────────────────
    // End to end (LicensedTestEnvironment): deletion / rollback / revival
    // ────────────────────────────────────────────────────────────────

    [Fact]
    public void EndToEnd_DeletedStateFile_OldLicenseRevivalIsDenied()
    {
        var options = new LicensedTestOptions { SequenceNumber = 5 };
        using var env = LicensedTestEnvironment.Create(options);

        // Establish the durable floor of 5.
        Assert.True(env.Load().IsValid);

        // The attack: delete the state file and install an older, still
        // unexpired artifact (sequence 4). Without the witness this was a
        // working revival: the machine looked freshly installed.
        File.Delete(env.StateStorePath);
        env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
        {
            SequenceNumber = 4,
            ApplicationName = options.ApplicationName,
        }));

        var result = env.Reload();

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.Superseded, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);
    }

    [Fact]
    public void EndToEnd_RolledBackStateFile_FailsClosedAndDeniesEverything()
    {
        var options = new LicensedTestOptions { SequenceNumber = 2 };
        using var env = LicensedTestEnvironment.Create(options);

        // An older state of the world (floor 2)...
        Assert.True(env.Load().IsValid);
        var olderStateBytes = File.ReadAllBytes(env.StateStorePath);

        // ...superseded by a newer artifact (floor 5).
        env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
        {
            SequenceNumber = 5,
            ApplicationName = options.ApplicationName,
        }));
        Assert.True(env.Reload().IsValid);

        // The attack: restore the older state file and present an artifact
        // that the rolled-back floor would accept (sequence 4).
        File.WriteAllBytes(env.StateStorePath, olderStateBytes);
        env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
        {
            SequenceNumber = 4,
            ApplicationName = options.ApplicationName,
        }));

        var result = env.Reload();

        // Rollback detection fails closed: the state store is unavailable,
        // the runtime locks down and every protected operation is denied.
        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.StateStoreUnavailable, result.ReasonCode);
        Assert.Equal(LicenseState.LockedDown, env.State);

        using var admission = env.Gate.AdmitTunnel();
        Assert.False(admission.IsAdmitted);
    }

    [Fact]
    public void EndToEnd_AfterDeletion_ANewerLicenseStillRecovers()
    {
        // Fail-closed must not mean bricked: after a deletion attempt the
        // floor is recovered from the witness, so installing a NEWER artifact
        // re-validates normally. Only the revival of OLD state is denied.
        var options = new LicensedTestOptions { SequenceNumber = 5 };
        using var env = LicensedTestEnvironment.Create(options);

        Assert.True(env.Load().IsValid);
        File.Delete(env.StateStorePath);

        env.WriteLicense(LicensedTestEnvironment.BuildPayload(new LicensedTestOptions
        {
            SequenceNumber = 6,
            ApplicationName = options.ApplicationName,
        }));

        var result = env.Reload();

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, env.State);
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    private static string WitnessPathFor(string licensingDirectory) =>
        SspStateWitnessPaths.GetWitnessPath(licensingDirectory, SspStateWitnessPaths.LicenseStatePurpose);

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-license-antirb-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void Cleanup(string dir)
    {
        TryDelete(dir);

        // The witness lives OUTSIDE dir (one level above, keyed by a hash of
        // dir), so it must be cleaned separately. The hash key makes this
        // subtree unique to this test; deleting it cannot touch another
        // test's witness.
        var witnessPath = WitnessPathFor(dir);
        try { File.Delete(witnessPath); } catch { /* best effort */ }
        try { Directory.Delete(Path.GetDirectoryName(witnessPath)!, recursive: true); } catch { /* best effort */ }
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
