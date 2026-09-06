// File: src/SSP.Server/Activation/SspLicenseStateStore.cs
//
// SSP-native durable anti-rollback state store. It persists the
// LicenseStateRecord (highest accepted sequence number and diagnostics)
// through SSP.Core.ProtectedFileStore, so the file is written in the SSP-EAR1
// encrypted-at-rest envelope: DPAPI LocalMachine on Windows (the recorded
// floor cannot be decrypted by a copied licensing folder on another machine)
// and the repo's existing non-Windows AES-GCM fallback for cross-platform
// tests. Reads fail closed: DPAPI, I/O, authorization or JSON failures throw,
// which the licensing validator maps to state_store_unavailable.
//
// Phase 4 (M-3) of the Security Correction roadmap adds three defenses on top
// of the encrypted envelope:
//
//   * INSTALLATION BINDING - every saved record is stamped with a
//     domain-separated installation id (SspInstallationIdentityProvider.
//     GetLicenseStateBindingId). A record that names a different
//     installation fails closed instead of silently resetting this
//     installation's floor, so state replayed from another machine (or
//     another installation of this machine) can never lower the floor.
//     Pre-Phase-4 records carry no binding and are adopted and upgraded on
//     the next save, never rejected.
//
//   * MONOTONIC STATE EPOCH - every save increments a persisted write
//     counter. The counter never decreases on a legitimate installation, so
//     a durable value higher than the file's value proves the file is an
//     older copy.
//
//   * REDUNDANT WITNESS (SspLicenseStateWitness) - a second, envelope-
//     encrypted copy of the binding, the epoch and the floor, stored OUTSIDE
//     the licensing directory (see SspStateWitnessPaths). It closes the two
//     attacks the single file could not answer:
//       - DELETION: a missing state file with an intact witness is NOT a
//         fresh installation. The floor (and activation state) is recovered
//         from the witness, LicenseStateDeletionRecovered is reported, and a
//         superseded license stays denied.
//       - ROLLBACK: a state file whose epoch is LOWER than the witnessed
//         epoch is an older copy. The load fails closed
//         (state_store_unavailable), LicenseStateRollbackDetected is
//         reported, and validation denies.
//     A present-but-corrupt, plaintext or foreign-bound witness is an
//     integrity violation and fails closed. An intact, consistent primary
//     can recover a MISSING witness. Phase 6 additionally requires that
//     recovery write to complete before authorization.
//
// The store is never a security boundary: it can only restrict
// authorization, never grant it. Phase 6 (M-6) adds a versioned monotonic UTC
// checkpoint to both copies, with mandatory checkpoint writes and a local
// cross-process lease. The Phase 4 binding/epoch/sequence rules are unchanged.
// Nothing here can restore authorization that
// the signed artifact and the witnessed floor do not already allow.

using System.Security.Cryptography;
using System.Text.Json;
using SSP.Activation;
using SSP.Core.IO;

namespace SSP.Server.Activation;

/// <summary>
/// Durable, tamper-resistant (DPAPI-backed) anti-rollback floor for
/// <see cref="SSP.Activation.LicenseManager"/>. The store is never a security
/// boundary: it can only restrict authorization, never grant it.
/// </summary>
public sealed class SspLicenseStateStore : ILicenseStateStore, ILicenseTimeStateLock
{
    /// <summary>Canonical name of the encrypted state file.</summary>
    public const string DefaultFileName = ".license-state.dat";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };

    private readonly string _path;
    private readonly string _witnessPath;
    private readonly string? _installationStateBindingId;
    private readonly ISecurityEventSink? _eventSink;
    private readonly IClock? _clock;
    private readonly object _gate = new();

    /// <summary>
    /// Creates the store.
    /// </summary>
    /// <param name="path">Path of the encrypted state file.</param>
    /// <param name="installationStateBindingId">
    /// Optional installation identity the persisted state is bound to (see
    /// <see cref="SspInstallationIdentityProvider.GetLicenseStateBindingId"/>).
    /// When null (non-Windows hosts, or stores composed without an identity)
    /// the store runs unbound: records are neither stamped nor checked,
    /// exactly the pre-Phase-4 behaviour.
    /// </param>
    /// <param name="eventSink">
    /// Optional sink for the Phase 4 detection events
    /// (<see cref="LicenseSecurityEventType.LicenseStateRollbackDetected"/>,
    /// <see cref="LicenseSecurityEventType.LicenseStateDeletionRecovered"/>).
    /// Reporting is best effort and never changes the fail-closed decision.
    /// </param>
    /// <param name="clock">Optional clock for event timestamps (tests).</param>
    /// <param name="witnessPath">
    /// Optional explicit witness path. When null the witness path is derived
    /// from the state file's directory through
    /// <see cref="SspStateWitnessPaths"/> (one directory level ABOVE the
    /// licensing directory, so restoring or deleting the licensing directory
    /// cannot take the witness with it).
    /// </param>
    public SspLicenseStateStore(
        string path,
        string? installationStateBindingId = null,
        ISecurityEventSink? eventSink = null,
        IClock? clock = null,
        string? witnessPath = null)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("State store path must not be null or empty.", nameof(path));
        }

        _path = path;
        _installationStateBindingId = string.IsNullOrWhiteSpace(installationStateBindingId)
            ? null
            : installationStateBindingId;
        _eventSink = eventSink;
        _clock = clock;

        var stateDirectory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
        if (string.IsNullOrEmpty(stateDirectory))
        {
            stateDirectory = ".";
        }

        _witnessPath = string.IsNullOrWhiteSpace(witnessPath)
            ? SspStateWitnessPaths.GetWitnessPath(stateDirectory, SspStateWitnessPaths.LicenseStatePurpose)
            : witnessPath;
    }

    /// <summary>The path of the underlying encrypted state file.</summary>
    public string Path => _path;

    /// <summary>The path of the redundant encrypted witness file.</summary>
    public string WitnessPath => _witnessPath;

    // A time observation holds this across Load + Save. Load/Save also acquire
    // it reentrantly, including calls made through other store instances.
    IDisposable ILicenseTimeStateLock.AcquireTimeStateLock()
        => SspLicenseStateFileLock.Acquire(_path);

    /// <inheritdoc />
    /// <remarks>
    /// A missing file with no witness means no anti-rollback floor has been
    /// established yet (fresh installation). A missing file WITH a witness is
    /// a deletion attempt: the floor is recovered from the witness and a
    /// <see cref="LicenseSecurityEventType.LicenseStateDeletionRecovered"/>
    /// event is reported. Any present-but-corrupt/unreadable file or witness
    /// throws so the validator fails closed rather than silently resetting
    /// the floor. A state file older than the witness (epoch regression)
    /// throws: that is a rollback.
    /// </remarks>
    public LicenseStateRecord? Load()
    {
        using var stateLock = SspLicenseStateFileLock.Acquire(_path);
        lock (_gate)
        {
            // The witness is read first: it is what turns "file missing" from
            // "fresh install" into "deletion attempt", and its epoch is what
            // makes an older copy of the file detectable. A corrupt,
            // plaintext or foreign witness fails closed here.
            var witness = SspLicenseStateWitnessStore.Load(_witnessPath);
            VerifyWitnessBindingOrThrow(witness);

            if (!SspLicenseStateFileLock.FileExists(_path))
            {
                if (witness is null)
                {
                    // Fresh installation: no floor has ever been established.
                    return null;
                }

                // Deletion attempt (Phase 4 / M-3): recover the floor from
                // the witness instead of silently treating the machine as
                // fresh. The recovered values can only RESTRICT: they are a
                // durable lower bound of everything this installation ever
                // accepted, and the signed artifact remains the root of
                // trust. LastValidatedUtc is deliberately null so the next
                // successful validation re-persists the recovered state
                // (self-healing the primary file).
                ReportWitnessEvent(
                    LicenseSecurityEventType.LicenseStateDeletionRecovered,
                    $"License state file was deleted; anti-rollback floor {witness.HighestAcceptedSequenceNumber} " +
                    $"(epoch {witness.StateEpoch}) recovered from the redundant witness.");
                return new LicenseStateRecord
                {
                    HighestAcceptedSequenceNumber = witness.HighestAcceptedSequenceNumber,
                    LastAcceptedLicenseId = witness.LastAcceptedLicenseId,
                    ActivatedLicenseId = witness.ActivatedLicenseId,
                    InstallationId = witness.InstallationId ?? _installationStateBindingId,
                    StateEpoch = witness.StateEpoch,
                    // Phase 6: the diagnostic successful-validation timestamp
                    // stays null, but deletion must NEVER erase witnessed time.
                    ClockStateVersion = witness.ClockStateVersion,
                    LastObservedUtc = witness.LastObservedUtc,
                };
            }

            LicenseStateRecord record;
            try
            {
                var read = ProtectedFileStore.ReadTextAsync(_path).GetAwaiter().GetResult();
                if (string.IsNullOrWhiteSpace(read.Text))
                {
                    throw new InvalidDataException("License state store file is empty.");
                }

                record = JsonSerializer.Deserialize<LicenseStateRecord>(read.Text, SerializerOptions)
                         ?? throw new InvalidDataException("License state store file could not be deserialized.");

                _ = record.GetClockFloor();
                if (record.ClockStateVersion != 0 && !read.WasEncrypted)
                    throw new InvalidDataException("An initialized clock checkpoint must be envelope-encrypted.");

                // A legacy plaintext state file is upgraded to the encrypted
                // envelope once it has been read successfully. Best effort:
                // a failed migration must not make an otherwise-readable state
                // unavailable (the next Save will re-write it encrypted).
                if (read.WasPlaintextProtectedFile)
                {
                    try
                    {
                        ProtectedFileStore.MigratePlaintextAsync(_path, read).GetAwaiter().GetResult();
                    }
                    catch
                    {
                        // Best effort only; keep the validated state available.
                    }
                }
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException
                                       or InvalidDataException or CryptographicException
                                       or PlatformNotSupportedException)
            {
                // Fail closed: a corrupt or unreadable state store must never
                // silently reset the anti-rollback floor.
                throw new InvalidDataException(
                    $"License state store could not be read: {ex.GetType().Name}", ex);
            }

            // Phase 4 (M-3): a record that names a DIFFERENT installation
            // is foreign state. Accepting it would silently replace this
            // installation's floor with a replayed one, so the load fails
            // closed. Legacy records (no binding) are adopted and upgraded on
            // the next save. (Deliberately outside the read try/catch above:
            // this is its own fail-closed verdict, not a read failure, and it
            // must surface with its own message.)
            if (_installationStateBindingId is not null &&
                record.InstallationId is not null &&
                !string.Equals(record.InstallationId, _installationStateBindingId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "License state is bound to a different installation " +
                    "(foreign or replayed state record).");
            }

            // Rollback detection (Phase 4 / M-3): the persisted epoch can
            // never legitimately be lower than the witnessed epoch — every
            // save writes the primary first and then max-merges the witness,
            // so a witnessed epoch strictly above the file's epoch proves the
            // file is an older copy restored over a newer one.
            if (witness is not null && witness.StateEpoch > record.StateEpoch)
            {
                ReportWitnessEvent(
                    LicenseSecurityEventType.LicenseStateRollbackDetected,
                    $"License state rollback detected: state file epoch {record.StateEpoch} is older than the " +
                    $"witnessed epoch {witness.StateEpoch} (witnessed floor {witness.HighestAcceptedSequenceNumber}).");
                throw new InvalidDataException(
                    $"License state rollback detected: the persisted state epoch {record.StateEpoch} is older " +
                    $"than the witnessed epoch {witness.StateEpoch}.");
            }

            // Phase 6: max-merge time independently of the Phase 4 epoch rule.
            // An intact witness must retain the clock floor even if a legacy or
            // stale primary lacks it; it can only make validation more restrictive.
            if (witness is { ClockStateVersion: LicenseStateRecord.CurrentClockStateVersion })
            {
                var floor = record.GetClockFloor();
                record = record with
                {
                    ClockStateVersion = LicenseStateRecord.CurrentClockStateVersion,
                    LastObservedUtc = floor is { } utc && utc > witness.LastObservedUtc!.Value
                        ? utc : witness.LastObservedUtc
                };
            }

            return record;
        }
    }

    /// <inheritdoc />
    public void Save(LicenseStateRecord record)
    {
        if (record is null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        using var stateLock = SspLicenseStateFileLock.Acquire(_path);
        lock (_gate)
        {
            // Phase 6: do not let any save erase an initialized time checkpoint.
            // Validate existing material before writing, including legacy callers:
            // unreadable history might contain initialized time, so the former
            // best-effort epoch read / corrupt-state overwrite could erase it.
            // Corrupt/foreign history cannot be "healed" into an earlier clock.
            // The reentrant lease keeps time-only writes from racing the
            // manager's acceptance/activation.
            var current = Load();
            var currentTime = current?.GetClockFloor();
            var proposedTime = record.GetClockFloor();
            var hasClockCheckpoint = record.ClockStateVersion != 0 || (current?.ClockStateVersion ?? 0) != 0;
            if (hasClockCheckpoint)
            {
                record = record with
                {
                    ClockStateVersion = LicenseStateRecord.CurrentClockStateVersion,
                    LastObservedUtc = currentTime is { } utc && (proposedTime is null || utc > proposedTime.Value)
                        ? utc : proposedTime
                };
            }

            var directory = System.IO.Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Phase 4 (M-3): stamp the installation binding (adopting legacy
            // records on their first save) and advance the monotonic state
            // epoch. The epoch is taken as max(record, on-disk) + 1 so that a
            // cross-process last-writer-wins save can never move the counter
            // backwards even when the in-memory record was loaded earlier.
            var stamped = record with
            {
                InstallationId = record.InstallationId ?? _installationStateBindingId,
                StateEpoch = checked(Math.Max(record.StateEpoch, current?.StateEpoch ?? 0) + 1),
            };

            var json = JsonSerializer.Serialize(stamped, SerializerOptions);
            ProtectedFileStore.WriteTextAsync(_path, json).GetAwaiter().GetResult();

            // Primary first, witness second: a crash between the two leaves a
            // lagging witness, which is the safe direction (a lagging witness
            // can only fail to detect, never falsely grant). The witness
            // write stays best effort for legacy sequence-only records. Phase 6
            // checkpoints MUST complete both writes before a caller may authorize.
            // A failed time write is propagated, never reported as success.
            try
            {
                LicenseStateWitness? existing = null;
                try
                {
                    existing = SspLicenseStateWitnessStore.Load(_witnessPath);
                }
                catch when (!hasClockCheckpoint)
                {
                    // Legacy sequence-only behavior; initialized time history
                    // must never be replaced after an integrity failure.
                    existing = null;
                }

                SspLicenseStateWitnessStore.Save(_witnessPath, new LicenseStateWitness
                {
                    InstallationId = stamped.InstallationId,
                    StateEpoch = Math.Max(stamped.StateEpoch, existing?.StateEpoch ?? 0),
                    HighestAcceptedSequenceNumber = Math.Max(
                        stamped.HighestAcceptedSequenceNumber,
                        existing?.HighestAcceptedSequenceNumber ?? 0),
                    LastAcceptedLicenseId = stamped.LastAcceptedLicenseId,
                    ActivatedLicenseId = stamped.ActivatedLicenseId,
                    ClockStateVersion = stamped.ClockStateVersion,
                    LastObservedUtc = stamped.LastObservedUtc is { } utc &&
                                      existing?.LastObservedUtc is { } witnessedUtc && witnessedUtc > utc
                        ? witnessedUtc : stamped.LastObservedUtc,
                });
            }
            catch when (!hasClockCheckpoint)
            {
                // Preserve legacy sequence-only witness behavior. Phase 6 time
                // checkpoints deliberately do NOT enter this best-effort path.
            }
        }
    }

    /// <summary>
    /// Fails closed when the witness names a different installation: foreign
    /// material in the witness slot is tampering, and an honest flow never
    /// produces it (fresh installs have no witness; same-installation
    /// upgrades keep the binding; cross-machine copies already fail at the
    /// encrypted envelope).
    /// </summary>
    private void VerifyWitnessBindingOrThrow(LicenseStateWitness? witness)
    {
        if (witness is null ||
            _installationStateBindingId is null ||
            witness.InstallationId is null)
        {
            return;
        }

        if (!string.Equals(witness.InstallationId, _installationStateBindingId, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "License state witness is bound to a different installation " +
                "(foreign or replayed witness material).");
        }
    }

    /// <summary>
    /// Best-effort, never-throwing report of a Phase 4 detection event.
    /// </summary>
    private void ReportWitnessEvent(LicenseSecurityEventType eventType, string detail)
    {
        try
        {
            _eventSink?.Report(new LicenseSecurityEvent
            {
                EventType = eventType,
                OccurredAtUtc = _clock?.UtcNow ?? DateTimeOffset.UtcNow,
                State = LicenseState.LockedDown,
                LicenseId = null,
                ReasonCode = LicenseReasons.StateStoreUnavailable,
                Detail = detail
            });
        }
        catch
        {
            // The sink contract is to never throw, and a reporting failure
            // must never change the fail-closed decision.
        }
    }

}
