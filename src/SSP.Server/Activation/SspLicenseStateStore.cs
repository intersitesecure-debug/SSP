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
//     integrity violation and fails closed. A MISSING witness is never a
//     violation: the primary file is authoritative while it is intact and
//     consistent, and the next save re-establishes the witness.
//
// The store is never a security boundary: it can only restrict
// authorization, never grant it. Nothing here can restore authorization that
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
public sealed class SspLicenseStateStore : ILicenseStateStore
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
        lock (_gate)
        {
            // The witness is read first: it is what turns "file missing" from
            // "fresh install" into "deletion attempt", and its epoch is what
            // makes an older copy of the file detectable. A corrupt,
            // plaintext or foreign witness fails closed here.
            var witness = SspLicenseStateWitnessStore.Load(_witnessPath);
            VerifyWitnessBindingOrThrow(witness);

            if (!File.Exists(_path))
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

        lock (_gate)
        {
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
                StateEpoch = Math.Max(record.StateEpoch, ReadCurrentOnDiskEpoch()) + 1,
            };

            var json = JsonSerializer.Serialize(stamped, SerializerOptions);
            ProtectedFileStore.WriteTextAsync(_path, json).GetAwaiter().GetResult();

            // Primary first, witness second: a crash between the two leaves a
            // lagging witness, which is the safe direction (a lagging witness
            // can only fail to detect, never falsely grant). The witness
            // write itself is best effort for the same reason, and it
            // max-merges with whatever is durably witnessed so it can never
            // regress either. An unreadable existing witness is overwritten
            // (self-healed) rather than propagated.
            try
            {
                LicenseStateWitness? existing = null;
                try
                {
                    existing = SspLicenseStateWitnessStore.Load(_witnessPath);
                }
                catch
                {
                    // Corrupt/undecryptable witness: overwrite with a fresh,
                    // primary-consistent one below.
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
                });
            }
            catch
            {
                // Best effort only: a witness write failure must never fail a
                // state save whose primary file was already written. A
                // persistently failing witness write disables deletion
                // detection (documented residual); it can never grant
                // authorization.
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

    /// <summary>
    /// Best-effort read of the epoch currently on disk, used by
    /// <see cref="Save"/> to keep the persisted epoch strictly monotonic even
    /// when the caller's in-memory record is stale. Any failure (corrupt file,
    /// I/O error, undecryptable envelope) yields 0, which simply means "stamp
    /// from the caller's record": the write then overwrites the unreadable
    /// file, and a rolled-back or corrupt file is healed by a fresh, valid
    /// record. This method never throws and never influences authorization.
    /// </summary>
    private long ReadCurrentOnDiskEpoch()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return 0;
            }

            var read = ProtectedFileStore.ReadTextAsync(_path).GetAwaiter().GetResult();
            if (string.IsNullOrWhiteSpace(read.Text))
            {
                return 0;
            }

            var existing = JsonSerializer.Deserialize<LicenseStateRecord>(read.Text, SerializerOptions);
            return existing?.StateEpoch ?? 0;
        }
        catch
        {
            return 0;
        }
    }
}
