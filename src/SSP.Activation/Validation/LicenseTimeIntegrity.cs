namespace SSP.Activation;

/// <summary>
/// Optional host-store synchronization for Phase 6 time checkpoints. A file-backed
/// host implements this with a reentrant cross-process lease covering Load + Save,
/// so a time-only write cannot overwrite a concurrent renewal/activation update.
/// The existing ILicenseStateStore contract and licensing composition are unchanged.
/// Stores without this seam are serialized on their shared instance in-process.
/// </summary>
public interface ILicenseTimeStateLock
{
    /// <summary>
    /// Acquires a synchronous, reentrant lease; throws if the state cannot be locked.
    /// Dispose on the acquiring thread; do not await while holding the lease.
    /// </summary>
    IDisposable AcquireTimeStateLock();
}

/// <summary>
/// Phase 6 / M-6: monotonic local time history. Shared by a manager and its validator.
/// This is NOT trusted absolute UTC: initial time and coordinated machine snapshots
/// cannot be authenticated offline. No persisted field here can grant authorization.
/// </summary>
internal sealed class LicenseTimeIntegrity
{
    private readonly IClock _clock;
    private readonly ILicenseStateStore _store;
    private readonly ISecurityEventSink _events;
    private DateTimeOffset? _highestObservedUtc;
    private DateTimeOffset? _lastSampleUtc;

    internal LicenseTimeIntegrity(IClock clock, ILicenseStateStore store, ISecurityEventSink events)
    {
        _clock = clock;
        _store = store;
        _events = events;
    }

    // Events must not resample an injected/failing clock or throw while a manager is
    // entering lockdown. Before the first observation, OS time is diagnostic only.
    internal DateTimeOffset EventTimeUtc
    {
        get
        {
            lock (_store)
                return _lastSampleUtc ?? DateTimeOffset.UtcNow;
        }
    }

    internal void Report(LicenseSecurityEvent securityEvent)
    {
        try { _events.Report(securityEvent); }
        catch { /* Logging must never mask the security verdict. */ }
    }

    /// <summary>
    /// Read history BEFORE sampling UTC (a concurrent forward checkpoint is not a
    /// clock regression). Check strict monotonicity, then durably record the sample.
    /// The optional update is executed under the same state lease and is used only
    /// by the manager for its existing acceptance/activation bookkeeping. Even a
    /// failed time window must persist the observation, but never accepted sequence
    /// or activation changes. Persistence failure always overrides success.
    /// </summary>
    internal Observation Observe(
        License license,
        Func<LicenseStateRecord, DateTimeOffset, (LicenseStateRecord Record, LicenseValidationResult? Failure)>? update = null)
    {
        lock (_store)
        {
            try
            {
                using var lease = (_store as ILicenseTimeStateLock)?.AcquireTimeStateLock();
                var record = _store.Load() ?? new LicenseStateRecord();
                var floor = record.GetClockFloor();
                if (_highestObservedUtc is { } memory && (floor is null || memory > floor.Value))
                    floor = memory;
                // Remember loaded evidence even when this observation is rejected
                // or the clock itself fails. Later missing/replayed state must not
                // make this manager forget a higher floor it has already read.
                _highestObservedUtc = floor;

                DateTimeOffset now;
                try
                {
                    now = _clock.UtcNow.ToUniversalTime();
                    _lastSampleUtc = now;
                }
                catch (Exception ex)
                {
                    return Failed(Unavailable(license, LicenseReasons.TimeIntegrityUnavailable,
                        $"Local UTC clock could not be read: {ex.GetType().Name}. Protected operations are denied."));
                }

                if (floor is { } lowerBound && now < lowerBound)
                {
                    return Failed(Failure(license, now, LicenseState.Unknown,
                        LicenseReasons.ClockRollbackDetected, LicenseSecurityEventType.ClockRollbackDetected,
                        $"Clock rollback detected: observed UTC {now:o} is earlier than retained UTC {lowerBound:o}. " +
                        "Restore the clock to at least the retained time and revalidate; the checkpoint is never reset."));
                }

                // Retain observed forward time even if the subsequent write fails. A
                // later call through this guard must not forget what it already saw.
                _highestObservedUtc = now;
                LicenseValidationResult? failure = null;
                if (update is not null)
                    (record, failure) = update(record, now);

                record = record with
                {
                    ClockStateVersion = LicenseStateRecord.CurrentClockStateVersion,
                    LastObservedUtc = now
                };
                _store.Save(record); // Required, never best effort for a time checkpoint.

                // Do not accept a store that silently discards the required write.
                // Native stores also complete their witness write before returning.
                var committed = _store.Load();
                if (committed is null ||
                    committed.ClockStateVersion != LicenseStateRecord.CurrentClockStateVersion ||
                    committed.GetClockFloor() is not { } committedTime || committedTime < now)
                {
                    throw new InvalidDataException("The required local time checkpoint was not retained.");
                }

                _highestObservedUtc = committedTime;
                if (committedTime > now)
                {
                    // A store without a working transaction lease may expose a
                    // later writer here. The earlier sample is no longer enough
                    // to authorize, even though the persisted floor did not shrink.
                    return Failed(Unavailable(license, LicenseReasons.StateStoreUnavailable,
                        "The local time checkpoint advanced during this observation. " +
                        "A fresh serialized validation is required; protected operations are denied."));
                }
                if (failure is not null)
                    Report(failure.SecurityEvent!);

                return new Observation(now, committed, failure);
            }
            catch (Exception ex)
            {
                return Failed(Unavailable(license, LicenseReasons.StateStoreUnavailable,
                    $"Local time checkpoint could not be read or persisted: {ex.GetType().Name}. Protected operations are denied."));
            }
        }
    }

    /// <summary>
    /// Uses exactly the supplied sample for BOTH windows. Only call on a license
    /// whose signatures/bindings were checked, never as an authorization shortcut.
    /// ExpiresAt remains exclusive; no rollback tolerance or expiration grace exists.
    /// </summary>
    internal LicenseValidationResult? CheckWindow(License license, DateTimeOffset now)
    {
        var certification = license.Certification;
        if (certification is not null)
        {
            if (now < certification.NotBefore)
                return Failure(license, now, LicenseState.NotYetValid, LicenseReasons.CertificationNotYetValid,
                    LicenseSecurityEventType.LicenseValidationFailed,
                    $"Key certification is not valid before {certification.NotBefore:o} (now {now:o}).");
            if (now >= certification.ExpiresAt)
                return Failure(license, now, LicenseState.Expired, LicenseReasons.CertificationExpired,
                    LicenseSecurityEventType.LicenseExpired,
                    $"Key certification expired at {certification.ExpiresAt:o} (now {now:o}).");
        }

        var payload = license.Payload;
        if (now < payload.NotBefore)
            return Failure(license, now, LicenseState.NotYetValid, LicenseReasons.NotYetValid,
                LicenseSecurityEventType.LicenseValidationFailed,
                $"License is not valid before {payload.NotBefore:o} (now {now:o}).");
        if (now >= payload.ExpiresAt)
            return Failure(license, now, LicenseState.Expired, LicenseReasons.Expired,
                LicenseSecurityEventType.LicenseExpired,
                $"License expired at {payload.ExpiresAt:o} (now {now:o}).");

        return null;
    }

    internal static LicenseValidationResult Failure(
        License license, DateTimeOffset now, LicenseState state, string reason,
        LicenseSecurityEventType eventType, string detail)
    {
        var securityEvent = new LicenseSecurityEvent
        {
            EventType = eventType,
            OccurredAtUtc = now,
            State = state,
            LicenseId = license.Payload.LicenseId,
            ReasonCode = reason,
            Detail = detail
        };
        return LicenseValidationResult.Fail(state, reason, detail, license, securityEvent);
    }

    private LicenseValidationResult Unavailable(License license, string reason, string detail)
        => Failure(license, EventTimeUtc, LicenseState.Unknown, reason,
            LicenseSecurityEventType.TimeIntegrityUnavailable, detail);

    private Observation Failed(LicenseValidationResult failure)
    {
        Report(failure.SecurityEvent!);
        return new Observation(failure.SecurityEvent!.OccurredAtUtc, null, failure);
    }

    internal sealed record Observation(
        DateTimeOffset UtcNow, LicenseStateRecord? Record, LicenseValidationResult? Failure);
}
