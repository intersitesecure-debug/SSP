namespace SSP.Activation;

/// <summary>
/// Default <see cref="ILicenseManager"/> and composition root of the licensing runtime.
/// Owns validation, runtime state transitions (Unknown / Valid / LockedDown),
/// anti-rollback bookkeeping, security events and policy-gated authorization.
/// Thread-safe.
///
/// State machine:
/// <code>
///   Unknown    --(valid license)-->            Valid
///   Unknown    --(invalid artifact)-->         LockedDown
///   Unknown    --(no artifact available)-->    Unknown   (operations denied)
///   Valid      --(revalidation failure)-->     LockedDown
///   LockedDown --(valid license loaded)-->     Valid     (lockdown cleared)
///   LockedDown --(license deleted/missing)-->  LockedDown (deletion never recovers)
/// </code>
/// </summary>
public sealed class LicenseManager : ILicenseManager
{
    private readonly object _gate = new();
    private readonly LicenseValidator _validator;
    private readonly ILicensePolicy _policy;
    private readonly ILicenseProvider? _provider;
    private readonly ISecurityEventSink _eventSink;
    private readonly ILicenseStateStore _stateStore;
    private readonly IClock _clock;

    private LicenseState _state = LicenseState.Unknown;
    private LicenseValidationResult? _lastResult;
    private string? _lastArtifact;
    private License? _currentLicense;

    /// <summary>
    /// Immutable, atomically-published view of the manager state for lock-free readers.
    ///
    /// Why this exists: <see cref="Authorize"/> evaluates the policy while holding
    /// <see cref="_gate"/> so that an authorization decision is atomic with respect to a
    /// concurrent license invalidation (state transitions in <see cref="Apply"/> take the
    /// same lock). If the read-only observers (<see cref="CurrentState"/> etc.) also took
    /// <see cref="_gate"/>, any thread observing the state while an authorization is in
    /// flight would block behind the policy — and if the policy's completion depends on
    /// that observing thread, the process deadlocks. Readers therefore consume this
    /// snapshot, which is only ever written under <see cref="_gate"/> and published with
    /// release semantics (volatile), so they always see a fully consistent
    /// state/result/license triple and never contend with an in-flight authorization.
    /// </summary>
    private volatile StateSnapshot _snapshot = new(LicenseState.Unknown, null, null);

    private sealed record StateSnapshot(
        LicenseState State,
        LicenseValidationResult? LastResult,
        License? CurrentLicense);

    /// <summary>
    /// Creates a manager and wires the complete validation pipeline. The same state store
    /// and event sink instances are shared between the manager and the validator, so
    /// callers cannot mis-wire the anti-rollback floor.
    /// </summary>
    public LicenseManager(
        LicenseValidationOptions options,
        LicenseTrustAnchor trustAnchor,
        IInstallationIdentityProvider identityProvider,
        IClock? clock = null,
        ILicenseProvider? licenseProvider = null,
        ILicensePolicy? policy = null,
        ISecurityEventSink? eventSink = null,
        ILicenseStateStore? stateStore = null,
        ILicenseRevocationChecker? revocationChecker = null)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (trustAnchor is null)
        {
            throw new ArgumentNullException(nameof(trustAnchor));
        }

        if (identityProvider is null)
        {
            throw new ArgumentNullException(nameof(identityProvider));
        }

        _clock = clock ?? SystemClock.Instance;
        _provider = licenseProvider;
        _policy = policy ?? DefaultLicensePolicy.Instance;
        _eventSink = eventSink ?? new NullSecurityEventSink();
        _stateStore = stateStore ?? new InMemoryLicenseStateStore();

        _validator = new LicenseValidator(
            trustAnchor,
            options,
            _clock,
            identityProvider,
            _stateStore,
            revocationChecker,
            _eventSink);
    }

    // The read-only observers are deliberately lock-free (see _snapshot). They must never
    // acquire _gate: policy evaluation runs under _gate, and a policy implementation may
    // (directly or indirectly) depend on a thread that is concurrently observing the
    // manager state. Taking _gate here would turn that dependency into a deadlock.
    public LicenseState CurrentState => _snapshot.State;

    public LicenseValidationResult? LastValidationResult => _snapshot.LastResult;

    public License? CurrentLicense
    {
        get
        {
            // Read one immutable snapshot so the state check and the license read can
            // never disagree (no torn read across a concurrent invalidation).
            var snapshot = _snapshot;
            return snapshot.State == LicenseState.Valid ? snapshot.CurrentLicense : null;
        }
    }

    /// <summary>
    /// Publishes the current mutable fields as an immutable snapshot for lock-free readers.
    /// Must be called while holding <see cref="_gate"/>, after every state mutation.
    /// </summary>
    private void PublishSnapshot()
    {
        _snapshot = new StateSnapshot(_state, _lastResult, _currentLicense);
    }

    /// <summary>Loads the license through the configured provider. Requires a provider.</summary>
    public LicenseValidationResult Load()
    {
        if (_provider is null)
        {
            throw new InvalidOperationException(
                "No license provider is configured. Configure one via the constructor or use LoadLicense(artifactJson).");
        }

        LicenseFetchResult fetch;
        try
        {
            fetch = _provider.FetchLicense();
        }
        catch (Exception ex)
        {
            fetch = LicenseFetchResult.Error($"License provider failed: {ex.GetType().Name}");
        }

        if (!fetch.HasLicense || string.IsNullOrWhiteSpace(fetch.ArtifactJson))
        {
            // Missing/empty artifact: fail closed as Unknown. This never clears an active
            // lockdown — deleting the license cannot recover a locked-down installation.
            var missing = _validator.Validate(null);
            if (!string.IsNullOrEmpty(fetch.Detail))
            {
                var detail = $"{missing.Detail} ({fetch.Detail})";
                missing = missing with { Detail = detail };
            }

            return Apply(missing, artifactJson: null);
        }

        return LoadLicense(fetch.ArtifactJson!);
    }

    public LicenseValidationResult LoadLicense(string artifactJson)
    {
        if (artifactJson is null)
        {
            throw new ArgumentNullException(nameof(artifactJson));
        }

        LicenseValidationResult result;
        try
        {
            result = _validator.Validate(artifactJson);
        }
        catch (Exception ex)
        {
            // Last-resort defense: an unexpected infrastructure failure must fail closed.
            result = LicenseValidationResult.Fail(
                LicenseState.Unknown,
                LicenseReasons.InternalError,
                $"Unexpected validation failure: {ex.GetType().Name}");
        }

        return Apply(result, artifactJson);
    }

    public LicenseValidationResult Revalidate()
    {
        // A provider is the authoritative source of the currently installed
        // artifact. Revalidation must read it again, not only re-check the
        // string captured by an earlier load: otherwise expiry is detected but
        // an operator-installed renewal can never clear a lockdown until the
        // process is restarted or some separate caller happens to invoke Load.
        //
        // The provider fetch is still transport-only; Load performs the full
        // validation pipeline and Apply performs the state transition under the
        // manager lock. A provider-less manager is supported for explicit
        // LoadLicense users and retains the original held-artifact behavior.
        if (_provider is not null)
        {
            return Load();
        }

        string? artifact;
        lock (_gate)
        {
            artifact = _lastArtifact;
        }

        if (artifact is null)
        {
            // Nothing has ever been loaded: report a missing-license result and keep the
            // runtime state consistent (Unknown, never Valid, never LockedDown).
            var result = _validator.Validate(null);
            return Apply(result, artifactJson: null);
        }

        return LoadLicense(artifact);
    }

    public AuthorizationDecision Authorize(ProtectedOperation operation)
    {
        if (operation is null)
        {
            throw new ArgumentNullException(nameof(operation));
        }

        // The state snapshot and the policy decision are taken atomically under the same
        // lock that governs state transitions, so a concurrent license invalidation can
        // never be observed as a valid authorization: an operation is authorized only
        // against the state that was current at the instant the decision was made.
        lock (_gate)
        {
            LicenseState state = _state;
            License? license = _state == LicenseState.Valid ? _currentLicense : null;

            AuthorizationDecision decision;
            try
            {
                decision = _policy.Evaluate(new LicenseEvaluationContext
                {
                    ManagerState = state,
                    License = license,
                    Operation = operation
                });
            }
            catch
            {
                // A throwing policy must never fail open: treat it as a denial.
                decision = AuthorizationDecision.Deny(
                    LicenseReasons.InternalError,
                    "License policy evaluation failed and the operation was denied.");
            }

            if (!decision.IsAllowed)
            {
                _eventSink.Report(new LicenseSecurityEvent
                {
                    EventType = LicenseSecurityEventType.ProtectedOperationDenied,
                    OccurredAtUtc = _clock.UtcNow,
                    State = state,
                    LicenseId = license?.Payload.LicenseId,
                    ReasonCode = decision.ReasonCode,
                    Detail = decision.Detail
                });
            }

            return decision;
        }
    }

    private LicenseValidationResult Apply(LicenseValidationResult result, string? artifactJson)
    {
        lock (_gate)
        {
            _lastResult = result;
            if (artifactJson is not null)
            {
                _lastArtifact = artifactJson;
            }

            if (result.IsValid)
            {
                // Anti-rollback is re-checked atomically under the manager lock. This closes
                // the race where two concurrent validations could otherwise install an older
                // license as current after a newer one had already persisted its floor: the
                // state store can only ever restrict authorization, never grant it.
                var payload = result.License!.Payload;
                LicenseStateRecord? stored;
                try
                {
                    stored = _stateStore.Load();
                }
                catch
                {
                    // A state-store read failure during Apply is treated the same way as
                    // PersistAcceptedSequence does: the signature is the root of trust, so a
                    // transient store failure never blocks an already-validated license.
                    stored = null;
                }

                if (stored is not null && payload.SequenceNumber < stored.HighestAcceptedSequenceNumber)
                {
                    var supersededEvent = new LicenseSecurityEvent
                    {
                        EventType = LicenseSecurityEventType.LicenseSuperseded,
                        OccurredAtUtc = _clock.UtcNow,
                        State = LicenseState.Superseded,
                        LicenseId = payload.LicenseId,
                        ReasonCode = LicenseReasons.Superseded,
                        Detail = $"License sequence {payload.SequenceNumber} is older than the highest accepted sequence {stored.HighestAcceptedSequenceNumber}."
                    };
                    var superseded = LicenseValidationResult.Fail(
                        LicenseState.Superseded,
                        LicenseReasons.Superseded,
                        supersededEvent.Detail!,
                        result.License,
                        supersededEvent);

                    _lastResult = superseded;
                    _eventSink.Report(supersededEvent);
                    var wasAlreadyLockedDown = _state == LicenseState.LockedDown;
                    _state = LicenseState.LockedDown;
                    _currentLicense = null;
                    PublishSnapshot();
                    if (!wasAlreadyLockedDown)
                    {
                        _eventSink.Report(MakeEvent(LicenseSecurityEventType.LicenseLockdownActivated, superseded));
                    }

                    return superseded;
                }

                var wasLockedDown = _state == LicenseState.LockedDown;
                _state = LicenseState.Valid;
                _currentLicense = result.License;
                PublishSnapshot();
                PersistAcceptedSequence(payload);

                if (wasLockedDown)
                {
                    _eventSink.Report(MakeEvent(LicenseSecurityEventType.LicenseLockdownCleared, result));
                }

                return result;
            }

            if (artifactJson is null)
            {
                // No artifact available (missing/empty license or provider error).
                if (_state != LicenseState.LockedDown)
                {
                    _state = LicenseState.Unknown;
                }

                _currentLicense = null;
                PublishSnapshot();
                return result;
            }

            // An artifact was provided and failed validation: enter (or remain in) lockdown.
            var wasLocked = _state == LicenseState.LockedDown;
            _state = LicenseState.LockedDown;
            _currentLicense = null;
            PublishSnapshot();
            if (!wasLocked)
            {
                _eventSink.Report(MakeEvent(LicenseSecurityEventType.LicenseLockdownActivated, result));
            }

            return result;
        }
    }

    private void PersistAcceptedSequence(LicensePayload payload)
    {
        try
        {
            var record = _stateStore.Load() ?? new LicenseStateRecord();
            if (payload.SequenceNumber > record.HighestAcceptedSequenceNumber ||
                record.LastAcceptedLicenseId != payload.LicenseId ||
                record.LastValidatedUtc is null)
            {
                _stateStore.Save(record with
                {
                    HighestAcceptedSequenceNumber = Math.Max(record.HighestAcceptedSequenceNumber, payload.SequenceNumber),
                    LastAcceptedLicenseId = payload.LicenseId,
                    LastValidatedUtc = _clock.UtcNow
                });
            }
        }
        catch
        {
            // State store writes remain best effort by contract: the signed
            // artifact is the root of trust, while the persisted floor only
            // restricts future authorization.
        }
    }

    private LicenseSecurityEvent MakeEvent(LicenseSecurityEventType eventType, LicenseValidationResult result)
        => new()
        {
            EventType = eventType,
            OccurredAtUtc = _clock.UtcNow,
            State = result.State,
            LicenseId = result.License?.Payload.LicenseId,
            ReasonCode = result.ReasonCode,
            Detail = result.Detail
        };
}
