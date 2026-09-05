// File: src/SSP.Server/Activation/SspActivationService.cs
// THE SINGLE AUTHORITATIVE ACTIVATION COMPOSITION ROOT for SSP.
//
// This type is the only place in SSP where the activation runtime is
// assembled. It wires the vendored SSP.Activation library to every SSP-native
// adapter in one explicit, inspectable graph:
//
//   LicenseValidationOptions(SspLicensing.ProductId)
//   LicenseTrustAnchor            <- SspTrustAnchor.Create() (production)
//   IInstallationIdentityProvider <- SspInstallationIdentityProvider
//   ILicenseProvider              <- LocalLicenseFileProvider(license.json)
//   ILicenseStateStore            <- SspLicenseStateStore (.license-state.dat)
//   ISecurityEventSink            <- SspSecurityEventSink (licensing dir)
//   IClock                        <- SystemClock (injectable for tests)
//   ILicensePolicy                <- DefaultLicensePolicy
//   LicenseManager                <- constructed with every component above;
//                                    it creates the LicenseValidator with the
//                                    same wired components (anchor, options, clock, identity, state store, revocation
//                                    checker, event sink)
//   LicenseEnforcement            <- facade over the manager
//
// The composition root lives on the SERVER side only: SSP.Client,
// SSP.ServiceHost and SSP.ServiceBuilder carry no activation code and no
// reference to this type. There is no second activation authority - the trust
// anchor above is the only root of trust, and the authority-side issuance
// code (which lives in SSP.Activation and is only ever driven by the offline
// licensing authority) is never reachable from any shipped runtime path.
// LicenseAuthoritySecurityIsolationTests enforces exactly that: no shipped
// runtime source tree may name the issuer type at all, so this comment
// deliberately does not either.
//
// The composition root is also the owner of the runtime enforcement path:
// SspRuntimeLicense delegates every gate decision back through this service's
// LicenseManager and its fail-closed policy. There is one authoritative
// activation runtime rather than separate cached decisions in the server.
//
// Fail-closed by construction: the production factory requires a compiled-in
// trust anchor (SspTrustAnchor.Create throws otherwise). There is no
// unmanaged-permissive mode and no environment/config bypass in this layer.
//
// Phase 3 (runtime enforcement): SspRuntimeLicense wraps this composition root
// and is the single ISspLicenseGate the server runtime consumes. This type owns
// the licensing lifetime (manager, validator, adapters, periodic refresh); it
// deliberately starts NO background work from its constructor or from Create() -
// the caller that owns the service lifetime calls StartRevalidationTimer()
// explicitly, once the runtime has been proven licensed.

using System.Text;
using System.Threading;
using SSP.Activation;
using SSP.Core.Activation;

namespace SSP.Server.Activation;

/// <summary>
/// Owns the fully wired SSP activation runtime: the
/// <see cref="LicenseManager"/> (which internally constructs the
/// <see cref="LicenseValidator"/>), the <see cref="LicenseEnforcement"/>
/// facade, and every adapter they depend on. Thread-safe through the
/// manager's own synchronization.
/// </summary>
public sealed class SspActivationService : IDisposable
{
    private readonly LicenseTrustAnchor _trustAnchor;
    private readonly IInstallationIdentityProvider _identityProvider;
    private readonly ISecurityEventSink _eventSink;
    private readonly ILicenseStateStore _stateStore;
    private readonly ILicenseProvider _licenseProvider;
    private readonly object _revalidationTimerGate = new();
    private PeriodicTimer? _revalidationTimer;
    private CancellationTokenSource? _revalidationCancellation;
    private Task? _revalidationTask;
    private bool _disposed;

    private SspActivationService(
        SspLicensePaths paths,
        LicenseTrustAnchor trustAnchor,
        LicenseValidationOptions validationOptions,
        IClock clock,
        ILicensePolicy policy,
        IInstallationIdentityProvider identityProvider,
        ISecurityEventSink eventSink,
        ILicenseStateStore stateStore,
        ILicenseProvider licenseProvider,
        LicenseManager manager,
        LicenseEnforcement enforcement)
    {
        Paths = paths;
        _trustAnchor = trustAnchor;
        ValidationOptions = validationOptions;
        Clock = clock;
        Policy = policy;
        _identityProvider = identityProvider;
        _eventSink = eventSink;
        _stateStore = stateStore;
        _licenseProvider = licenseProvider;
        Manager = manager;
        Enforcement = enforcement;
    }

    /// <summary>Canonical activation paths in use by this composition.</summary>
    public SspLicensePaths Paths { get; }

    /// <summary>The wired validation options (product id bound at composition time).</summary>
    public LicenseValidationOptions ValidationOptions { get; }

    /// <summary>The clock in use; <see cref="SystemClock"/> in production, injectable for tests.</summary>
    public IClock Clock { get; }

    /// <summary>The policy in use (fail-closed <see cref="DefaultLicensePolicy"/> in production).</summary>
    public ILicensePolicy Policy { get; }

    /// <summary>The single compiled-in root of trust (public key only).</summary>
    public LicenseTrustAnchor TrustAnchor => _trustAnchor;

    /// <summary>The installation identity provider (MachineGuid-derived on Windows).</summary>
    public IInstallationIdentityProvider IdentityProvider => _identityProvider;

    /// <summary>The security event sink (file + Windows event log in production).</summary>
    public ISecurityEventSink EventSink => _eventSink;

    /// <summary>The durable anti-rollback state store (DPAPI-backed in production).</summary>
    public ILicenseStateStore StateStore => _stateStore;

    /// <summary>The license artifact transport (local license.json in production).</summary>
    public ILicenseProvider LicenseProvider => _licenseProvider;

    /// <summary>
    /// The runtime authority: owns the state machine (Unknown/Valid/LockedDown),
    /// validation and policy-gated authorization. Constructs and owns the
    /// <see cref="LicenseValidator"/> with exactly the components wired here.
    /// </summary>
    public LicenseManager Manager { get; }

    /// <summary>
    /// Headless enforcement facade over <see cref="Manager"/>. This is the only
    /// licensing decision surface SSP runtime code may consult (through
    /// <see cref="SspRuntimeLicense"/>); every call is evaluated live against
    /// the manager's current state under the manager's own gate.
    /// </summary>
    public LicenseEnforcement Enforcement { get; }

    /// <summary>
    /// Default period between license refreshes. Long enough that the RSA
    /// re-verification and the file read are noise, short enough that an expiry
    /// or a newly installed renewal license is noticed without a restart.
    /// </summary>
    public static readonly TimeSpan DefaultRevalidationInterval = TimeSpan.FromMinutes(30);

    /// <summary>True while the periodic license refresh loop is running.</summary>
    public bool IsRevalidationTimerRunning
    {
        get
        {
            lock (_revalidationTimerGate)
            {
                return _revalidationTask is not null && !_disposed;
            }
        }
    }

    /// <summary>Current runtime state of the activation subsystem.</summary>
    public LicenseState CurrentState => Manager.CurrentState;

    /// <summary>Most recent validation result (state, reason, untrusted diagnostics payload).</summary>
    public LicenseValidationResult? LastValidationResult => Manager.LastValidationResult;

    /// <summary>Current license; non-null only while the state is <see cref="LicenseState.Valid"/>.</summary>
    public License? CurrentLicense => Manager.CurrentLicense;

    /// <summary>
    /// The authoritative production composition: canonical paths, compiled-in
    /// trust anchor, MachineGuid identity, DPAPI state store, production event
    /// sink, local-file provider, system clock and the default fail-closed
    /// policy.
    /// </summary>
    /// <param name="paths">Optional explicit paths (defaults to
    /// <see cref="SspLicensePaths.Resolve()"/>).</param>
    /// <param name="clock">Optional clock override (tests).</param>
    /// <exception cref="InvalidOperationException">
    /// No production trust anchor is compiled into this build
    /// (<see cref="SspTrustAnchor.IsCompiledIn"/> is false). This is
    /// deliberate: a build without an anchor must fail closed instead of
    /// silently running unmanaged.
    /// </exception>
    public static SspActivationService Create(SspLicensePaths? paths = null, IClock? clock = null)
    {
        var resolvedPaths = paths ?? SspLicensePaths.Resolve();
        var trustAnchor = SspTrustAnchor.Create();
        return Compose(
            resolvedPaths,
            trustAnchor,
            new SspInstallationIdentityProvider(),
            new SspSecurityEventSink(resolvedPaths.SecurityLogDirectory, writeToConsole: false),
            new SspLicenseStateStore(resolvedPaths.StateStorePath),
            new LocalLicenseFileProvider(resolvedPaths.LicenseFilePath),
            clock ?? SystemClock.Instance,
            DefaultLicensePolicy.Instance);
    }

    /// <summary>
    /// Explicit composition: wires the complete activation graph from the
    /// supplied components. Used by tests (with an ephemeral authority key)
    /// and by operator tooling that must supply its own parts. This is not a
    /// bypass - every component is required and the wiring is identical to
    /// <see cref="Create"/>; nothing is skipped or weakened.
    /// </summary>
    public static SspActivationService Compose(
        SspLicensePaths paths,
        LicenseTrustAnchor trustAnchor,
        IInstallationIdentityProvider identityProvider,
        ISecurityEventSink eventSink,
        ILicenseStateStore stateStore,
        ILicenseProvider licenseProvider,
        IClock? clock = null,
        ILicensePolicy? policy = null,
        ILicenseRevocationChecker? revocationChecker = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(trustAnchor);
        ArgumentNullException.ThrowIfNull(identityProvider);
        ArgumentNullException.ThrowIfNull(eventSink);
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(licenseProvider);

        var validationOptions = new LicenseValidationOptions(SspLicensing.ProductId);
        var resolvedClock = clock ?? SystemClock.Instance;
        var resolvedPolicy = policy ?? DefaultLicensePolicy.Instance;

        var manager = new LicenseManager(
            validationOptions,
            trustAnchor,
            identityProvider,
            resolvedClock,
            licenseProvider,
            resolvedPolicy,
            eventSink,
            stateStore,
            revocationChecker);

        return new SspActivationService(
            paths,
            trustAnchor,
            validationOptions,
            resolvedClock,
            resolvedPolicy,
            identityProvider,
            eventSink,
            stateStore,
            licenseProvider,
            manager,
            new LicenseEnforcement(manager));
    }

    /// <summary>Loads and validates the current license through the wired provider.</summary>
    public LicenseValidationResult Load() => Manager.Load();

    /// <summary>Revalidates the current provider artifact (periodic/operator refresh).</summary>
    public LicenseValidationResult Revalidate() => Manager.Revalidate();

    /// <summary>
    /// Attempts to activate the currently loaded activation-required license with a
    /// 10-digit activation code. This is the transport-independent activation step: the
    /// server hashes the code the operator typed and compares it (constant time) with the
    /// hash the authority signed into the license's key certification, then persists the
    /// activation and revalidates. The server never generates a code.
    /// </summary>
    public LicenseValidationResult TryActivate(string activationCode) => Manager.TryActivate(activationCode);

    /// <summary>
    /// Builds the activation-request message for the currently loaded license when it is
    /// in the <see cref="LicenseState.ActivationRequired"/> state and its certification
    /// carries an activation OTT; otherwise returns null. This produces pure data (license
    /// identity + OTT) — it performs no I/O and depends on no transport. The current
    /// offline transport writes it to a file (<see cref="SspLicensePaths.ActivationRequestFilePath"/>);
    /// a future HTTPS transport would send the same message over the network.
    /// </summary>
    public ActivationRequest? CreateActivationRequest()
    {
        var result = Manager.LastValidationResult;
        if (result is null || result.State != LicenseState.ActivationRequired)
        {
            return null;
        }

        var license = result.License;
        var certification = license?.Certification;
        if (license is null || certification is null || string.IsNullOrEmpty(certification.ActivationOtt))
        {
            return null;
        }

        var payload = license.Payload;
        return new ActivationRequest
        {
            LicenseId = payload.LicenseId,
            ProductId = payload.ProductId,
            CustomerId = payload.CustomerId,
            OrganizationOrPersonName = payload.OrganizationOrPersonName,
            ComputerName = payload.ComputerName,
            InstallationId = payload.InstallationId,
            ActivationOtt = certification.ActivationOtt,
            RequestedAtUtc = Clock.UtcNow
        };
    }

    /// <summary>
    /// Starts the periodic license refresh loop. Explicit, idempotent and owned
    /// by the caller that owns the service lifetime: no background work is ever
    /// started from a constructor, from <see cref="Create"/> or from
    /// <see cref="Compose"/>, so composing an activation runtime for a one-shot
    /// status query never leaves a timer behind.
    /// </summary>
    /// <param name="interval">
    /// Refresh period; defaults to <see cref="DefaultRevalidationInterval"/>.
    /// Must be positive.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="interval"/> is not positive.</exception>
    /// <exception cref="ObjectDisposedException">This service has been disposed.</exception>
    /// <remarks>
    /// Each tick calls <see cref="RefreshLicense"/>, which re-reads the license
    /// artifact through the wired provider and re-runs the full validation
    /// pipeline. <see cref="LicenseManager.Revalidate"/> owns that refresh
    /// contract, so expiry and an operator-installed renewal follow the same
    /// state transition path (reference ARCHITECTURE §8).
    ///
    /// Lifecycle guarantees:
    ///   • exactly one loop - Start is idempotent under <c>_revalidationTimerGate</c>;
    ///   • no overlapping refreshes - the loop awaits the tick, then calls the
    ///     (synchronous) refresh, then awaits the next tick;
    ///   • no unobserved task exceptions - the loop body catches everything and
    ///     the task is retained and joined by <see cref="Dispose"/>;
    ///   • no timer after shutdown - <see cref="Dispose"/> cancels, disposes the
    ///     <see cref="PeriodicTimer"/>, joins the loop and marks the service
    ///     disposed, after which Start throws;
    ///   • no stale "Valid" cache anywhere - every gate consults
    ///     <see cref="Enforcement"/>, which reads the manager's state under the
    ///     manager's own gate at call time.
    /// </remarks>
    public void StartRevalidationTimer(TimeSpan? interval = null)
    {
        var resolvedInterval = interval ?? DefaultRevalidationInterval;
        if (resolvedInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(interval), resolvedInterval, "The license refresh interval must be positive.");
        }

        lock (_revalidationTimerGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            // Start is idempotent, including when callers race with each other.
            if (_revalidationTask is not null)
                return;

            var timer = new PeriodicTimer(resolvedInterval);
            var cancellation = new CancellationTokenSource();

            _revalidationTimer = timer;
            _revalidationCancellation = cancellation;
            _revalidationTask = Task.Run(
                () => RunRevalidationLoopAsync(timer, cancellation.Token));
        }
    }

    private async Task RunRevalidationLoopAsync(
        PeriodicTimer timer,
        CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    RefreshLicense();
                }
                catch (Exception ex)
                {
                    // A transient provider or validation failure must not fault
                    // the owned background task or stop later refreshes. The
                    // licensing state itself is untouched by a throw here: the
                    // manager keeps the last authoritative state, and every gate
                    // keeps consulting it.
                    ReportRevalidationTimerError(ex);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected when Dispose cancels the pending timer wait.
        }
        catch (Exception ex)
        {
            // PeriodicTimer itself is not expected to fail, but retaining and
            // observing the task is not a substitute for diagnosing a failure.
            ReportRevalidationTimerError(ex);
        }
    }

    /// <summary>
    /// Re-read the license artifact through the wired provider and re-run the
    /// full validation pipeline. Detects expiry, revocation, tampering, a
    /// deleted artifact and a newly installed renewal (which is the only way a
    /// lockdown is cleared). The manager owns the provider-vs-held-artifact
    /// decision so the timer and explicit revalidation cannot diverge.
    /// </summary>
    public LicenseValidationResult RefreshLicense()
        => Manager.Revalidate();

    private static void ReportRevalidationTimerError(Exception ex)
    {
        try
        {
            Console.Error.WriteLine($"[activation] License refresh error: {ex.Message}");
        }
        catch
        {
            // Diagnostics must never turn a handled timer failure into a
            // faulted, unobserved background task.
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Task? loopToJoin;
        CancellationTokenSource? cancellationToDispose;

        lock (_revalidationTimerGate)
        {
            if (_disposed)
                return;

            _disposed = true;

            loopToJoin = _revalidationTask;
            cancellationToDispose = _revalidationCancellation;
            var timer = _revalidationTimer;

            // Clear the owned references before cancellation. Start cannot race
            // this method because it takes the same gate and now sees _disposed.
            _revalidationTimer = null;
            _revalidationCancellation = null;
            _revalidationTask = null;

            try
            {
                cancellationToDispose?.Cancel();
            }
            catch (Exception ex)
            {
                ReportRevalidationTimerError(ex);
            }
            finally
            {
                // Disposing PeriodicTimer makes any pending wait complete; the
                // cancellation token covers the same shutdown path explicitly.
                try { timer?.Dispose(); }
                catch (Exception ex) { ReportRevalidationTimerError(ex); }
            }
        }

        // Join OUTSIDE the gate: a refresh in flight may be inside the license
        // manager's own lock doing RSA verification and file I/O, and holding
        // _revalidationTimerGate across that would serialize unrelated callers
        // (including a concurrent IsRevalidationTimerRunning read) behind disk
        // and crypto work. Waiting here is still required: the loop touches the
        // trust anchor indirectly through the validator, which is disposed below.
        if (loopToJoin is not null)
        {
            try
            {
                loopToJoin.GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) when (cancellationToDispose?.IsCancellationRequested == true)
            {
                // Defensive: the loop normally handles expected cancellation.
            }
            catch (Exception ex)
            {
                // Observe every task failure so Dispose cannot leave an
                // unobserved exception behind.
                ReportRevalidationTimerError(ex);
            }
        }

        try { cancellationToDispose?.Dispose(); }
        catch (Exception ex) { ReportRevalidationTimerError(ex); }

        try { _trustAnchor.Dispose(); }
        catch (Exception ex) { ReportRevalidationTimerError(ex); }

        GC.SuppressFinalize(this);
    }

    /// <summary>Human-readable, secret-free status report for operators and diagnostics.</summary>
    public string DescribeStatus()
    {
        var result = Manager.LastValidationResult;
        // During ActivationRequired the manager does not publish a CurrentLicense (it is not
        // Valid), but the authenticated payload is still available for diagnostics.
        var license = Manager.CurrentLicense ?? result?.License;
        var identity = SafeIdentity();

        var builder = new StringBuilder();
        builder.AppendLine("SSP activation status");
        builder.AppendLine($"  State              : {Manager.CurrentState}");
        builder.AppendLine($"  Reason             : {result?.ReasonCode ?? "(not yet validated)"}");
        if (!string.IsNullOrWhiteSpace(result?.Detail))
        {
            builder.AppendLine($"  Detail             : {result.Detail}");
        }

        if (Manager.CurrentState == LicenseState.ActivationRequired)
        {
            builder.AppendLine("  Action             : run 'SSP.Server --create-activation-request' to produce the");
            builder.AppendLine("                       activation request, send it to the SSP Licensing Authority,");
            builder.AppendLine("                       then run 'SSP.Server --activate <code>' with the returned code.");
        }

        builder.AppendLine($"  Product            : {SspLicensing.ProductName} ({SspLicensing.ProductId:D})");
        builder.AppendLine($"  Trust anchor       : {DescribeTrustAnchor()}");
        builder.AppendLine($"  Installation id    : {identity}");
        if (license is not null)
        {
            var payload = license.Payload;
            builder.AppendLine($"  LicenseId          : {payload.LicenseId:D}");
            builder.AppendLine($"  Customer           : {payload.CustomerName}");
            if (!string.IsNullOrWhiteSpace(payload.OrganizationOrPersonName))
            {
                builder.AppendLine($"  Organization       : {payload.OrganizationOrPersonName}");
            }

            if (!string.IsNullOrWhiteSpace(payload.ComputerName))
            {
                builder.AppendLine($"  Computer           : {payload.ComputerName}");
            }

            builder.AppendLine($"  Edition            : {payload.Edition}");
            builder.AppendLine($"  IssuedAt           : {payload.IssuedAt:o}");
            builder.AppendLine($"  NotBefore          : {payload.NotBefore:o}");
            builder.AppendLine($"  ExpiresAt          : {payload.ExpiresAt:o}");
            builder.AppendLine($"  Installation bound : {payload.InstallationId ?? "(floating)"}");
            builder.AppendLine($"  Sequence           : {payload.SequenceNumber}");
        }
        else
        {
            builder.AppendLine("  License            : (none)");
        }

        builder.AppendLine($"  License file       : {Paths.LicenseFilePath}");
        builder.AppendLine($"  State store        : {Paths.StateStorePath}");
        builder.AppendLine($"  Security log       : {Path.Combine(Paths.SecurityLogDirectory, SspSecurityEventSink.LogFileName)}");
        return builder.ToString();
    }

    /// <summary>
    /// Secret-free identification of the root of trust actually wired into this
    /// runtime: key size plus the SHA-256 of its DER SubjectPublicKeyInfo. The
    /// fingerprint is what an operator compares against the key-ceremony
    /// minutes; the key material itself is never printed (it is public, but a
    /// status report is not a key-distribution channel).
    /// </summary>
    private string DescribeTrustAnchor()
    {
        try
        {
            return $"rsa-{_trustAnchor.KeySizeBits} sha256:{SspTrustAnchor.ComputeFingerprint(_trustAnchor)}";
        }
        catch
        {
            // Diagnostics must never fail a status report.
            return "(unavailable)";
        }
    }

    private string SafeIdentity()
    {
        try
        {
            return _identityProvider.GetInstallationId() ?? "(unavailable)";
        }
        catch
        {
            // The identity provider contract is fail-closed via null; a
            // throwing provider must never break operator diagnostics.
            return "(unavailable)";
        }
    }
}
