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
// anchor above is the only root of trust, and issuance code (LicenseIssuer)
// is never reachable from any shipped runtime path.
//
// Phase 3 scope: composition/bootstrap only. No runtime enforcement gates
// call into this type yet; nothing in the server runtime references it. The
// root exists so the later enforcement phase (and operator tooling) has one
// authoritative way to obtain a fully wired, thread-safe activation runtime.
//
// Fail-closed by construction: the production factory requires a compiled-in
// trust anchor (SspTrustAnchor.Create throws otherwise). There is no
// unmanaged-permissive mode and no environment/config bypass in this layer.

using System.Threading;
using System.Threading.PeriodicTimer;
using System.Text;
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
    private readonly TimeSpan _revalidationInterval = TimeSpan.FromMinutes(30);
    private PeriodicTimer? _revalidationTimer;

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
    /// Headless enforcement facade over <see cref="Manager"/>. The later
    /// enforcement phase calls the protected-operation methods on this facade
    /// from the server control-plane seams. Phase 3 wires it only; nothing
    /// calls it in a runtime path yet.
    /// </summary>
    public LicenseEnforcement Enforcement { get; }

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

    /// <summary>Loads and validates the license through the wired provider (no-op if already loaded).</summary>
    public LicenseValidationResult Load() => Manager.Load();

    /// <summary>Revalidates the currently loaded artifact (periodic/operator refresh).</summary>
    public LicenseValidationResult Revalidate() => Manager.Revalidate();

    /// <summary>
    /// Starts a periodic revalidation timer that periodically calls <see cref="Revalidate"/>
    /// to detect license state changes (expiry, revocation, etc.). The timer runs on a
    /// background thread and transitions the runtime to <see cref="LicenseState.LockedDown"/>
    /// if revalidation fails. The timer is stopped automatically on <see cref="Dispose"/>.
    /// </summary>
    /// <remarks>
    /// The revalidation interval is 30 minutes by default, configurable through the
    /// <see cref="_revalidationInterval"/> field. This interval balances the need to detect
    /// license expiration/revocation promptly against the desire to not add unnecessary
    /// overhead or wake locks on process shutdown.
    ///
    /// The timer uses <see cref="PeriodicTimer"/> and <see cref="Task.Run"/> so that
    /// it does not block shutdown and does not create unobserved background exceptions.
    /// If the timer body throws, the error is logged and the timer continues running.
    /// </remarks>
    public void StartRevalidationTimer()
    {
        // If a timer is already running, do not start another (prevents concurrent loops).
        if (_revalidationTimer is not null) return;

        _revalidationTimer = new PeriodicTimer(_revalidationInterval);
        _ = Task.Run(async delegate
        {
            try
            {
                while (_revalidationTimer is not null && await _revalidationTimer.WaitForNextTickAsync())
                {
                    try
                    {
                        Manager.Revalidate();
                    }
                    catch (Exception ex)
                    {
                        // The timer must not produce unobserved background exceptions.
                        Console.Error.WriteLine($"[activation] Revalidation timer error: {ex.Message}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown; ignore.
            }
        });
    }

    /// <summary>Stops the periodic revalidation timer if running.</summary>
    private void StopRevalidationTimer()
    {
        if (_revalidationTimer is not null)
        {
            _revalidationTimer.Dispose();
            _revalidationTimer = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        StopRevalidationTimer();
        _trustAnchor.Dispose();
    }

    /// <summary>Human-readable, secret-free status report for operators and diagnostics.</summary>
    public string DescribeStatus()
    {
        var result = Manager.LastValidationResult;
        var license = Manager.CurrentLicense;
        var identity = SafeIdentity();

        var builder = new StringBuilder();
        builder.AppendLine("SSP activation status");
        builder.AppendLine($"  State              : {Manager.CurrentState}");
        builder.AppendLine($"  Reason             : {result?.ReasonCode ?? "(not yet validated)"}");
        if (!string.IsNullOrWhiteSpace(result?.Detail))
        {
            builder.AppendLine($"  Detail             : {result.Detail}");
        }

        builder.AppendLine($"  Product            : {SspLicensing.ProductName} ({SspLicensing.ProductId:D})");
        builder.AppendLine($"  Installation id    : {identity}");
        if (license is not null)
        {
            var payload = license.Payload;
            builder.AppendLine($"  LicenseId          : {payload.LicenseId:D}");
            builder.AppendLine($"  Customer           : {payload.CustomerName}");
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
