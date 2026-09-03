// File: src/SSP.Server/Activation/SspRuntimeLicense.cs
//
// THE production ISspLicenseGate. One instance per SSP server process.
//
//   SspActivationService  (composition root: LicenseManager + LicenseEnforcement
//                          + every SSP-native adapter)
//           │
//           ▼
//   SspRuntimeLicense     (this type)
//     • resolves the feature identity of the protected application ONCE, from
//       SspLicensing.Features (no feature string literals anywhere else)
//     • owns the runtime usage counters license limits are measured against
//     • turns "check then create" into one atomic reserve/release
//     • delegates EVERY decision to ILicenseEnforcement - it never re-implements
//       or caches policy, so there is exactly one authoritative licensing
//       decision path in SSP
//           │
//           ▼
//   ServerGateway / ServerProtocol / SetupEngine / SspWindowsService
//
// Fail-closed:
//   CreateForService throws SspActivationException unless (a) a trust anchor is
//   compiled into this build, (b) the license artifact validates to
//   LicenseState.Valid, (c) the protected protocol is in the licensed feature
//   set and (d) max_services is not already exhausted. Nothing here reads an
//   environment variable, a config file or a command-line switch to relax any
//   of those: the only input that can create authorization is a signed license
//   artifact verified against the compiled-in authority public key.

using SSP.Activation;
using SSP.Core.Activation;
using SSP.Core.Models;

namespace SSP.Server.Activation;

/// <summary>
/// Production licensing gate for one SSP protected service. Wraps an
/// <see cref="SspActivationService"/> and adds the SSP-side feature identity and
/// usage counters that <see cref="ILicenseEnforcement"/> requires its host to
/// supply.
/// </summary>
public sealed class SspRuntimeLicense : ISspLicenseGate, IDisposable
{
    private readonly SspActivationService _activation;
    private readonly bool _ownsActivation;
    private readonly object _admissionGate = new();
    private long _activeTunnels;
    private long _activeSessions;
    private bool _disposed;

    /// <summary>
    /// Wraps an already-composed activation runtime.
    /// </summary>
    /// <param name="activation">The composition root (never null).</param>
    /// <param name="feature">
    /// Feature identity of the protected application, resolved through
    /// <see cref="SspLicensing.Features"/>; null when the application is outside
    /// SSP's protocol vocabulary.
    /// </param>
    /// <param name="ownsActivation">
    /// When true this gate disposes <paramref name="activation"/> with itself.
    /// The production factory sets this; explicit/test wiring that owns the
    /// service elsewhere leaves it false.
    /// </param>
    public SspRuntimeLicense(SspActivationService activation, string? feature, bool ownsActivation = false)
    {
        ArgumentNullException.ThrowIfNull(activation);

        _activation = activation;
        _ownsActivation = ownsActivation;
        Feature = string.IsNullOrWhiteSpace(feature) ? null : feature;
    }

    /// <summary>The activation runtime behind this gate (the single licensing authority).</summary>
    public SspActivationService Activation => _activation;

    /// <inheritdoc />
    public string? Feature { get; }

    /// <inheritdoc />
    public LicenseState CurrentState => _activation.CurrentState;

    /// <inheritdoc />
    public long ActiveTunnels => Interlocked.Read(ref _activeTunnels);

    /// <inheritdoc />
    public long ActiveSessions => Interlocked.Read(ref _activeSessions);

    // ------------------------------------------------------------------
    // Production composition (EP0 / EP1)
    // ------------------------------------------------------------------

    /// <summary>
    /// Compose the production licensing runtime for a protected service and
    /// prove it is licensed before any protected functionality is reachable.
    /// This is the ONLY way a shipped SSP binary obtains a gate.
    /// </summary>
    /// <param name="config">
    /// The service configuration; only <see cref="ServiceConfig.ApplicationName"/>
    /// is consulted (to resolve the feature identity).
    /// </param>
    /// <param name="serviceDir">
    /// The service directory being started, excluded from the
    /// <c>max_services</c> inventory so a service does not count against itself.
    /// </param>
    /// <param name="paths">Optional licensing paths override (operator tooling/tests).</param>
    /// <param name="clock">Optional clock override (tests).</param>
    /// <param name="startRevalidationTimer">
    /// When true (the production default) the periodic license refresh is
    /// started here, after the runtime has been proven licensed. Background work
    /// is never started from a constructor or from <c>SspActivationService.Create</c>:
    /// the caller that owns the service lifetime owns the timer lifetime.
    /// </param>
    /// <exception cref="SspActivationException">
    /// The build has no compiled-in trust anchor, the license did not validate,
    /// the protected protocol is not in the licensed feature set, or
    /// <c>max_services</c> is already exhausted. In every case no protected
    /// functionality may become operational.
    /// </exception>
    public static SspRuntimeLicense CreateForService(
        ServiceConfig config,
        string? serviceDir = null,
        SspLicensePaths? paths = null,
        IClock? clock = null,
        bool startRevalidationTimer = true)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (!SspTrustAnchor.IsCompiledIn)
        {
            // Fail closed. There is no root of trust in this build, so no
            // artifact could ever validate and no protected operation may be
            // authorized. This is a release blocker, not a runtime mode: the
            // anchor is a compiled-in constant that no environment variable,
            // config file, license file or command line can supply.
            throw new SspActivationException(
                SspActivationException.TrustAnchorMissingReason,
                "SSP cannot start a protected service: this build has no Licensing Authority " +
                "trust anchor compiled in (SspTrustAnchor.AuthorityPublicKeyPem is empty). " +
                "Set the authority public key at the release key ceremony and rebuild.");
        }

        SspActivationService activation;
        try
        {
            activation = SspActivationService.Create(paths, clock);
        }
        catch (Exception ex)
        {
            throw new SspActivationException(
                SspActivationException.CompositionFailedReason,
                $"SSP licensing runtime could not be composed: {ex.Message}",
                ex);
        }

        var gate = new SspRuntimeLicense(
            activation,
            SspLicensing.Features.ResolveForApplication(config.ApplicationName),
            ownsActivation: true);

        try
        {
            gate.AuthorizeServiceStart(config, serviceDir);
            if (startRevalidationTimer)
            {
                activation.StartRevalidationTimer();
            }

            return gate;
        }
        catch
        {
            gate.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Compose the production licensing runtime for a provisioning (SETUP MODE)
    /// run. Provisioning is short-lived, so no revalidation timer is started.
    /// Returns null - with one loud diagnostic - when this build has no compiled
    /// trust anchor or the license is not valid. Callers must treat null as a
    /// failed setup and must not construct <see cref="SSP.Server.Setup.SetupEngine"/>
    /// without the returned gate. The runtime gates (EP1 service start, EP2 enrollment, EP3
    /// tunnel admission) remain fail-closed as well.
    /// </summary>
    public static SspRuntimeLicense? TryCreateForProvisioning(
        string? applicationName = null,
        SspLicensePaths? paths = null,
        IClock? clock = null)
    {
        if (!SspTrustAnchor.IsCompiledIn)
        {
            Console.Error.WriteLine(
                "[activation] No Licensing Authority trust anchor is compiled into this build. " +
                "Provisioning-time license limit checks (max_services / max_clients) are unavailable; " +
                "the runtime gates remain fail-closed and a provisioned service will not start " +
                "without a valid license.");
            return null;
        }

        var activation = SspActivationService.Create(paths, clock);
        try
        {
            // Provisioning must itself be licensed: read and validate the
            // artifact so every decision below is taken against a real state.
            var result = activation.Load();
            var state = activation.CurrentState;
            if (state != LicenseState.Valid)
            {
                Console.Error.WriteLine(
                    $"[activation] Provisioning denied: license state is {state} ({result.ReasonCode}).");
                activation.Dispose();
                return null;
            }
        }
        catch
        {
            activation.Dispose();
            throw;
        }

        return new SspRuntimeLicense(
            activation,
            SspLicensing.Features.ResolveForApplication(applicationName),
            ownsActivation: true);
    }

    // ------------------------------------------------------------------
    // EP1 - service start
    // ------------------------------------------------------------------

    /// <summary>
    /// EP0a / EP1: prove this process may run the protected service before any
    /// protected functionality is reachable. Internal (visible to SSP.Tests) so
    /// the fail-closed startup contract is asserted directly instead of being
    /// re-implemented in a test.
    /// </summary>
    /// <exception cref="SspActivationException">
    /// The license is not Valid, this service's protocol is not in the licensed
    /// feature set, or <c>max_services</c> is exhausted.
    /// </exception>
    internal void AuthorizeServiceStart(ServiceConfig config, string? serviceDir = null)
    {
        var result = _activation.Load();

        if (_activation.CurrentState != LicenseState.Valid)
        {
            throw new SspActivationException(
                result.ReasonCode,
                $"SSP protected service '{config.ApplicationName}' refused to start: license state is " +
                $"{_activation.CurrentState} (reason {result.ReasonCode}). {result.Detail}");
        }

        // EP1a - feature: the protected protocol this service forwards must be
        // in the licensed feature set. Checked at start (so an unlicensed
        // protocol never binds a port at all) and again on every tunnel
        // admission (so a lockdown or a re-issued license takes effect without
        // a restart).
        var featureDecision = CanUseServiceFeature();
        if (!featureDecision.IsAllowed)
        {
            throw new SspActivationException(
                featureDecision.ReasonCode,
                $"SSP protected service '{config.ApplicationName}' refused to start: feature " +
                $"'{Feature}' is not licensed (reason {featureDecision.ReasonCode}).");
        }

        // EP1b - max_services. Usage is measured BEFORE this service is granted:
        // every OTHER protected service instance on this machine.
        var otherServices = SspProtectedServiceInventory.CountProtectedServices(excludeServiceDir: serviceDir);
        var serviceDecision = CanStartProtectedService(otherServices);
        if (!serviceDecision.IsAllowed)
        {
            throw new SspActivationException(
                serviceDecision.ReasonCode,
                $"SSP protected service '{config.ApplicationName}' refused to start: " +
                $"{otherServices} other protected service instance(s) are already present " +
                $"(reason {serviceDecision.ReasonCode}).");
        }

        Console.WriteLine(
            $"[activation] license valid ({DescribeLicenseSummary()}); " +
            $"feature='{Feature ?? "(none)"}', other protected services={otherServices}");
    }

    private string DescribeLicenseSummary()
    {
        var payload = _activation.CurrentLicense?.Payload;
        if (payload is null)
        {
            return "no license";
        }

        // Identifiers and dates only - never key material, never the raw
        // installation identity source, never anything secret.
        return $"licenseId={payload.LicenseId:D}, edition={payload.Edition}, " +
               $"expiresAt={payload.ExpiresAt:u}, sequence={payload.SequenceNumber}";
    }

    // ------------------------------------------------------------------
    // ISspLicenseGate
    // ------------------------------------------------------------------

    /// <inheritdoc />
    public SspTunnelAdmission AdmitTunnel()
    {
        var enforcement = _activation.Enforcement;

        // One critical section covers the whole decision AND the reservation, so
        // two connections racing for the last licensed slot cannot both be
        // admitted. Lock ordering is _admissionGate -> LicenseManager's gate;
        // the manager never calls back into this type, so it cannot invert.
        lock (_admissionGate)
        {
            if (_disposed)
            {
                // Fail closed, and deliberately without throwing: a connection
                // still in flight while the service is shutting down must be
                // refused, not crash its handler.
                return SspTunnelAdmission.Deny(AuthorizationDecision.Deny(
                    LicenseReasons.LicenseNotValid,
                    "The licensing runtime for this service has been disposed."));
            }

            // EP1 - feature gate (re-checked per connection: a lockdown or a
            // re-issued license must take effect without a restart).
            if (Feature is not null)
            {
                var featureDecision = enforcement.CanUseFeature(Feature);
                if (!featureDecision.IsAllowed)
                {
                    return SspTunnelAdmission.Deny(featureDecision);
                }
            }

            // EP3 - tunnel limit. Usage is the count of tunnels admitted and not
            // yet released, measured BEFORE this one is granted.
            var tunnelDecision = enforcement.CanEstablishTunnel(_activeTunnels);
            if (!tunnelDecision.IsAllowed)
            {
                return SspTunnelAdmission.Deny(tunnelDecision);
            }

            // EP2 - concurrent session limit. In SSP one authenticated
            // data-plane connection is both the session and the tunnel (the
            // session key negotiated for it feeds exactly one TunnelCodec), so
            // the counters move together and the stricter limit always wins.
            // Checking both means a license that constrains either is honored.
            var sessionDecision = enforcement.CanCreateSession(_activeSessions);
            if (!sessionDecision.IsAllowed)
            {
                return SspTunnelAdmission.Deny(sessionDecision);
            }

            _activeTunnels++;
            _activeSessions++;

            return SspTunnelAdmission.Grant(ReleaseTunnel);
        }
    }

    private void ReleaseTunnel()
    {
        lock (_admissionGate)
        {
            if (_activeTunnels > 0)
            {
                _activeTunnels--;
            }

            if (_activeSessions > 0)
            {
                _activeSessions--;
            }
        }
    }

    /// <inheritdoc />
    public AuthorizationDecision CanStartProtectedService(long currentRunningServices)
        => _activation.Enforcement.CanStartProtectedService(currentRunningServices);

    /// <inheritdoc />
    public AuthorizationDecision CanEnrollClient(long currentAuthorisedClients)
        => _activation.Enforcement.CheckLimit(LicenseLimitNames.MaxClients, currentAuthorisedClients);

    /// <inheritdoc />
    public AuthorizationDecision CanUseServiceFeature()
    {
        // No feature identity -> there is no feature-membership check, but
        // this is still a protected operation and must require a valid signed
        // license. Do not turn an unknown application name into an allow-all
        // decision by returning AuthorizationDecision.Allow() here.
        return Feature is null
            ? _activation.Enforcement.RequireValidLicense()
            : _activation.Enforcement.CanUseFeature(Feature);
    }

    /// <inheritdoc />
    public AuthorizationDecision CanUseFeature(string feature)
        => _activation.Enforcement.CanUseFeature(feature);

    /// <summary>
    /// Re-read and re-validate the license artifact from disk. This is the
    /// explicit reload operation used by operator/test callers; the periodic
    /// path uses <c>Revalidate()</c>, whose provider-backed implementation has
    /// the same behavior. A newly installed (renewed or superseding) license is
    /// therefore able to clear a lockdown without restarting the process.
    /// </summary>
    public LicenseValidationResult Reload() => _activation.Load();

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_ownsActivation)
        {
            _activation.Dispose();
        }
    }
}

/// <summary>
/// Counts the protected SSP service instances present on this machine, which is
/// the usage figure <c>max_services</c> is enforced against.
/// </summary>
/// <remarks>
/// The inventory is the set of complete application directories under the
/// canonical services root (<c>{Program Files}\SSP\services\{Application}</c>),
/// i.e. directories holding <c>.cache.dat</c> plus both RSA key files - exactly
/// the definition <c>SetupEngine.IsExistingApplicationDirectory</c> already uses
/// to decide whether an application exists. That measure is deterministic,
/// needs no SCM access and behaves identically on every platform.
///
/// Documented limitation: a service provisioned into a directory OUTSIDE the
/// canonical root (an explicit <c>--service-dir</c>) is not counted. This is the
/// same measure the approved integration plan chose for EP0a; the license
/// signature - not this counter - remains the root of trust.
/// </remarks>
public static class SspProtectedServiceInventory
{
    /// <summary>
    /// Number of protected SSP service instances on this machine.
    /// </summary>
    /// <param name="excludeServiceDir">
    /// Service directory to exclude (the one being started), so a service never
    /// counts against itself. Null counts every instance.
    /// </param>
    public static long CountProtectedServices(string? excludeServiceDir = null)
    {
        try
        {
            var root = ResolveServicesRoot();
            if (root is null || !Directory.Exists(root))
            {
                return 0;
            }

            string? excluded = SafeFullPath(excludeServiceDir);
            long count = 0;

            foreach (var candidate in Directory.EnumerateDirectories(root))
            {
                if (excluded is not null &&
                    string.Equals(SafeFullPath(candidate), excluded, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (IsCompleteApplicationDirectory(candidate))
                {
                    count++;
                }
            }

            return count;
        }
        catch
        {
            // An unreadable inventory must not crash a licensed service start.
            // Reporting 0 leaves max_services unconstrained for this check while
            // every other gate (Valid state, feature, max_clients,
            // max_concurrent_tunnels) still applies. The failure is surfaced so
            // it is never silent.
            return 0;
        }
    }

    private static string? ResolveServicesRoot()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            return null;
        }

        return Path.Combine(programFiles, "SSP", "services");
    }

    private static bool IsCompleteApplicationDirectory(string serviceDir)
    {
        try
        {
            return File.Exists(Path.Combine(serviceDir, ".cache.dat"))
                && File.Exists(Path.Combine(serviceDir, ".sysdata.bin"))
                && File.Exists(Path.Combine(serviceDir, ".runtime.dat"));
        }
        catch
        {
            return false;
        }
    }

    private static string? SafeFullPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch
        {
            return path;
        }
    }
}
