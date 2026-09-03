// File: src/SSP.Server/Activation/ISspLicenseGate.cs
//
// The SINGLE SSP-side licensing boundary that runtime components consume.
//
// Why this exists (P3 hardening):
//   The vendored SSP.Activation library exposes ILicenseEnforcement, whose
//   methods take the *current usage* as a caller-supplied argument. SSP runtime
//   components must not each invent their own usage counts, feature strings or
//   check ordering - that is how the previous integration ended up with
//   CanStartProtectedService(1) on every inbound socket and
//   CanEstablishTunnel(0) on every tunnel, neither of which enforced anything.
//
//   ISspLicenseGate owns exactly three things on behalf of one SSP server
//   process:
//     1. the authoritative licensing decisions (delegated, never duplicated, to
//        ILicenseEnforcement -> LicenseManager -> DefaultLicensePolicy),
//     2. the feature identity of the protected application being served, and
//     3. the runtime usage counters the license limits are measured against,
//        with an atomic reserve/release so "check then create" cannot race.
//
//   Every gate implementation consults the LicenseManager on EVERY call. No
//   implementation may cache a bool such as "isLicensed": the whole point of
//   the gate is that a Valid -> LockedDown transition is visible to the next
//   protected operation immediately.
//
// Production/test split (fail-closed by construction):
//   SspRuntimeLicense is the only production implementation and it cannot be
//   built without a compiled-in trust anchor and a Valid license. Runtime
//   components take a NON-NULLABLE gate, so "no enforcement object" is not
//   representable in a production composition path. Test code that deliberately
//   exercises unlicensed runtime components supplies its own explicit, loudly
//   named gate (tests/SSP.Tests/Helpers/UnlicensedTestGate.cs); that type lives
//   in the test assembly and is not reachable from any shipped binary.

using SSP.Activation;

namespace SSP.Server.Activation;

/// <summary>
/// SSP's runtime licensing boundary. One instance per SSP server process (one
/// protected application), owned by the composition root that started it.
/// </summary>
public interface ISspLicenseGate
{
    /// <summary>
    /// The license feature identity of the protected application this process
    /// serves (see <c>SspLicensing.Features</c>), or null when the application
    /// name is not one of SSP's known protected protocols. A null feature
    /// removes only the feature check; the license-state and limit checks are
    /// unconditional.
    /// </summary>
    string? Feature { get; }

    /// <summary>
    /// The current authoritative runtime state, read live from the license
    /// manager. Diagnostics only - never cache it and never derive an
    /// authorization decision from it in SSP code; call the decision methods.
    /// </summary>
    LicenseState CurrentState { get; }

    /// <summary>Concurrently admitted tunnels in this process (EP2/EP3 counter).</summary>
    long ActiveTunnels { get; }

    /// <summary>Concurrently admitted sessions in this process (EP2/EP3 counter).</summary>
    long ActiveSessions { get; }

    /// <summary>
    /// EP1 + EP2 + EP3 combined, atomically: authorize ONE new protected
    /// data-plane connection (feature licensed, license Valid, tunnel slot and
    /// session slot available) and reserve the slots in the same critical
    /// section, so two concurrent connections can never both observe the same
    /// "one slot left" state.
    ///
    /// The returned admission is never null. Inspect
    /// <see cref="SspTunnelAdmission.IsAdmitted"/>; disposing it releases the
    /// reserved slots. Disposing a denied admission is a no-op.
    /// </summary>
    /// <remarks>
    /// Callers MUST invoke this only after the connecting client has been
    /// cryptographically authenticated. Reserving a licensed slot for an
    /// unauthenticated connection would let an anonymous peer exhaust
    /// <c>max_concurrent_tunnels</c> and deny service to licensed clients.
    /// </remarks>
    SspTunnelAdmission AdmitTunnel();

    /// <summary>
    /// EP0a / EP1: authorize running one more protected service instance
    /// (limit <c>max_services</c>, plus the Valid-state requirement that
    /// <c>DefaultLicensePolicy</c> applies to every operation).
    /// </summary>
    /// <param name="currentRunningServices">
    /// Protected service instances that already exist/run on this machine,
    /// measured BEFORE this one is granted (the library's convention).
    /// </param>
    AuthorizationDecision CanStartProtectedService(long currentRunningServices);

    /// <summary>
    /// EP0b / EP2: authorize enrolling one more client (limit
    /// <c>max_clients</c>, plus the Valid-state requirement).
    /// </summary>
    /// <param name="currentAuthorisedClients">
    /// Clients already authorized for this service, measured BEFORE this one is
    /// granted. Callers must read this count under the lock that guards the
    /// authoritative store (<c>.index.dat</c>) so the count cannot race.
    /// </param>
    AuthorizationDecision CanEnrollClient(long currentAuthorisedClients);

    /// <summary>
    /// EP1: authorize the protected protocol this service forwards. An
    /// application outside SSP's protocol vocabulary has no feature identity,
    /// but its license-state requirement is still enforced by the gate.
    /// </summary>
    AuthorizationDecision CanUseServiceFeature();

    /// <summary>
    /// EP0a: authorize an arbitrary feature identity (used by provisioning,
    /// where the application - and therefore the feature - is a parameter of the
    /// operation rather than a property of this process). The feature must come
    /// from <c>SspLicensing.Features</c>; SSP contains no other feature strings.
    /// </summary>
    AuthorizationDecision CanUseFeature(string feature);
}

/// <summary>
/// A reserved license slot for one protected data-plane connection. The
/// reservation is taken atomically with the authorization decision (see
/// <see cref="ISspLicenseGate.AdmitTunnel"/>) and released by
/// <see cref="Dispose"/>. Dispose is idempotent and safe to call from a finally
/// block whether or not the tunnel ever became active.
/// </summary>
public sealed class SspTunnelAdmission : IDisposable
{
    private readonly Action? _release;
    private int _disposed;

    private SspTunnelAdmission(AuthorizationDecision decision, Action? release)
    {
        Decision = decision;
        _release = release;
    }

    /// <summary>
    /// Grants an admission. <paramref name="release"/> is invoked exactly once,
    /// on the first <see cref="Dispose"/>, and gives the reserved slots back.
    /// </summary>
    public static SspTunnelAdmission Grant(Action? release = null)
        => new(AuthorizationDecision.Allow(), release);

    /// <summary>Denies an admission. Nothing was reserved, so Dispose is a no-op.</summary>
    public static SspTunnelAdmission Deny(AuthorizationDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);
        if (decision.IsAllowed)
        {
            throw new ArgumentException("A granted decision cannot be used to deny an admission.", nameof(decision));
        }

        return new SspTunnelAdmission(decision, release: null);
    }

    /// <summary>The authoritative decision behind this admission.</summary>
    public AuthorizationDecision Decision { get; }

    /// <summary>True when the tunnel/session slots were reserved and the connection may proceed.</summary>
    public bool IsAdmitted => Decision.IsAllowed;

    /// <summary>Stable reason code for a denial (<see cref="LicenseReasons"/>).</summary>
    public string ReasonCode => Decision.ReasonCode;

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _release?.Invoke();
    }
}

/// <summary>
/// Thrown when SSP refuses to bring up protected functionality because the
/// licensing subsystem is not in the <see cref="LicenseState.Valid"/> state (or
/// cannot be composed at all). This is the fail-closed startup signal: on the
/// Windows Service path it is raised inside <c>OnStart</c>, so the SCM records a
/// diagnosed failed start (ERROR 1064) through <c>ServiceDiagnostics</c>
/// instead of an opaque ERROR 1053.
/// </summary>
public sealed class SspActivationException : Exception
{
    /// <summary>SSP-specific reason code for a missing compiled-in trust anchor.</summary>
    public const string TrustAnchorMissingReason = "trust_anchor_missing";

    /// <summary>SSP-specific reason code for a licensing subsystem that failed to compose.</summary>
    public const string CompositionFailedReason = "activation_composition_failed";

    public SspActivationException(string reasonCode, string message)
        : base(message)
    {
        ReasonCode = reasonCode;
    }

    public SspActivationException(string reasonCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ReasonCode = reasonCode;
    }

    /// <summary>Stable, secret-free reason code (a <see cref="LicenseReasons"/> value or an SSP-specific one).</summary>
    public string ReasonCode { get; }
}
