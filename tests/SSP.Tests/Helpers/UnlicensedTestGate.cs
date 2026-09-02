// File: tests/SSP.Tests/Helpers/UnlicensedTestGate.cs
//
// EXPLICIT TEST SEAM - NOT A PRODUCTION TYPE.
//
// SSP's runtime components take a mandatory, non-nullable ISspLicenseGate, so
// "protected runtime with no enforcement object" is not representable and
// cannot be constructed by accident. Tests that deliberately exercise
// unlicensed runtime components (the pre-existing crypto, framing, tunnel,
// enrollment, multi-service and connection-isolation suites, none of which are
// about licensing) must therefore say so out loud. This type is that statement.
//
// It lives in the TEST assembly: no shipped binary contains it, no production
// composition path can reach it, and nothing in src/ references it. Production
// obtains its gate from SspRuntimeLicense.CreateForService, which refuses to
// return anything unless a trust anchor is compiled in and the license is Valid.
//
// Every decision is recorded so a test can assert what the runtime asked for
// even while the answer is always "allow".

using SSP.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Helpers;

/// <summary>
/// Allow-all licensing gate for tests that are not about licensing. Records
/// every decision requested so a test can assert the runtime consulted the gate
/// at the right boundary.
/// </summary>
public sealed class UnlicensedTestGate : ISspLicenseGate
{
    /// <summary>Shared instance for tests that do not need the call log.</summary>
    public static UnlicensedTestGate Instance { get; } = new();

    private long _activeTunnels;
    private long _activeSessions;

    /// <summary>Always null: this gate is not bound to any application.</summary>
    public string? Feature => null;

    /// <summary>Always Valid - the point of the seam is that licensing is not under test.</summary>
    public LicenseState CurrentState => LicenseState.Valid;

    public long ActiveTunnels => Interlocked.Read(ref _activeTunnels);

    public long ActiveSessions => Interlocked.Read(ref _activeSessions);

    /// <summary>Every gate call made against this instance, in order.</summary>
    public List<string> Calls { get; } = new();

    /// <summary>Total tunnel admissions granted (asserted by the seam's own tests).</summary>
    public int AdmittedTunnels { get; private set; }

    public SspTunnelAdmission AdmitTunnel()
    {
        lock (Calls)
        {
            Calls.Add(nameof(AdmitTunnel));
            AdmittedTunnels++;
            Interlocked.Increment(ref _activeTunnels);
            Interlocked.Increment(ref _activeSessions);
        }

        return SspTunnelAdmission.Grant(() =>
        {
            Interlocked.Decrement(ref _activeTunnels);
            Interlocked.Decrement(ref _activeSessions);
        });
    }

    public AuthorizationDecision CanStartProtectedService(long currentRunningServices)
    {
        lock (Calls)
        {
            Calls.Add($"{nameof(CanStartProtectedService)}({currentRunningServices})");
        }

        return AuthorizationDecision.Allow();
    }

    public AuthorizationDecision CanEnrollClient(long currentAuthorisedClients)
    {
        lock (Calls)
        {
            Calls.Add($"{nameof(CanEnrollClient)}({currentAuthorisedClients})");
        }

        return AuthorizationDecision.Allow();
    }

    public AuthorizationDecision CanUseServiceFeature()
    {
        lock (Calls)
        {
            Calls.Add(nameof(CanUseServiceFeature));
        }

        return AuthorizationDecision.Allow();
    }

    public AuthorizationDecision CanUseFeature(string feature)
    {
        lock (Calls)
        {
            Calls.Add($"{nameof(CanUseFeature)}({feature})");
        }

        return AuthorizationDecision.Allow();
    }
}
