// File: tests/SSP.Tests/Activation/Runtime/ActivationRuntimeEnforcementTests.cs
//
// The activation state machine through the REAL SSP runtime gate: an
// activation-required license denies every protected-operation boundary
// (service start, enrollment, service feature, feature use, tunnel admission),
// and the same boundaries open once the operator supplies the correct code.
// The enforcement is at the existing gate boundaries, not a boolean flag.

using SSP.Activation;
using SSP.Core.Activation;
using SSP.Tests.Helpers;

namespace SSP.Tests.Activation.Runtime;

public class ActivationRuntimeEnforcementTests
{
    private static LicensedTestOptions ActivationRequiredOptions()
        => new() { Certified = true, ActivationRequired = true };

    [Fact]
    public void ActivationRequired_EveryProtectedBoundaryIsDenied()
    {
        using var env = LicensedTestEnvironment.Create(ActivationRequiredOptions());

        var result = env.Load();

        Assert.Equal(LicenseState.ActivationRequired, result.State);
        Assert.Equal(LicenseState.ActivationRequired, env.State);
        Assert.False(result.IsValid);

        Assert.False(env.Gate.CanStartProtectedService(currentRunningServices: 0).IsAllowed);
        Assert.False(env.Gate.CanEnrollClient(currentAuthorisedClients: 0).IsAllowed);
        Assert.False(env.Gate.CanUseServiceFeature().IsAllowed);
        Assert.False(env.Gate.CanUseFeature(SspLicensing.Features.RemoteDesktopProtocol).IsAllowed);
        using (var admission = env.Gate.AdmitTunnel())
        {
            Assert.False(admission.IsAdmitted);
        }
    }

    [Fact]
    public void WrongCode_DoesNotOpenAnyBoundary()
    {
        using var env = LicensedTestEnvironment.Create(ActivationRequiredOptions());
        env.Load();

        var wrong = env.Activation.TryActivate("0000000000");

        Assert.False(wrong.IsValid);
        Assert.Equal(LicenseState.ActivationRequired, env.State);
        Assert.False(env.Gate.CanStartProtectedService(0).IsAllowed);
    }

    [Fact]
    public void CorrectCode_OpensEveryProtectedBoundary()
    {
        using var env = LicensedTestEnvironment.Create(ActivationRequiredOptions());
        env.Load();
        Assert.Equal(LicenseState.ActivationRequired, env.State);

        var activated = env.Activation.TryActivate(env.IssuedActivationCode!);

        Assert.True(activated.IsValid);
        Assert.Equal(LicenseState.Valid, env.State);
        Assert.NotNull(env.Activation.CurrentLicense);

        Assert.True(env.Gate.CanStartProtectedService(0).IsAllowed);
        Assert.True(env.Gate.CanEnrollClient(0).IsAllowed);
        Assert.True(env.Gate.CanUseServiceFeature().IsAllowed);
        Assert.True(env.Gate.CanUseFeature(SspLicensing.Features.RemoteDesktopProtocol).IsAllowed);
        using (var admission = env.Gate.AdmitTunnel())
        {
            Assert.True(admission.IsAdmitted);
        }
    }

    [Fact]
    public void ActivatedLicense_SurvivesRecomposition_OverTheSameStateStore()
    {
        using var env = LicensedTestEnvironment.Create(ActivationRequiredOptions());
        env.Load();
        Assert.True(env.Activation.TryActivate(env.IssuedActivationCode!).IsValid);

        // A second protected-service process on the same host composes a fresh runtime
        // over the same artifact and the same durable state store. The activated license
        // id is persisted, so no re-activation is required.
        using var second = env.CreateAdditionalServiceGate("RDP");
        var result = second.Reload();

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, second.CurrentState);
        Assert.True(second.CanStartProtectedService(0).IsAllowed);
    }

    [Fact]
    public void ActivationRequest_IsProducedOnlyWhileActivationRequired()
    {
        using var env = LicensedTestEnvironment.Create(ActivationRequiredOptions());
        env.Load();

        var request = env.Activation.CreateActivationRequest();

        Assert.NotNull(request);
        Assert.Equal(env.IssuedActivationOtt, request!.ActivationOtt);
        // While ActivationRequired the manager does not publish a CurrentLicense (it is not Valid).
        Assert.Null(env.Activation.CurrentLicense);

        // Once activated, no further activation request is produced.
        Assert.True(env.Activation.TryActivate(env.IssuedActivationCode!).IsValid);
        Assert.Null(env.Activation.CreateActivationRequest());
    }

    [Fact]
    public void PreActivatedCertifiedLicense_NeedsNoActivation()
    {
        using var env = LicensedTestEnvironment.Create(new LicensedTestOptions
        {
            Certified = true,
            ActivationRequired = false
        });

        var result = env.Load();

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, env.State);
        Assert.Null(env.Activation.CreateActivationRequest());
        Assert.True(env.Gate.CanStartProtectedService(0).IsAllowed);
    }
}
