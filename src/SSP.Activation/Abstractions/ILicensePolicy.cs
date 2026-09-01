namespace SSP.Activation;

/// <summary>
/// Decides whether a protected operation is allowed given the current license state.
/// This is the boundary SSP.Core calls (directly or via <see cref="ILicenseEnforcement"/>).
/// The default policy grants nothing unless the manager state is Valid and the operation
/// is covered by the signed license payload.
/// </summary>
public interface ILicensePolicy
{
    AuthorizationDecision Evaluate(LicenseEvaluationContext context);
}
