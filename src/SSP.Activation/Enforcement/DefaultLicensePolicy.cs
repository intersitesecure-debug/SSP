namespace SSP.Activation;

/// <summary>
/// Default fail-closed policy: protected operations are allowed only when the manager is
/// in the Valid state AND the operation is covered by the signed license payload
/// (feature present / limit not exceeded). Unknown operation kinds are denied.
/// </summary>
public sealed class DefaultLicensePolicy : ILicensePolicy
{
    public static DefaultLicensePolicy Instance { get; } = new();

    public AuthorizationDecision Evaluate(LicenseEvaluationContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (context.ManagerState != LicenseState.Valid || context.License is null)
        {
            return AuthorizationDecision.Deny(
                LicenseReasons.LicenseNotValid,
                $"Protected operation denied: license state is {context.ManagerState}.");
        }

        var payload = context.License.Payload;

        switch (context.Operation.Kind)
        {
            case ProtectedOperation.RequireValidLicenseKind:
                // The common state/license guard above has already run. This
                // operation intentionally adds no feature or limit constraint.
                return AuthorizationDecision.Allow();

            case ProtectedOperation.UseFeatureKind:
            {
                var feature = context.Operation.Feature;
                if (!LicenseFeatureSet.TryNormalize(feature, out _))
                {
                    return AuthorizationDecision.Deny(
                        LicenseReasons.InvalidOperation,
                        "Feature name is missing or invalid.");
                }

                if (!payload.FeatureSet.Contains(feature))
                {
                    return AuthorizationDecision.Deny(
                        LicenseReasons.FeatureNotLicensed,
                        $"Feature '{feature}' is not part of the licensed feature set.");
                }

                return AuthorizationDecision.Allow();
            }

            case ProtectedOperation.LimitCheckKind:
            {
                var limitName = context.Operation.LimitName;
                if (!LicenseFeatureSet.TryNormalize(limitName, out _))
                {
                    return AuthorizationDecision.Deny(
                        LicenseReasons.InvalidOperation,
                        "Limit name is missing or invalid.");
                }

                if (context.Operation.CurrentUsage < 0)
                {
                    return AuthorizationDecision.Deny(
                        LicenseReasons.InvalidOperation,
                        "Current usage must not be negative.");
                }

                if (!payload.Limits.TryGetValue(limitName, out var max) || max is null)
                {
                    // Absent limits and explicitly unlimited (null) limits are unconstrained.
                    return AuthorizationDecision.Allow();
                }

                if (context.Operation.CurrentUsage < max.Value)
                {
                    return AuthorizationDecision.Allow();
                }

                return AuthorizationDecision.Deny(
                    LicenseReasons.LimitExceeded,
                    $"Limit '{limitName}' ({max.Value}) would be exceeded by this operation (current usage {context.Operation.CurrentUsage}).");
            }

            default:
                return AuthorizationDecision.Deny(
                    LicenseReasons.OperationNotSupported,
                    $"Operation kind '{context.Operation.Kind}' is not supported.");
        }
    }
}
