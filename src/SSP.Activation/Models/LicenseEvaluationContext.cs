namespace SSP.Activation;

/// <summary>
/// Input to <see cref="ILicensePolicy"/>. <see cref="License"/> is non-null only while the
/// manager state is Valid; policies must treat every other state as denied-by-default.
/// </summary>
public sealed record LicenseEvaluationContext
{
    public required LicenseState ManagerState { get; init; }

    public required License? License { get; init; }

    public required ProtectedOperation Operation { get; init; }
}
