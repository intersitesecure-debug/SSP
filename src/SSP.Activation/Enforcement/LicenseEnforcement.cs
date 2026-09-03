namespace SSP.Activation;

/// <summary>
/// Headless enforcement facade over an <see cref="ILicenseManager"/>. This is the concrete
/// API SSP.Core calls to gate protected functionality; it contains no SSP runtime logic.
/// </summary>
public sealed class LicenseEnforcement : ILicenseEnforcement
{
    private readonly ILicenseManager _manager;

    public LicenseEnforcement(ILicenseManager manager)
    {
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
    }

    public AuthorizationDecision CanStartProtectedService(long currentRunningServices = 0)
        => _manager.Authorize(ProtectedOperation.StartProtectedService(currentRunningServices));

    public AuthorizationDecision CanEstablishTunnel(long currentActiveTunnels = 0)
        => _manager.Authorize(ProtectedOperation.EstablishTunnel(currentActiveTunnels));

    public AuthorizationDecision CanCreateSession(long currentActiveSessions = 0)
        => _manager.Authorize(ProtectedOperation.CreateSession(currentActiveSessions));

    public AuthorizationDecision CanUseFeature(string feature)
        => _manager.Authorize(ProtectedOperation.UseFeature(feature));

    public AuthorizationDecision CheckLimit(string limitName, long currentUsage)
        => _manager.Authorize(ProtectedOperation.CheckLimit(limitName, currentUsage));

    /// <summary>
    /// Requires a valid signed license without adding a feature or limit
    /// constraint. Hosts use this for protected applications outside their
    /// known feature vocabulary.
    /// </summary>
    public AuthorizationDecision RequireValidLicense()
        => _manager.Authorize(ProtectedOperation.RequireValidLicense());
}
