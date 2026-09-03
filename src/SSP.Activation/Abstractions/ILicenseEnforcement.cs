namespace SSP.Activation;

/// <summary>
/// Headless enforcement API for protected SSP functionality. Backed by an
/// <see cref="ILicenseManager"/> and an <see cref="ILicensePolicy"/>; performs no I/O and
/// contains no SSP runtime logic. Usage counts are supplied by the host.
/// </summary>
public interface ILicenseEnforcement
{
    AuthorizationDecision CanStartProtectedService(long currentRunningServices = 0);

    AuthorizationDecision CanEstablishTunnel(long currentActiveTunnels = 0);

    AuthorizationDecision CanCreateSession(long currentActiveSessions = 0);

    AuthorizationDecision CanUseFeature(string feature);

    AuthorizationDecision CheckLimit(string limitName, long currentUsage);

    /// <summary>
    /// Requires a valid signed license without requiring a particular feature
    /// or limit. This is used when the host protects an application that has no
    /// feature identity in its own vocabulary.
    /// </summary>
    AuthorizationDecision RequireValidLicense();
}
