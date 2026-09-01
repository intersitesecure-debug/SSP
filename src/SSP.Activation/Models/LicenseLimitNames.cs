namespace SSP.Activation;

/// <summary>
/// Conventional limit names understood by the <see cref="ProtectedOperation"/> factories
/// and by <see cref="DefaultLicensePolicy"/>. These names are conventions, not reserved
/// keywords: SSP.Core may enforce additional host-defined limits via
/// <see cref="ProtectedOperation.CheckLimit(string, long)"/>.
/// </summary>
public static class LicenseLimitNames
{
    /// <summary>Maximum number of protected service instances that may run.</summary>
    public const string MaxServices = "max_services";

    /// <summary>Maximum number of licensed clients.</summary>
    public const string MaxClients = "max_clients";

    /// <summary>Maximum total number of sessions.</summary>
    public const string MaxSessions = "max_sessions";

    /// <summary>Maximum number of concurrently active sessions.</summary>
    public const string MaxConcurrentSessions = "max_concurrent_sessions";

    /// <summary>Maximum number of concurrently active tunnels.</summary>
    public const string MaxConcurrentTunnels = "max_concurrent_tunnels";
}
