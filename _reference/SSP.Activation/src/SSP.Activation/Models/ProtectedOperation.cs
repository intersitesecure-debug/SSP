namespace SSP.Activation;

/// <summary>
/// Description of a protected operation that requires license authorization.
/// Operations are pure value descriptions — the licensing library performs no I/O to
/// evaluate them; usage counts are supplied by the host (SSP.Core owns runtime counters).
/// </summary>
public sealed record ProtectedOperation
{
    internal const string UseFeatureKind = "use_feature";
    internal const string LimitCheckKind = "limit_check";

    private ProtectedOperation(string kind, string? feature, string? limitName, long currentUsage)
    {
        Kind = kind;
        Feature = feature;
        LimitName = limitName;
        CurrentUsage = currentUsage;
    }

    /// <summary>Operation kind discriminator ("use_feature" or "limit_check").</summary>
    public string Kind { get; }

    /// <summary>Requested feature for use_feature operations.</summary>
    public string? Feature { get; }

    /// <summary>Limit to enforce for limit_check operations.</summary>
    public string? LimitName { get; }

    /// <summary>Current usage count reported by the host, measured BEFORE the new operation is granted.</summary>
    public long CurrentUsage { get; }

    /// <summary>Authorization to use a licensed feature.</summary>
    public static ProtectedOperation UseFeature(string feature)
        => new(UseFeatureKind, feature, null, 0);

    /// <summary>Authorization to start one more protected service instance (limit "max_services").</summary>
    public static ProtectedOperation StartProtectedService(long currentRunningServices)
        => CheckLimit(LicenseLimitNames.MaxServices, currentRunningServices);

    /// <summary>Authorization to establish one more tunnel (limit "max_concurrent_tunnels").</summary>
    public static ProtectedOperation EstablishTunnel(long currentActiveTunnels)
        => CheckLimit(LicenseLimitNames.MaxConcurrentTunnels, currentActiveTunnels);

    /// <summary>Authorization to create one more session (limit "max_concurrent_sessions").</summary>
    public static ProtectedOperation CreateSession(long currentActiveSessions)
        => CheckLimit(LicenseLimitNames.MaxConcurrentSessions, currentActiveSessions);

    /// <summary>Generic limit check against a host-defined limit name.</summary>
    public static ProtectedOperation CheckLimit(string limitName, long currentUsage)
        => new(LimitCheckKind, null, limitName, currentUsage);
}
