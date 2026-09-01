namespace SSP.Activation;

/// <summary>
/// Installation identity provider backed by a fixed identifier supplied by the host.
/// Useful for explicit deployments and tests. Production SSP installations should supply
/// a protected identity implementation instead (see docs/ARCHITECTURE.md §5); the
/// licensing library deliberately does not derive identity from hardware APIs.
/// </summary>
public sealed class StaticInstallationIdentityProvider : IInstallationIdentityProvider
{
    private readonly string? _installationId;

    public StaticInstallationIdentityProvider(string? installationId)
    {
        _installationId = installationId;
    }

    public string? GetInstallationId() => _installationId;
}
