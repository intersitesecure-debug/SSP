namespace SSP.Activation;

/// <summary>
/// Provides the stable identity of the current SSP installation for license binding.
/// The licensing library never inspects hardware or OS APIs itself; the host (SSP.Core)
/// supplies a protected implementation (see docs/ARCHITECTURE.md). A provider that cannot
/// determine the identity returns null — validation then fails closed.
/// </summary>
public interface IInstallationIdentityProvider
{
    /// <summary>Stable installation identifier, or null when the identity is unavailable.</summary>
    string? GetInstallationId();
}
