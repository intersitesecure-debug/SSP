// File: src/SSP.Server/Activation/SspLicensePaths.cs
//
// Canonical on-disk locations of the SSP activation (licensing) subsystem.
//
// All activation state lives under the machine's canonical product root in a
// dedicated `licensing` directory:
//
//   {Canonical Product Root}/licensing/
//   ├── license.json               (the signed artifact; transport only)
//   ├── .license-state.dat         (DPAPI-encrypted anti-rollback floor)
//   └── ssp-activation-security.log(security event log)
//
// The product root is the canonical one resolved through
// SSP.Core.ClientInstallPaths.GetCanonicalProductRoot() (i.e.
// C:\Program Files\SSP on Windows), so client and server share one product
// root. Licensing state is redirected only through its own dedicated seam,
// SSP_LICENSE_ROOT (same *pattern* as SSP_CLIENT_ROOT, deliberately not the
// same *variable*), which lets tests and alternative deployments redirect the
// licensing directory without touching Program Files. SSP_CLIENT_ROOT must
// never move the licensing root: it is the client connection-state seam.
// The license file is a signed JSON artifact and is deliberately plaintext (the reference
// architecture: transport is never a security boundary); the state store is
// encrypted at rest and the security log is operator-facing diagnostics.

using SSP.Core.IO;

namespace SSP.Server.Activation;

/// <summary>
/// Canonical activation paths. The composition root resolves these once and
/// hands them to every adapter that needs a file location, so no other SSP
/// component invents its own licensing paths.
/// </summary>
public sealed record SspLicensePaths
{
    /// <summary>Directory name of the licensing root under the product root.</summary>
    public const string LicensingDirectoryName = "licensing";

    /// <summary>Name of the signed license artifact file (transport only).</summary>
    public const string LicenseFileName = "license.json";

    /// <summary>
    /// Name of the encrypted anti-rollback state file. Kept in sync with
    /// <see cref="SspLicenseStateStore.DefaultFileName"/>; the constant is
    /// repeated here so path resolution and the store can never disagree.
    /// </summary>
    public const string StateFileName = SspLicenseStateStore.DefaultFileName;

    /// <summary>
    /// When set, the licensing root is redirected to this directory instead of
    /// the canonical product root. Same *pattern* as SSP_CLIENT_ROOT (a
    /// dedicated per-concern seam), deliberately not the same variable:
    /// SSP_CLIENT_ROOT redirects client connection state only. Used by tests
    /// so they never touch Program Files.
    /// </summary>
    public const string EnvironmentRootOverrideVariable = "SSP_LICENSE_ROOT";

    private SspLicensePaths(string licenseDirectory)
    {
        LicenseDirectory = licenseDirectory;
    }

    /// <summary>Root of the licensing directory (always an absolute path).</summary>
    public string LicenseDirectory { get; }

    /// <summary>Full path of the signed license artifact read by the license provider.</summary>
    public string LicenseFilePath => Path.Combine(LicenseDirectory, LicenseFileName);

    /// <summary>Full path of the encrypted anti-rollback state file.</summary>
    public string StateStorePath => Path.Combine(LicenseDirectory, StateFileName);

    /// <summary>Directory the security event sink writes <see cref="SspSecurityEventSink.LogFileName"/> into.</summary>
    public string SecurityLogDirectory => LicenseDirectory;

    /// <summary>
    /// Resolves the canonical licensing root.
    /// </summary>
    /// <param name="licenseRootOverride">
    /// Explicit root (used by tests and by operator tooling). When null, the
    /// <see cref="EnvironmentRootOverrideVariable"/> environment override is
    /// consulted; when that is unset or blank the canonical
    /// <c>{Canonical Product Root}/licensing</c> location is used.
    /// </param>
    /// <remarks>
    /// Precedence is exactly:
    /// <list type="number">
    ///   <item><description><paramref name="licenseRootOverride"/> (when non-blank)</description></item>
    ///   <item><description><c>SSP_LICENSE_ROOT</c> (when non-blank)</description></item>
    ///   <item><description><c>{Canonical Product Root}/licensing</c>, i.e. C:\Program Files\SSP\licensing</description></item>
    /// </list>
    /// The fallback uses <see cref="ClientInstallPaths.GetCanonicalProductRoot"/>,
    /// <em>not</em> <see cref="ClientInstallPaths.GetProductRoot"/>: the latter
    /// honors <c>SSP_CLIENT_ROOT</c>, which is the client connection-state test
    /// seam. Licensing state is a different concept with its own seam
    /// (<c>SSP_LICENSE_ROOT</c>), so redirecting client state must never
    /// silently relocate (and thereby orphan, or hand back a pristine empty)
    /// the license artifact and the DPAPI anti-rollback floor. Blank values
    /// for either override are treated as "not set", mirroring
    /// <see cref="ClientInstallPaths"/> and <c>AuthenticationCodeFile</c>.
    /// This selects only which directory is read; it can never create
    /// authorization (licensing Invariant 4) — the subsystem stays fail-closed.
    /// </remarks>
    public static SspLicensePaths Resolve(string? licenseRootOverride = null)
    {
        var root = licenseRootOverride;
        if (string.IsNullOrWhiteSpace(root))
        {
            root = Environment.GetEnvironmentVariable(EnvironmentRootOverrideVariable);
        }

        if (string.IsNullOrWhiteSpace(root))
        {
            // Canonical product root, never the SSP_CLIENT_ROOT test redirect.
            root = Path.Combine(ClientInstallPaths.GetCanonicalProductRoot(), LicensingDirectoryName);
        }

        return new SspLicensePaths(Path.GetFullPath(root));
    }
}
