// File: src/SSP.Server/Activation/SspLicensePaths.cs
//
// Canonical on-disk locations of the SSP activation (licensing) subsystem.
//
// All activation state lives under the machine's canonical product root in a
// dedicated `licensing` directory:
//
//   {Canonical Product Root}/licensing/
//   ├── license.json               (the signed artifact; transport only)
//   ├── activation-request.json    (offline activation request; transport only)
//   ├── .license-state.dat         (DPAPI-encrypted anti-rollback floor + activated license id)
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
    /// Name of the activation-request file written when a license is awaiting activation.
    /// Transport only: the file carries the license identity and the activation OTT for
    /// out-of-band delivery to the Licensing Authority. Not a security boundary.
    /// </summary>
    public const string ActivationRequestFileName = "activation-request.json";

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

    /// <summary>
    /// Root of the licensing directory (always an absolute path in canonical
    /// form: normalized separators and no trailing directory separator, so
    /// every spelling of the same directory yields the same value).
    /// </summary>
    public string LicenseDirectory { get; }

    /// <summary>Full path of the signed license artifact read by the license provider.</summary>
    public string LicenseFilePath => Path.Combine(LicenseDirectory, LicenseFileName);

    /// <summary>Full path of the activation-request file (offline transport, written by SSP.Server).</summary>
    public string ActivationRequestFilePath => Path.Combine(LicenseDirectory, ActivationRequestFileName);

    /// <summary>Full path of the encrypted anti-rollback state file.</summary>
    public string StateStorePath => Path.Combine(LicenseDirectory, StateFileName);

    /// <summary>
    /// Full path of the redundant encrypted anti-rollback WITNESS file
    /// (Phase 4 / M-3). The witness deliberately lives OUTSIDE the licensing
    /// directory — one directory level above it, in the
    /// <c>.ssp-state-witness</c> tree — so deleting, rolling back or
    /// restoring the licensing directory itself cannot take the witness with
    /// it. Kept in sync with <see cref="SspLicenseStateStore.WitnessPath"/>
    /// (both derive through <see cref="SSP.Core.IO.SspStateWitnessPaths"/>).
    /// </summary>
    public string StateWitnessPath =>
        SspStateWitnessPaths.GetWitnessPath(LicenseDirectory, SspStateWitnessPaths.LicenseStatePurpose);

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
    /// <para>
    /// The selected root is canonicalized with <see cref="Path.GetFullPath"/>
    /// (a relative override resolves against the process working directory)
    /// followed by <see cref="Path.TrimEndingDirectorySeparator"/>, so a
    /// trailing or redundant directory separator in the override produces the
    /// same value as the plain spelling: every spelling of one directory
    /// resolves to one equal <see cref="SspLicensePaths"/> record and one
    /// identical set of derived file paths (the trailing separator was
    /// cosmetic for <see cref="Path.Combine"/> file access, but it broke the
    /// record's value semantics).
    /// </para>
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

        // Canonicalize the directory. GetFullPath makes an override absolute (a
        // relative value resolves against the process working directory) and
        // normalizes separators and ./.. segments, but it deliberately PRESERVES
        // a trailing directory separator. Trim that trailing separator away
        // (root-safely: "C:\", "/" and UNC roots are returned unchanged) so that
        // every spelling of one directory resolves to exactly one
        // SspLicensePaths value: the license provider, the DPAPI state store and
        // the security event sink must never alias the same directory under two
        // different spellings. Pure string canonicalization - no I/O, and it
        // only selects which directory is read, never what is authorized.
        return new SspLicensePaths(Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)));
    }
}
