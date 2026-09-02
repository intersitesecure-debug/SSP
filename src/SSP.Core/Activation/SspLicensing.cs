// File: src/SSP.Core/Activation/SspLicensing.cs
//
// SSP licensing identity constants. These are build/deployment constants of
// SSP.Core, never user-editable runtime configuration (see the reference
// library's LicenseValidationOptions contract). SSP.Server's activation
// adapters bind these values into SSP.Activation at composition time; the
// SSP Licensing Authority issues artifacts signed over the same product id
// so a config/program-data change can never redefine which licenses are
// acceptable.

namespace SSP.Core.Activation;

/// <summary>
/// Build-time identity constants that bind the SSP product to the sold
/// activation license vocabulary.
/// </summary>
public static class SspLicensing
{
    /// <summary>
    /// The product identifier SSP expects in every activation artifact.
    ///
    /// This is the SSP product identity for the licensing subsystem. It is
    /// intentionally constant and not read from configuration. If this value
    /// changes, every license previously issued by the SSP Licensing
    /// Authority becomes invalid, so it is established once as part of the
    /// authority/release ceremony and then only changed through the
    /// documented key-ceremony process.
    /// </summary>
    public static readonly Guid ProductId = new("d81f65cb-bd7e-4a6e-9b4c-3be9d13c0f2a");

    /// <summary>The public product name carried in license payloads and diagnostics.</summary>
    public const string ProductName = "SSP";

    /// <summary>
    /// Domain-separation tag mixed into the installation binding hash. The
    /// hash is used only to compare installation ids; the tag prevents an id
    /// computed for another product/purpose from matching an SSP license.
    /// </summary>
    public const string InstallationBindingPurposeTag = "SSP-LICENSE-INSTALL-v1";

    /// <summary>
    /// SSP host feature vocabulary, and the SINGLE mapping mechanism between an
    /// SSP protected application (<c>ServiceConfig.ApplicationName</c>) and the
    /// feature identity carried in a signed license payload.
    ///
    /// The licensing library validates feature-name shape and normalization but
    /// not product semantics ("Feature/limit vocabularies are host conventions"
    /// - reference ARCHITECTURE §15). These constants ARE the SSP conventions.
    /// No other place in SSP may hard-code a feature string: every runtime gate
    /// resolves the feature through <see cref="ResolveForApplication"/> so the
    /// vocabulary can never drift between the server runtime, the setup engine
    /// and the licenses the SSP Licensing Authority issues.
    ///
    /// Names are already in the normalized form the library stores them in
    /// (trimmed, invariant lower-case, no whitespace, &lt;= 64 chars), so they
    /// can be handed to <c>ILicenseEnforcement.CanUseFeature</c> verbatim.
    /// </summary>
    public static class Features
    {
        /// <summary>The Remote Desktop Protocol forwarding capability.</summary>
        public const string RemoteDesktopProtocol = "rdp";

        /// <summary>The Secure Shell forwarding capability.</summary>
        public const string SecureShell = "ssh";

        /// <summary>The HTTP/HTTPS (web) forwarding capability.</summary>
        public const string Web = "web";

        /// <summary>The SQL (TDS / database) forwarding capability.</summary>
        public const string Sql = "sql";

        /// <summary>
        /// Every feature SSP knows how to protect. Ordinal-sorted so it can be
        /// compared against a license feature set deterministically.
        /// </summary>
        public static IReadOnlyList<string> Known { get; } = new[]
        {
            RemoteDesktopProtocol,
            SecureShell,
            Sql,
            Web,
        };

        /// <summary>
        /// Application-name aliases accepted for each feature. Keys and values
        /// are compared after trimming and invariant lower-casing, so an
        /// administrator writing "RDP", "rdp" or " Remote Desktop " all resolve
        /// to <see cref="RemoteDesktopProtocol"/>.
        ///
        /// Only spellings SSP itself already uses are listed (the setup prompts
        /// and the client launcher special-case "RDP"; ServiceBuilder documents
        /// "RDP, WEB, SSH, ..."). No feature name is invented here.
        /// </summary>
        private static readonly Dictionary<string, string> ApplicationAliases =
            new(StringComparer.Ordinal)
            {
                // Remote Desktop Protocol.
                ["rdp"] = RemoteDesktopProtocol,
                ["remote desktop"] = RemoteDesktopProtocol,
                ["remotedesktop"] = RemoteDesktopProtocol,
                ["remote desktop protocol"] = RemoteDesktopProtocol,
                ["mstsc"] = RemoteDesktopProtocol,

                // Secure Shell.
                ["ssh"] = SecureShell,
                ["secure shell"] = SecureShell,
                ["openssh"] = SecureShell,

                // Web / HTTP(S).
                ["web"] = Web,
                ["http"] = Web,
                ["https"] = Web,
                ["rdweb"] = Web,

                // SQL / TDS.
                ["sql"] = Sql,
                ["mssql"] = Sql,
                ["sqlserver"] = Sql,
                ["sql server"] = Sql,
                ["ms sql"] = Sql,
                ["tds"] = Sql,
            };

        /// <summary>
        /// Resolves the license feature identity for an SSP protected
        /// application name. Returns null when the application is not one of
        /// SSP's known protected protocols.
        /// </summary>
        /// <remarks>
        /// A null result is deliberate and fail-safe in the only direction that
        /// matters: SSP protects arbitrary TCP applications, and the
        /// administrator chooses the application name freely. An unrecognized
        /// name therefore carries NO feature identity, which means the feature
        /// gate does not apply - but the license-state gate (Valid) and every
        /// limit gate (<c>max_services</c>, <c>max_clients</c>,
        /// <c>max_concurrent_tunnels</c>, <c>max_concurrent_sessions</c>) still
        /// apply unconditionally. An unlicensed installation is denied whatever
        /// the application is called; a licensed installation is additionally
        /// restricted to the protocols its feature set covers.
        /// </remarks>
        public static string? ResolveForApplication(string? applicationName)
            => TryResolveForApplication(applicationName, out var feature) ? feature : null;

        /// <summary>
        /// <see cref="ResolveForApplication"/> in Try form. The returned
        /// feature is always one of the <see cref="Known"/> values (already in
        /// the library's normalized form).
        /// </summary>
        public static bool TryResolveForApplication(string? applicationName, out string feature)
        {
            feature = string.Empty;
            if (string.IsNullOrWhiteSpace(applicationName))
            {
                return false;
            }

            var normalized = applicationName.Trim().ToLowerInvariant();
            if (normalized.Length == 0)
            {
                return false;
            }

            if (!ApplicationAliases.TryGetValue(normalized, out var resolved))
            {
                return false;
            }

            feature = resolved;
            return true;
        }
    }

    /// <summary>
    /// SSP host limit vocabulary. The string values mirror
    /// <c>SSP.Activation.LicenseLimitNames</c>; they are duplicated here so
    /// SSP.Core can express/vocabulary-check without referencing the
    /// activation assembly. Keep in sync with the vendored library.
    ///
    /// Enforcement status (P3):
    ///   max_services              - enforced (EP0a provisioning, EP1 service start)
    ///   max_clients               - enforced (EP0b provisioning, EP2 enrollment)
    ///   max_concurrent_tunnels    - enforced (EP3 tunnel admission)
    ///   max_concurrent_sessions   - enforced (EP3 tunnel admission; in SSP one
    ///                               authenticated data-plane connection is both
    ///                               the session and the tunnel, so the two
    ///                               counters move together and the stricter of
    ///                               the two limits always wins)
    ///   max_sessions              - RESERVED, not enforced: it is a cumulative
    ///                               total, which SSP cannot measure offline
    ///                               across process restarts without persisting a
    ///                               per-license counter. Enforcing it against a
    ///                               per-process total would silently change its
    ///                               meaning, so it is left unconstrained rather
    ///                               than enforced incorrectly.
    /// </summary>
    public static class Limits
    {
        /// <summary>Maximum number of protected services on a machine.</summary>
        public const string MaxServices = "max_services";

        /// <summary>Maximum number of authorised clients per service.</summary>
        public const string MaxClients = "max_clients";

        /// <summary>Maximum total number of sessions (reserved seam; not enforced).</summary>
        public const string MaxSessions = "max_sessions";

        /// <summary>Maximum number of concurrently active sessions.</summary>
        public const string MaxConcurrentSessions = "max_concurrent_sessions";

        /// <summary>Maximum number of concurrently active tunnels.</summary>
        public const string MaxConcurrentTunnels = "max_concurrent_tunnels";
    }
}
