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
    /// SSP host feature vocabulary. The licensing library validates feature
    /// name shape and normalization but not product semantics; these are the
    /// feature names SSP actually uses. Reserved for future enforcement seam
    /// wiring (not yet enforced).
    /// </summary>
    public static class Features
    {
        /// <summary>The Remote Desktop Protocol forwarding capability.</summary>
        public const string RemoteDesktopProtocol = "rdp";
    }

    /// <summary>
    /// SSP host limit vocabulary. The string values mirror
    /// <c>SSP.Activation.LicenseLimitNames</c>; they are duplicated here so
    /// SSP.Core can express/vocabulary-check without referencing the
    /// activation assembly. Keep in sync with the vendored library.
    /// </summary>
    public static class Limits
    {
        /// <summary>Maximum number of protected services on a machine.</summary>
        public const string MaxServices = "max_services";

        /// <summary>Maximum number of authorised clients per service.</summary>
        public const string MaxClients = "max_clients";

        /// <summary>Maximum total number of sessions (reserved seam).</summary>
        public const string MaxSessions = "max_sessions";

        /// <summary>Maximum number of concurrently active sessions (reserved seam).</summary>
        public const string MaxConcurrentSessions = "max_concurrent_sessions";

        /// <summary>Maximum number of concurrently active tunnels (reserved seam).</summary>
        public const string MaxConcurrentTunnels = "max_concurrent_tunnels";
    }
}
