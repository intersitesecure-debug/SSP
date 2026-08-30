// File: src/SSP.Core/Models/ServiceConfig.cs
//
// .cache.dat schema. One instance per protected application,
// stored at the root of the service directory.

using System.Text.Json.Serialization;

namespace SSP.Core.Models;

/// <summary>
/// Persisted configuration for a single SSP gateway service.
/// Loaded by the server in SERVICE MODE.
/// </summary>
public sealed class ServiceConfig
{
    /// <summary>Human-readable application name, e.g. "RDP", "WEB", "SSH".</summary>
    public string ApplicationName { get; set; } = string.Empty;

    /// <summary>Public IP address clients use to reach the gateway.</summary>
    public string GatewayPublicIpAddress { get; set; } = string.Empty;

    /// <summary>TCP port the gateway listens on (0.0.0.0:GatewayPort).</summary>
    public int GatewayPort { get; set; }

    /// <summary>TCP port of the local protected application (127.0.0.1).</summary>
    public int LocalApplicationPort { get; set; }

    /// <summary>TCP port the client listens on locally for tunnel traffic.</summary>
    public int ClientTunnelPort { get; set; }

    /// <summary>
    /// Path to the server private key PEM file (relative to service dir).
    /// </summary>
    public string ServerPrivateKeyPath { get; set; } = ".sysdata.bin";

    /// <summary>
    /// Path to the server public key PEM file (relative to service dir).
    /// </summary>
    public string ServerPublicKeyPath { get; set; } = ".runtime.dat";

    /// <summary>
    /// Path to the authorised users JSON file (relative to service dir).
    /// </summary>
    public string AuthorisedUsersPath { get; set; } = ".index.dat";

    /// <summary>
    /// SHA-256 hash (hex) of the currently active One-Time Token. Set
    /// during SETUP MODE, cleared (set to null) as soon as a client
    /// successfully completes enrollment.
    /// Legacy single-slot field kept for backward compatibility.
    /// New installations should use <see cref="PendingOneTimeTokens"/>.
    /// </summary>
    public string? ActiveOneTimeTokenHash { get; set; }

    /// <summary>
    /// Collection of pending One-Time Tokens for multi-client provisioning.
    /// Each entry stores the hash and the intended client name.
    /// Supports concurrent pending enrollments: Client02, Client03, etc.
    /// </summary>
    public List<PendingOneTimeToken> PendingOneTimeTokens { get; set; } = new();

    /// <summary>
    /// ISO-8601 timestamp at which the service was created.
    /// </summary>
    public string CreatedAtUtc { get; set; } = string.Empty;

    /// <summary>
    /// Optional Windows Service name (filled in by ServiceBuilder).
    /// </summary>
    public string? WindowsServiceName { get; set; }
}

/// <summary>
/// Pending OTT record for multi-client provisioning.
/// Stores only the hash, never plaintext, plus client label.
/// </summary>
public sealed class PendingOneTimeToken
{
    /// <summary>Friendly client name, e.g. Client01, Client02.</summary>
    public string ClientName { get; set; } = string.Empty;

    /// <summary>SHA-256 hash (hex) of the OTT.</summary>
    public string OneTimeTokenHash { get; set; } = string.Empty;

    /// <summary>ISO-8601 creation timestamp.</summary>
    public string CreatedAtUtc { get; set; } = string.Empty;
}

/// <summary>
/// Record stored in .index.dat for every enrolled client.
/// </summary>
public sealed class AuthorisedUser
{
    /// <summary>SHA-256 fingerprint of the client's public key (lowercase hex).</summary>
    public string ClientPublicKeyFingerprint { get; set; } = string.Empty;

    /// <summary>Client's RSA public key in PEM format.</summary>
    public string ClientPublicKeyPem { get; set; } = string.Empty;

    /// <summary>
    /// True once the enrollment has been fully completed (AuthenticationCode
    /// validated). Until this is true the client cannot use the future
    /// authorization path.
    /// </summary>
    public bool IsAuthorized { get; set; }

    /// <summary>ISO-8601 enrollment timestamp (UTC).</summary>
    public string EnrolledAtUtc { get; set; } = string.Empty;

    /// <summary>Optional friendly label assigned by the administrator.</summary>
    public string? Label { get; set; }
}

/// <summary>
/// Root object serialised to .index.dat. We use a wrapper
/// rather than a top-level array so future schema versions can add
/// metadata without breaking deserialization.
/// </summary>
public sealed class AuthorisedUsersFile
{
    public int Version { get; set; } = 1;

    public List<AuthorisedUser> Users { get; set; } = new();
}
