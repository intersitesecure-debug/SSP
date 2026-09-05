// File: src/SSP.Core/Models/ClientConfig.cs
//
// Schema for the configuration embedded into a patched client executable
// plus the two concepts that scope it correctly:
//
//   ConnectionIdentity     - deterministic "Server + Service" identity.
//   ClientConnectionState  - the per-connection profile persisted on the
//                            client (enrollment / authentication state).
//
// An SSP connection is identified by Server + Service, NEVER by the
// client name, never by the application name alone and never by the
// server alone. ServerA/RDP, ServerA/WEB, ServerB/RDP and ServerB/WEB
// are four different SSP identities even when the client is called
// "Client01" in all four cases.

using System.Security.Cryptography;
using System.Text.Json;
using SSP.Core.Crypto;
using SSP.Core.IO;

// CA1416 suppression (build-clean, platform-safe)
// ------------------------------------------------
// System.Security.Cryptography.DataProtectionScope is annotated
// [SupportedOSPlatform("windows")], so ANY reference to the type - even a
// pure enum member used as a scope MARKER in cross-platform code - is
// reported by the platform-compatibility analyzer as CA1416. The actual
// Windows-only APIs (ProtectedData.Protect / Unprotect) are never invoked
// off Windows: every call site is guarded by OperatingSystem.IsWindows()
// (see ProtectedFileStore.Protect / UnprotectWithWindowsDpapi, which throws
// PlatformNotSupportedException otherwise) and non-Windows hosts take the
// AES-GCM fallback. The enum reference itself carries no runtime dependency,
// so the diagnostic is a false positive here and is suppressed deliberately
// and locally rather than globally in the project file.
#pragma warning disable CA1416


namespace SSP.Core.Models;

/// <summary>
/// Configuration baked into a generated SSP.Client.&lt;ApplicationName&gt;.exe
/// at SETUP TIME. The patcher locates the PatchSlot inside the embedded
/// client template and replaces its placeholder content with the JSON
/// serialisation of this object.
///
/// One instance == one SSP connection (Server + Service).
/// </summary>
public sealed class ClientConfig
{
    /// <summary>Human-readable name of the protected application.</summary>
    public string ApplicationName { get; set; } = string.Empty;

    /// <summary>Server public key in PEM format. This key belongs to
    /// THIS connection only (services never share an RSA key pair).</summary>
    public string ServerPublicKeyPem { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 fingerprint (lowercase hex) of <see cref="ServerPublicKeyPem"/>.
    /// Written by SETUP MODE. Optional: when absent it is derived from
    /// the PEM, so older patched clients keep working unchanged.
    /// This is the cryptographically meaningful server identity used to
    /// scope the connection - not the IP address.
    /// </summary>
    public string ServerFingerprint { get; set; } = string.Empty;

    /// <summary>Gateway public IP address.</summary>
    public string GatewayPublicIpAddress { get; set; } = string.Empty;

    /// <summary>Gateway TCP port.</summary>
    public int GatewayPort { get; set; }

    /// <summary>Local application port on the server side.</summary>
    public int LocalApplicationPort { get; set; }

    /// <summary>Local TCP port the client listens on for tunnel traffic.</summary>
    public int ClientTunnelPort { get; set; }
    public bool AutoLaunchApplication { get; set; } = false;

    /// <summary>
    /// The One-Time Token issued by the server for THIS connection.
    /// Stored in plaintext on the client because it is single-use and the
    /// server only keeps a hash. The token is invalidated the moment
    /// enrollment of this connection succeeds.
    /// </summary>
    public string OneTimeToken { get; set; } = string.Empty;

    /// <summary>
    /// Friendly client name / label, e.g. Client01, Client02. The same
    /// client name MAY be reused across different connections; it is not
    /// the connection identity.
    /// </summary>
    public string ClientName { get; set; } = string.Empty;
}

/// <summary>
/// Deterministic identity of an SSP connection:
/// <c>Service/Application + Server</c>.
///
/// The server part prefers the SHA-256 fingerprint of the server public
/// key embedded in the connection (the protocol already authenticates
/// the server with that key). Only when no key is available does it fall
/// back to a hash of the gateway endpoint.
/// </summary>
public static class ConnectionIdentity
{
    /// <summary>Length of the server tag appended to the application name.</summary>
    public const int ServerTagLength = 16;

    /// <summary>
    /// SHA-256 fingerprint (lowercase hex) of the server public key of
    /// this connection, or an empty string when the connection carries
    /// no (parsable) server key.
    /// </summary>
    public static string ResolveServerFingerprint(ClientConfig? config)
    {
        if (config == null) return string.Empty;

        if (!string.IsNullOrWhiteSpace(config.ServerFingerprint))
            return config.ServerFingerprint.Trim().ToLowerInvariant();

        if (!string.IsNullOrWhiteSpace(config.ServerPublicKeyPem))
        {
            try { return RsaCrypto.ComputePublicKeyFingerprintFromPem(config.ServerPublicKeyPem); }
            catch { /* unparsable PEM: fall through to the endpoint tag */ }
        }

        return string.Empty;
    }

    /// <summary>
    /// Short, stable, filesystem-safe tag identifying the SERVER of this
    /// connection.
    /// </summary>
    public static string ServerTag(ClientConfig? config)
    {
        var fingerprint = ResolveServerFingerprint(config);
        if (fingerprint.Length >= ServerTagLength)
            return fingerprint[..ServerTagLength];

        // No server key: fall back to the endpoint so two different
        // servers still produce two different connection identities.
        var endpoint = $"{config?.GatewayPublicIpAddress}:{config?.GatewayPort}";
        return HashHex(endpoint, ServerTagLength);
    }

    /// <summary>
    /// Deterministic connection id: <c>{APPLICATION}-{serverTag}</c>.
    /// Stable across restarts and safe for filesystem/configuration use.
    /// </summary>
    public static string ConnectionId(ClientConfig? config)
    {
        var app = Sanitize(config?.ApplicationName).ToUpperInvariant();
        return $"{app}-{ServerTag(config)}";
    }

    /// <summary>True when both configs describe the same SSP connection.</summary>
    public static bool SameConnection(ClientConfig? a, ClientConfig? b) =>
        string.Equals(ConnectionId(a), ConnectionId(b), StringComparison.OrdinalIgnoreCase);

    /// <summary>Replace characters that are unsafe in a file name.</summary>
    public static string Sanitize(string? name)
    {
        var raw = string.IsNullOrWhiteSpace(name) ? "service" : name!.Trim();
        var chars = raw.ToCharArray();
        var invalid = Path.GetInvalidFileNameChars();
        for (var i = 0; i < chars.Length; i++)
        {
            if (Array.IndexOf(invalid, chars[i]) >= 0 || chars[i] is '/' or '\\')
                chars[i] = '_';
        }
        return new string(chars);
    }

    private static string HashHex(string value, int hexChars)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant()[..hexChars];
    }
}

/// <summary>
/// Per-connection profile persisted on the client, next to the RSA key
/// pair of that connection (<c>connections/{ConnectionId}/</c>).
///
/// This is what makes "am I enrolled?" a per Server + Service question
/// instead of a global one. A state file whose ConnectionId does not
/// match the connection currently being launched is never treated as an
/// enrollment for that connection.
/// </summary>
public sealed class ClientConnectionState
{
    public const string FileName = ".runtime.dat";

    public int Version { get; set; } = 1;

    /// <summary>Deterministic Server + Service identity.</summary>
    public string ConnectionId { get; set; } = string.Empty;

    /// <summary>Service / application identity.</summary>
    public string ApplicationName { get; set; } = string.Empty;

    /// <summary>Server identity (SHA-256 fingerprint of the server public key).</summary>
    public string ServerFingerprint { get; set; } = string.Empty;

    public string GatewayPublicIpAddress { get; set; } = string.Empty;
    public int GatewayPort { get; set; }
    public int LocalApplicationPort { get; set; }
    public int ClientTunnelPort { get; set; }

    /// <summary>Friendly client name (may repeat across connections).</summary>
    public string ClientName { get; set; } = string.Empty;

    /// <summary>Fingerprint of the client key pair used for THIS connection.</summary>
    public string ClientPublicKeyFingerprint { get; set; } = string.Empty;

    /// <summary>Enrollment completed for this connection.</summary>
    public bool IsEnrolled { get; set; }

    /// <summary>Server authorised this connection (AuthenticationCode validated).</summary>
    public bool IsAuthorized { get; set; }

    public string? EnrolledAtUtc { get; set; }

    public static string PathIn(string connectionDirectory) =>
        Path.Combine(connectionDirectory, FileName);

    /// <summary>
    /// Load the profile for a connection directory, or null when the
    /// file is absent, undecryptable or malformed.
    ///
    /// .runtime.dat is a protected-at-rest file: the read goes through
    /// the same ProtectedFileStore mechanism as the server-side state
    /// files, and a legacy plaintext profile is migrated into the
    /// encrypted envelope as a side effect of the read (the plaintext
    /// no longer remains on disk). The scope is CurrentUser (Phase 3 /
    /// M-2) because this profile belongs to the interactive client
    /// user: an undecryptable profile (another user's file, lost user
    /// profile, corruption) is reported as "no profile" by the caller
    /// and, for the key pair, fails closed at the PemStore layer before
    /// any enrollment decision is made.
    /// </summary>
    public static ClientConnectionState? TryLoad(
        string connectionDirectory,
        DataProtectionScope scope = ClientInstallPaths.ClientConnectionProtectionScope)
    {
        var path = PathIn(connectionDirectory);
        if (!File.Exists(path))
            return null;
        try
        {
            var read = ProtectedFileStore.ReadTextAsync(path, scope).GetAwaiter().GetResult();
            ProtectedFileStore.MigratePlaintextAsync(path, read, scope).GetAwaiter().GetResult();
            return JsonSerializer.Deserialize<ClientConnectionState>(
                read.Text, JsonOptions.Default);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Persist the profile. The JSON is written through
    /// ProtectedFileStore, so .runtime.dat always lands on disk as an
    /// encrypted envelope (never plaintext). The scope is CurrentUser
    /// (Phase 3 / M-2): the profile lives next to the client identity
    /// and is bound to the same interactive user as the key pair.
    /// </summary>
    public static Task SaveAsync(
        string connectionDirectory,
        ClientConnectionState state,
        DataProtectionScope scope = ClientInstallPaths.ClientConnectionProtectionScope,
        CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(state, JsonOptions.Default);
        return ProtectedFileStore.WriteTextAsync(PathIn(connectionDirectory), json, scope, ct);
    }

    /// <summary>Build the profile for a connection from its config.</summary>
    public static ClientConnectionState FromConfig(ClientConfig config) => new()
    {
        ConnectionId           = ConnectionIdentity.ConnectionId(config),
        ApplicationName        = config.ApplicationName,
        ServerFingerprint      = ConnectionIdentity.ResolveServerFingerprint(config),
        GatewayPublicIpAddress = config.GatewayPublicIpAddress,
        GatewayPort            = config.GatewayPort,
        LocalApplicationPort   = config.LocalApplicationPort,
        ClientTunnelPort       = config.ClientTunnelPort,
        ClientName             = config.ClientName,
    };

    /// <summary>
    /// True when this stored profile belongs to <paramref name="config"/>'s
    /// connection. Both the Server identity and the Service identity must
    /// match, so an old RDP profile can never be reinterpreted as a WEB
    /// profile and a ServerA profile can never satisfy ServerB.
    /// </summary>
    public bool Matches(ClientConfig config)
    {
        if (!string.Equals(ConnectionId, ConnectionIdentity.ConnectionId(config),
                StringComparison.OrdinalIgnoreCase))
            return false;

        var fingerprint = ConnectionIdentity.ResolveServerFingerprint(config);
        if (!string.IsNullOrEmpty(ServerFingerprint) && !string.IsNullOrEmpty(fingerprint) &&
            !string.Equals(ServerFingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }
}
#pragma warning restore CA1416
