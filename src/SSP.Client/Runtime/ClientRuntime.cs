// File: src/SSP.Client/Runtime/ClientRuntime.cs
//
// Persistent state of ONE SSP connection (Server + Service):
//   * the ClientConfig of that connection,
//   * the RSA key pair used for that connection,
//   * the persisted connection profile (.runtime.dat) holding
//     the enrollment / authorization state of that connection.
//
// Everything lives in the connection directory
// (connections/{ConnectionId}/), so ServerA/RDP, ServerA/WEB and
// ServerB/WEB never share identity or enrollment state even when the
// client is called "Client01" in all three cases.
//
// All three files (.cache.dat, .index.dat, .runtime.dat) are protected
// at rest through the same ProtectedFileStore mechanism the server-side
// service files use: they are always written as an encrypted envelope
// and decrypted transparently on read. Legacy plaintext files (from the
// pre-encryption layout) are migrated into the envelope on first read,
// replacing the plaintext in place.
//
// The SCOPE differs from the server-side files (Phase 3 / M-2): the
// client files use DPAPI CurrentUser scope
// (ClientInstallPaths.ClientConnectionProtectionScope), because the
// client is a desktop app whose identity is created and used by the
// same interactive user only. Every other local account on the machine
// can read the file bytes (C:\Program Files is world-readable) but
// cannot decrypt them; a file whose owner can no longer decrypt it
// fails closed instead of regenerating the identity.

using System.Security.Cryptography;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;

namespace SSP.Client.Runtime;

/// <summary>
/// Aggregates everything a running client connection needs: the config
/// (read from the patch slot / client_services.json at startup), the
/// persistent key pair and the persisted connection profile.
/// </summary>
public sealed class ClientRuntime
{
    public ClientConfig Config { get; init; } = new();
    public RSA ClientPrivateKey { get; private set; } = RSA.Create();
    public string ClientPublicKeyPem { get; private set; } = string.Empty;
    public string ClientPublicKeyFingerprint { get; private set; } = string.Empty;

    public string PrivateKeyPath { get; init; } = ".cache.dat";
    public string PublicKeyPath  { get; init; } = ".index.dat";

    /// <summary>Directory holding this connection's identity and state.</summary>
    public string ConnectionDirectory { get; init; } = string.Empty;

    /// <summary>Deterministic Server + Service identity of this connection.</summary>
    public string ConnectionId => ConnectionIdentity.ConnectionId(Config);

    /// <summary>
    /// True if THIS connection (Server + Service) has completed
    /// enrollment. Never a global "is this client enrolled" answer.
    /// </summary>
    public bool IsEnrolled { get; private set; }

    /// <summary>
    /// True when the connection directory already holds the profile of a
    /// DIFFERENT connection (a copied installation). We refuse to treat
    /// it as enrolled and we refuse to overwrite the foreign profile.
    /// </summary>
    private bool _foreignState;

    public static async Task<ClientRuntime> LoadOrCreateAsync(string baseDir, ClientConfig config)
    {
        var runtime = new ClientRuntime
        {
            Config              = config,
            ConnectionDirectory = baseDir,
            PrivateKeyPath      = Path.Combine(baseDir, ".cache.dat"),
            PublicKeyPath       = Path.Combine(baseDir, ".index.dat"),
        };

        var hasPrivate = File.Exists(runtime.PrivateKeyPath);
        var hasPublic  = File.Exists(runtime.PublicKeyPath);

        if (hasPrivate && hasPublic)
        {
            // Existing identity: load it. If the private key is corrupt,
            // ImportPrivateKeyPem throws and the error propagates to the
            // caller — the client reports that its local identity
            // credential is unavailable (spec §19) rather than silently
            // generating a replacement identity.
            //
            // .cache.dat / .index.dat are protected-at-rest files: PemStore
            // transparently decrypts them via the same ProtectedFileStore
            // mechanism the server-side key files use, and migrates a
            // legacy plaintext file into the encrypted envelope on load.
            // The scope is CurrentUser (Phase 3 / M-2): the client identity
            // is bound to the user who created it, so no other local
            // account can recover the private key even though the file
            // itself is world-readable inside C:\Program Files.
            var privPem = await PemStore.LoadPrivateKeyAsync(
                runtime.PrivateKeyPath,
                ClientInstallPaths.ClientConnectionProtectionScope);
            runtime.ClientPrivateKey = RsaCrypto.ImportPrivateKeyPem(privPem);
            runtime.ClientPublicKeyPem = await PemStore.LoadPublicKeyAsync(
                runtime.PublicKeyPath,
                ClientInstallPaths.ClientConnectionProtectionScope);

            // Per-connection enrollment state. When a profile exists it is
            // authoritative AND it must belong to this exact connection:
            // a profile copied from another Server/Service can never make
            // this connection look enrolled.
            var state = ClientConnectionState.TryLoad(baseDir);
            if (state == null)
            {
                runtime.IsEnrolled = true;                  // legacy layout: keys == enrolled
            }
            else if (state.Matches(config))
            {
                runtime.IsEnrolled = state.IsEnrolled;
            }
            else
            {
                // The directory holds the profile of a DIFFERENT connection
                // (for example RDP keys copied into a Web folder). That
                // profile must never make THIS connection look enrolled.
                runtime.IsEnrolled = false;
                runtime._foreignState = true;
            }
        }
        else if (!hasPrivate && !hasPublic)
        {
            // Genuine first run for this connection: generate an identity
            // that belongs to this connection only.
            runtime.ClientPrivateKey = RsaCrypto.GenerateKeyPair();
            runtime.ClientPublicKeyPem = RsaCrypto.ExportPublicKeyPem(runtime.ClientPrivateKey);
            // Encrypted at rest: .cache.dat / .index.dat are on
            // ProtectedFileStore's protected-name list, so PemStore routes
            // these saves through the same encrypted-at-rest envelope the
            // server-side key files use. The PEM never reaches disk in
            // plaintext, and the read paths above decrypt transparently.
            // CurrentUser scope: the identity belongs to this interactive
            // user and must stay unreadable to every other account on the
            // machine (Phase 3 / M-2).
            await PemStore.SavePrivateKeyAsync(runtime.PrivateKeyPath,
                RsaCrypto.ExportPrivateKeyPem(runtime.ClientPrivateKey),
                ClientInstallPaths.ClientConnectionProtectionScope);
            await PemStore.SavePublicKeyAsync(runtime.PublicKeyPath, runtime.ClientPublicKeyPem,
                ClientInstallPaths.ClientConnectionProtectionScope);
            runtime.IsEnrolled = false;
        }
        else
        {
            // Only one of the two key files exists: the local identity
            // credential is incomplete/corrupted. Spec §19 mandates that
            // we MUST NOT silently generate a new identity and overwrite
            // the surviving credential. Report it and require explicit
            // re-provisioning instead.
            throw new InvalidDataException(
                "Client identity credential is incomplete or corrupted: " +
                $"{(hasPrivate ? "private key present but public key missing" : "public key present but private key missing")}. " +
                "Re-provision this client (delete both key files or re-run setup) rather than silently replacing its identity.");
        }

        runtime.ClientPublicKeyFingerprint = RsaCrypto.ComputePublicKeyFingerprint(runtime.ClientPrivateKey);

        if (!runtime.IsEnrolled)
            await runtime.SaveStateAsync(enrolled: false);

        return runtime;
    }

    /// <summary>
    /// Reload the key pair from disk after a successful enrollment and
    /// persist the enrollment state of THIS connection.
    /// </summary>
    public async Task ReloadKeysAsync()
    {
        // Encrypted-at-rest read (transparent decryption + legacy
        // plaintext migration, CurrentUser scope), same mechanism as the
        // initial load.
        var privPem = await PemStore.LoadPrivateKeyAsync(
            PrivateKeyPath,
            ClientInstallPaths.ClientConnectionProtectionScope);
        ClientPrivateKey = RsaCrypto.ImportPrivateKeyPem(privPem);
        ClientPublicKeyPem = await PemStore.LoadPublicKeyAsync(
            PublicKeyPath,
            ClientInstallPaths.ClientConnectionProtectionScope);
        ClientPublicKeyFingerprint = RsaCrypto.ComputePublicKeyFingerprint(ClientPrivateKey);
        IsEnrolled = true;
        await SaveStateAsync(enrolled: true);
    }

    /// <summary>Persist the connection profile (best effort).</summary>
    private async Task SaveStateAsync(bool enrolled)
    {
        if (string.IsNullOrEmpty(ConnectionDirectory) || _foreignState)
            return;

        try
        {
            var state = ClientConnectionState.FromConfig(Config);
            state.ClientPublicKeyFingerprint = ClientPublicKeyFingerprint;
            state.IsEnrolled = enrolled;
            state.IsAuthorized = enrolled;
            state.EnrolledAtUtc = enrolled ? DateTime.UtcNow.ToString("o") : null;
            await ClientConnectionState.SaveAsync(ConnectionDirectory, state);
        }
        catch
        {
            // The profile is a convenience/scoping record; a write failure
            // must not break an otherwise working connection.
        }
    }

}
