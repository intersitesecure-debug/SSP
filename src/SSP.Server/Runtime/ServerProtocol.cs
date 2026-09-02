// File: src/SSP.Server/Runtime/ServerProtocol.cs
//
// Server-side handling of an incoming client connection.
//
//   1. Send ServerNonce + signature so the client can authenticate us.
//   2. Read the first client message and dispatch:
//        - EnrollmentBundleMessage : run enrollment flow
//        - ChallengeResponseMessage: run future-authorization flow
//   3. On success, accept a session key offer and start relaying.
//      After enrollment the client may close without a session key
//      (startup enrollment); that is a successful no-tunnel outcome.
//
// The class holds no per-connection state (every connection creates a
// fresh ServerProtocol) so it is safe to call from multiple threads.

using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Protocol;

namespace SSP.Server.Runtime;

public sealed class ServerProtocol
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> EnrollmentLocks = new(StringComparer.OrdinalIgnoreCase);

    private readonly ServiceConfig _config;
    private readonly RSA _serverPrivateKey;
    private readonly string _serverPublicKeyPem;
    private readonly string _serviceDir;
    private readonly ILicenseEnforcement? _enforcement;

    public ServerProtocol(ServiceConfig config, RSA serverPrivateKey, string serverPublicKeyPem, string serviceDir, ILicenseEnforcement? enforcement = null)
    {
        _config = config;
        _serverPrivateKey = serverPrivateKey;
        _serverPublicKeyPem = serverPublicKeyPem;
        _serviceDir = serviceDir;
        _enforcement = enforcement;
    }

    /// <summary>
    /// Handle a single client connection from accept to tunnel start.
    /// Returns the negotiated session key on success, or null when
    /// enrollment completed and the client closed without opening a
    /// data-plane session on this socket.
    /// </summary>
    public async Task<byte[]?> HandleAsync(TcpClient tcp, CancellationToken ct = default)
    {
        var stream = tcp.GetStream();

        // 1. Send ServerNonce + signature.
        var serverNonce = TokenGenerator.GenerateNonce(32);
        var serverNonceSig = RsaCrypto.Sign(_serverPrivateKey, serverNonce);

        var snMsg = new ServerNonceMessage
        {
            ServerNonceB64          = TokenGenerator.Base64UrlEncode(serverNonce),
            ServerNonceSignatureB64 = Convert.ToBase64String(serverNonceSig),
        };
        await MessageWire.WriteAsync(stream, snMsg, ct);

        // 2. Dispatch on the first client message.
        var firstMsg = await MessageWire.ReadAsync(stream, ct)
            ?? throw new IOException("Client closed before sending any message.");

        byte[]? sessionKey;
        switch (firstMsg)
        {
            case EnrollmentBundleMessage eb:
                sessionKey = await HandleEnrollmentAsync(stream, eb, ct);
                break;
            case ChallengeResponseMessage cr:
                sessionKey = await HandleFutureAuthorizationAsync(stream, cr, serverNonce, ct);
                break;
            default:
                throw new InvalidDataException($"Unexpected first message: {firstMsg.Type}.");
        }

        return sessionKey;
    }

    // ────────────────────────────────────────────────────────────────
    // Enrollment
    // ────────────────────────────────────────────────────────────────

    private async Task<byte[]?> HandleEnrollmentAsync(
        NetworkStream stream,
        EnrollmentBundleMessage bundle,
        CancellationToken ct)
    {
        var serviceKey = Path.GetFullPath(_serviceDir);
        var enrollmentLock = EnrollmentLocks.GetOrAdd(serviceKey, _ => new SemaphoreSlim(1, 1));

        await enrollmentLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await HandleEnrollmentLockedAsync(stream, bundle, ct).ConfigureAwait(false);
        }
        finally
        {
            enrollmentLock.Release();
        }
    }

    private async Task<byte[]?> HandleEnrollmentLockedAsync(
        NetworkStream stream,
        EnrollmentBundleMessage bundle,
        CancellationToken ct)
    {
        // Step 8: validate OneTimeToken hash + ClientNonceSignature.
        // Reload .cache.dat while holding the per-service enrollment
        // lock so a gateway that was already running before additional-client
        // provisioning sees the newly appended PendingOneTimeTokens entry, and
        // so matched-token consumption cannot race with another enrollment.
        var configPath = Path.Combine(_serviceDir, ".cache.dat");
        ServiceConfig config;
        using (await ServiceConfigFileLock.AcquireAsync(_serviceDir, ct).ConfigureAwait(false))
        {
            config = await ServiceConfigStore.LoadAsync(configPath, ct).ConfigureAwait(false);
            config.PendingOneTimeTokens ??= new List<PendingOneTimeToken>();
        }

        var authPath = Path.Combine(_serviceDir, config.AuthorisedUsersPath);
        var users = await AuthorisedUsersStore.LoadAsync(authPath, ct).ConfigureAwait(false);

        var presentedHash = TokenGenerator.HashOneTimeToken(bundle.OneTimeToken);

        PendingOneTimeToken? matchedPending = null;
        bool matchedLegacy = false;

        // Check pending list first (multi-client provisioning)
        foreach (var pending in config.PendingOneTimeTokens)
        {
            if (TokenGenerator.ConstantTimeEquals(presentedHash, pending.OneTimeTokenHash))
            {
                matchedPending = pending;
                break;
            }
        }

        // Fallback to legacy single-slot field for backward compatibility
        if (matchedPending == null && !string.IsNullOrEmpty(config.ActiveOneTimeTokenHash))
        {
            if (TokenGenerator.ConstantTimeEquals(presentedHash, config.ActiveOneTimeTokenHash!))
            {
                matchedLegacy = true;
            }
        }

        if (matchedPending == null && !matchedLegacy)
        {
            // Also check if there are no pending tokens at all -> legacy behavior message
            if (config.PendingOneTimeTokens.Count == 0 && string.IsNullOrEmpty(config.ActiveOneTimeTokenHash))
                throw new UnauthorizedAccessException("No active One-Time Token on this server.");

            throw new UnauthorizedAccessException("One-Time Token rejected.");
        }

        // Verify the client's signature over ClientNonce using the
        // presented ClientPublicKey (we have not stored it yet).
        using var clientRsa = RsaCrypto.ImportPublicKeyPem(bundle.ClientPublicKeyPem);
        var clientNonce = TokenGenerator.Base64UrlDecode(bundle.ClientNonceB64);
        var clientNonceSig = Convert.FromBase64String(bundle.ClientNonceSignatureB64);
        if (!RsaCrypto.Verify(clientRsa, clientNonce, clientNonceSig))
            throw new UnauthorizedAccessException("Client nonce signature verification failed.");

        // Compute the fingerprint early so we can display it on the
        // server console alongside the Authentication Code.
        var fingerprint = RsaCrypto.ComputePublicKeyFingerprint(clientRsa);

        // Step 9: generate the AuthenticationCode. Per spec §12 / §16 the
        // One-Time Token hash is invalidated ONLY after the enrollment has
        // fully completed (Authentication Code validated + client stored),
        // so a mistyped Authentication Code does not permanently burn the
        // token and brick the client. We therefore defer clearing
        // ActiveOneTimeTokenHash to the success path below.
        var authCode = TokenGenerator.GenerateAuthenticationCode();

        // Spec §13 / §15: the Authentication Code MUST be presented on
        // the SERVER side, NEVER transmitted to the client. The client
        // receives only "WAIT" - the human operator reads the code from
        // the server and enters it into the client through the intended
        // external channel.
        //
        // Desktop UI (WTSSendMessage / MessageBox) is not used. The
        // current administrator readout is Authcode.txt; the Console
        // banner is retained as a diagnostic fallback for --run-once /
        // non-Windows / CI (it is also what the in-process test harness
        // reads to drive enrollment).
        WriteAuthenticationCodeFile(authCode);

        Console.WriteLine();
        Console.WriteLine("=== CLIENT ENROLLMENT ===");
        Console.WriteLine();
        Console.WriteLine($"Client connected:");
        Console.WriteLine($"    {fingerprint}");
        Console.WriteLine();
        Console.WriteLine("Authentication Code:");
        Console.WriteLine();
        Console.WriteLine($"    {authCode}");
        Console.WriteLine();
        Console.WriteLine("Read this code to the client operator.");
        Console.WriteLine("Waiting for client confirmation...");
        Console.WriteLine();

        var result = new EnrollmentResultMessage
        {
            Success = true,
            ErrorOrWait = "WAIT", // No code transmitted - see spec §13
        };
        await MessageWire.WriteAsync(stream, result, ct).ConfigureAwait(false);

        // Step 11-12: receive user-entered code and validate.
        var codeMsg = await MessageWire.ReadAsync(stream, ct).ConfigureAwait(false)
            ?? throw new IOException("Client closed before sending AuthenticationCode.");
        if (codeMsg is not AuthenticationCodeMessage acm)
            throw new InvalidDataException($"Expected AuthenticationCode, got {codeMsg.Type}.");

        if (!TokenGenerator.ConstantTimeEquals(acm.Code, authCode))
        {
            await SendOutcomeAsync(stream, false, "verification failed", ct).ConfigureAwait(false);
            throw new UnauthorizedAccessException("AuthenticationCode mismatch.");
        }

        // Step 12 success: store the client as authorized.
        users.Users.RemoveAll(u => u.ClientPublicKeyFingerprint == fingerprint);
        var label = matchedPending?.ClientName;
        if (string.IsNullOrWhiteSpace(label) && matchedLegacy)
            label = "Legacy";

        users.Users.Add(new AuthorisedUser
        {
            ClientPublicKeyPem       = bundle.ClientPublicKeyPem,
            ClientPublicKeyFingerprint = fingerprint,
            IsAuthorized             = true,
            EnrolledAtUtc            = DateTime.UtcNow.ToString("o"),
            Label                    = string.IsNullOrWhiteSpace(label) ? null : label,
        });
        await AuthorisedUsersStore.SaveAsync(authPath, users, ct).ConfigureAwait(false);

        // Additional-client provisioning can append new pending OTTs while
        // this enrollment is waiting for the human Authentication Code. Take
        // the cross-process config lock and reload immediately before
        // consuming this token so persisting the updated config cannot
        // overwrite those newly provisioned entries.
        using (await ServiceConfigFileLock.AcquireAsync(_serviceDir, ct).ConfigureAwait(false))
        {
            config = await ServiceConfigStore.LoadAsync(configPath, ct).ConfigureAwait(false);
            config.PendingOneTimeTokens ??= new List<PendingOneTimeToken>();

            // Enrollment completed: now (and only now) invalidate the
            // One-Time Token hash permanently (spec §12 / §16). The token can
            // never be used again; a mistyped Authentication Code above would
            // have thrown before reaching this point, leaving the token intact
            // so the operator can retry without re-provisioning the client.
            // Multi-client: consume ONLY the matched pending entry, not all.
            if (matchedPending != null)
            {
                config.PendingOneTimeTokens.RemoveAll(p =>
                    TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, matchedPending.OneTimeTokenHash));
                // If legacy hash equals the consumed pending hash, clear legacy as well
                if (!string.IsNullOrEmpty(config.ActiveOneTimeTokenHash) &&
                    TokenGenerator.ConstantTimeEquals(config.ActiveOneTimeTokenHash!, matchedPending.OneTimeTokenHash))
                {
                    config.ActiveOneTimeTokenHash = null;
                }
            }
            if (matchedLegacy)
            {
                config.ActiveOneTimeTokenHash = null;
                // Also remove any pending entry that might have same hash (first client created with both fields)
                if (!string.IsNullOrEmpty(presentedHash))
                {
                    config.PendingOneTimeTokens.RemoveAll(p =>
                        TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, presentedHash));
                }
            }
            await PersistConfigAsync(configPath, config, ct).ConfigureAwait(false);
        }

        await SendOutcomeAsync(stream, true, "You verified", ct).ConfigureAwait(false);

        // Enrollment is fully committed. The production client then
        // closes this socket and binds its local listener; the data
        // tunnel is a later future-authorization connection. A clean
        // EOF here is success, not a protocol error — do not connect
        // to the protected application on an enrollment-only socket.
        return await ReceiveSessionKeyAsync(stream, ct, allowEof: true).ConfigureAwait(false);
    }


    /// <summary>
    /// Write the current Authentication Code to the administrator
    /// readout file. A write failure is logged and must not change
    /// enrollment protocol behaviour.
    /// </summary>
    private static void WriteAuthenticationCodeFile(string authenticationCode)
    {
        try
        {
            AuthenticationCodeFile.Write(authenticationCode);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[authcode-file] Failed to write {AuthenticationCodeFile.ResolvePath()}: {ex.Message}");
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Future authorization
    // ────────────────────────────────────────────────────────────────

    private async Task<byte[]> HandleFutureAuthorizationAsync(
        NetworkStream stream,
        ChallengeResponseMessage cr,
        byte[] originalNonce,
        CancellationToken ct)
    {
        var authPath = Path.Combine(_serviceDir, _config.AuthorisedUsersPath);
        var users = await AuthorisedUsersStore.LoadAsync(authPath, ct);

        var user = users.Users.FirstOrDefault(u =>
            u.ClientPublicKeyFingerprint == cr.ClientPublicKeyFingerprint
            && u.IsAuthorized);
        if (user == null)
        {
            await SendOutcomeAsync(stream, false, "verification failed", ct);
            throw new UnauthorizedAccessException($"Unknown fingerprint {cr.ClientPublicKeyFingerprint}.");
        }

        using var clientRsa = RsaCrypto.ImportPublicKeyPem(user.ClientPublicKeyPem);
        var sig = Convert.FromBase64String(cr.SignedChallengeB64);
        if (!RsaCrypto.Verify(clientRsa, originalNonce, sig))
        {
            await SendOutcomeAsync(stream, false, "verification failed", ct);
            throw new UnauthorizedAccessException("Challenge signature verification failed.");
        }

        // EP3 — Tunnel establishment license gate:
        // The client has been authenticated (fingerprint + challenge signature),
        // but the license must also permit tunnel establishment.
        // Fail closed: if the enforcement policy denies, do not establish the tunnel.
        if (_enforcement is not null && !_enforcement.CanEstablishTunnel(0).IsAllowed)
        {
            await SendOutcomeAsync(stream, false, "License does not permit tunnel establishment", ct);
            throw new UnauthorizedAccessException("License does not permit tunnel establishment.");
        }

        await SendOutcomeAsync(stream, true, "You verified", ct);
        return await ReceiveSessionKeyAsync(stream, ct, allowEof: false)
            ?? throw new IOException("Client closed before sending SessionKeyOffer.");
    }

    // ────────────────────────────────────────────────────────────────
    // Session key
    // ────────────────────────────────────────────────────────────────

    private async Task<byte[]?> ReceiveSessionKeyAsync(
        NetworkStream stream,
        CancellationToken ct,
        bool allowEof)
    {
        var msg = await MessageWire.ReadAsync(stream, ct);
        if (msg == null)
        {
            if (allowEof)
                return null;
            throw new IOException("Client closed before sending SessionKeyOffer.");
        }
        if (msg is not SessionKeyOfferMessage offer)
            throw new InvalidDataException($"Expected SessionKeyOffer, got {msg.Type}.");

        var wrapped = Convert.FromBase64String(offer.WrappedSessionKeyB64);
        var sessionKey = RsaCrypto.DecryptOaep(_serverPrivateKey, wrapped);

        var ack = new SessionKeyAckMessage { Accepted = true };
        await MessageWire.WriteAsync(stream, ack, ct);
        return sessionKey;
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────

    private async Task SendOutcomeAsync(NetworkStream stream, bool ok, string msg, CancellationToken ct)
    {
        var outcome = new AuthorizationOutcomeMessage { Authorized = ok, Message = msg };
        await MessageWire.WriteAsync(stream, outcome, ct);
    }

    private static async Task PersistConfigAsync(string configPath, ServiceConfig config, CancellationToken ct)
    {
        await ServiceConfigStore.SaveAsync(configPath, config, ct).ConfigureAwait(false);
    }
}
