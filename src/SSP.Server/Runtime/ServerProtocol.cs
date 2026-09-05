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
// One instance per connection (ServerGateway creates a fresh one for every
// accepted socket), so the mutable state it holds - the license admission this
// connection reserved - belongs to exactly one connection. Instances must not be
// shared between connections.
//
// LICENSING (P3) - the authorized order is:
//
//     client connects
//         -> server challenge (ServerNonce + RSA signature)
//         -> client signature verification (OTT hash + client-nonce signature,
//            or fingerprint + challenge signature)
//         -> identity authorization (the presenter is a known/authorized client)
//         -> LICENSE authorization (ISspLicenseGate)          <-- here
//         -> session key accepted / tunnel becomes active
//
//   The license decision is taken AFTER identity authorization on purpose:
//   reserving a licensed slot (max_concurrent_tunnels /
//   max_concurrent_sessions) for an anonymous peer would let an
//   unauthenticated caller exhaust the license and deny service to real
//   clients. It is taken BEFORE the outcome is sent and before any session key
//   is accepted, so a denied connection can never become an active tunnel.
//
//   No licensing state is cached here: every decision is a live call into the
//   gate, which consults the LicenseManager under the manager's own lock, so a
//   Valid -> LockedDown transition denies the next connection immediately.

using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Protocol;
using SSP.Server.Activation;

namespace SSP.Server.Runtime;

public sealed class ServerProtocol : IDisposable
{
    private const int MaximumAuthenticationCodeAttempts = 3;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> EnrollmentLocks = new(StringComparer.OrdinalIgnoreCase);

    private readonly ServiceConfig _config;
    private readonly RSA _serverPrivateKey;
    private readonly string _serverPublicKeyPem;
    private readonly string _serviceDir;
    private readonly ISspLicenseGate _license;

    /// <summary>
    /// The license slot reserved for this connection, held until
    /// <see cref="TakeTunnelAdmission"/> transfers it to the gateway or
    /// <see cref="Dispose"/> releases it. Never both.
    /// </summary>
    private SspTunnelAdmission? _heldAdmission;

    /// <param name="license">
    /// The mandatory licensing gate for this service. Never null: a protected
    /// protocol handler without one would be a fail-open path.
    /// </param>
    public ServerProtocol(
        ServiceConfig config,
        RSA serverPrivateKey,
        string serverPublicKeyPem,
        string serviceDir,
        ISspLicenseGate license)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _serverPrivateKey = serverPrivateKey ?? throw new ArgumentNullException(nameof(serverPrivateKey));
        _serverPublicKeyPem = serverPublicKeyPem ?? throw new ArgumentNullException(nameof(serverPublicKeyPem));
        _serviceDir = serviceDir ?? throw new ArgumentNullException(nameof(serviceDir));
        _license = license ?? throw new ArgumentNullException(
            nameof(license),
            "A protected SSP protocol handler requires a licensing gate. Production callers obtain one " +
            "from SspRuntimeLicense.CreateForService; tests must pass an explicit gate.");
    }

    /// <summary>
    /// Transfers ownership of this connection's reserved license slot to the
    /// caller (the gateway, which releases it when the tunnel ends) and clears
    /// it here so <see cref="Dispose"/> cannot release it a second time.
    /// Returns null when no tunnel was authorized on this connection
    /// (enrollment-only sockets, and every denial).
    /// </summary>
    public SspTunnelAdmission? TakeTunnelAdmission()
    {
        var admission = _heldAdmission;
        _heldAdmission = null;
        return admission;
    }

    /// <summary>Releases any license slot still held by this connection.</summary>
    public void Dispose()
    {
        var admission = _heldAdmission;
        _heldAdmission = null;
        admission?.Dispose();
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

        // EP2 - max_clients. Enrolling a client grows .index.dat, which is the
        // authoritative count of licensed clients for this service, so this is
        // the exact point where the limit must be measured.
        //
        // Concurrency: the count is read inside the per-service enrollment
        // semaphore (taken in HandleEnrollmentAsync) and inside the
        // cross-process ServiceConfigFileLock region taken above, which is the
        // same pair of locks that guards every write to .index.dat. Two
        // concurrent enrollments therefore cannot both observe the same "one
        // client slot left" state - the check and the commit are serialized.
        //
        // Ordering is deliberate. The check runs AFTER the presenter has proven
        // possession of a valid One-Time Token and signed the client nonce, and
        // BEFORE the Authentication Code is generated, before anything is
        // written to disk and before the token is consumed. A licensing denial
        // therefore (a) never leaks the license state to a caller that has not
        // presented valid credentials, and (b) leaves the OTT intact so the
        // operator can retry once the license allows it.
        var reEnrollsExistingClient = users.Users.Any(u =>
            string.Equals(u.ClientPublicKeyFingerprint, fingerprint, StringComparison.Ordinal));

        // Usage is measured BEFORE the grant (the library's convention). A
        // re-enrollment of an already-authorized fingerprint replaces its entry
        // instead of growing the set, so it must not count against itself.
        var currentAuthorisedClients = reEnrollsExistingClient
            ? Math.Max(0, users.Users.Count - 1)
            : users.Users.Count;

        var clientDecision = _license.CanEnrollClient(currentAuthorisedClients);
        if (!clientDecision.IsAllowed)
        {
            await SendOutcomeAsync(stream, false, "enrollment not permitted", ct).ConfigureAwait(false);
            throw new UnauthorizedAccessException(
                $"License does not permit enrolling another client ({clientDecision.ReasonCode}).");
        }

        // Progressive cooldown (Phase 2): refuse to mint a new Authentication
        // Code until the per-OTT retry instant has elapsed. Checked after the
        // presenter has proven possession of this OTT and before any code is
        // generated or displayed, so a hammering client cannot obtain fresh
        // guesses and other pending OTTs are not delayed.
        var retryNotBeforeUtc = matchedPending?.AuthenticationCodeRetryNotBeforeUtc
            ?? (matchedLegacy ? config.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc : null);
        if (!AuthenticationCodeAbusePolicy.IsRetryAllowed(retryNotBeforeUtc, DateTimeOffset.UtcNow))
        {
            var failedAttempts = matchedPending?.FailedAuthenticationCodeAttempts
                ?? config.ActiveOneTimeTokenFailedAuthenticationCodeAttempts;
            ReportEnrollmentSecurityEvent("Enrollment.AuthenticationCodeRateLimited", failedAttempts);

            var rateLimited = new EnrollmentResultMessage
            {
                Success = false,
                ErrorOrWait = "verification failed",
            };
            await MessageWire.WriteAsync(stream, rateLimited, ct).ConfigureAwait(false);
            throw new UnauthorizedAccessException("AuthenticationCode retry is not yet allowed.");
        }

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
            var revoked = await RecordFailedAuthenticationCodeAttemptAsync(
                configPath,
                presentedHash,
                ct).ConfigureAwait(false);

            ReportEnrollmentSecurityEvent(
                "Enrollment.AuthenticationCodeFailed",
                revoked ? MaximumAuthenticationCodeAttempts : null);

            if (revoked)
            {
                ReportEnrollmentSecurityEvent(
                    "Enrollment.OTTRevokedAfterFailedAttempts",
                    MaximumAuthenticationCodeAttempts);
                await SendOutcomeAsync(stream, false, "enrollment permanently failed", ct).ConfigureAwait(false);
                throw new UnauthorizedAccessException(
                    "AuthenticationCode mismatch; the One-Time Token has been permanently revoked.");
            }

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
                    config.ActiveOneTimeTokenFailedAuthenticationCodeAttempts = 0;
                    config.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc = null;
                }
            }
            if (matchedLegacy)
            {
                config.ActiveOneTimeTokenHash = null;
                config.ActiveOneTimeTokenFailedAuthenticationCodeAttempts = 0;
                config.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc = null;
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

    /// <summary>
    /// Durably records a failed code submission against the matched OTT. The
    /// third failure removes every server-side authorization for that OTT, so
    /// all copies of the same client package are permanently unable to retry.
    /// The caller holds the per-service enrollment semaphore, while this method
    /// takes the cross-process configuration lock used by all OTT mutations.
    /// </summary>
    private async Task<bool> RecordFailedAuthenticationCodeAttemptAsync(
        string configPath,
        string presentedHash,
        CancellationToken ct)
    {
        using (await ServiceConfigFileLock.AcquireAsync(_serviceDir, ct).ConfigureAwait(false))
        {
            var current = await ServiceConfigStore.LoadAsync(configPath, ct).ConfigureAwait(false);
            current.PendingOneTimeTokens ??= new List<PendingOneTimeToken>();

            var pending = current.PendingOneTimeTokens.FirstOrDefault(p =>
                TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, presentedHash));

            int attempts;
            if (pending is not null)
            {
                pending.FailedAuthenticationCodeAttempts++;
                attempts = pending.FailedAuthenticationCodeAttempts;
            }
            else if (!string.IsNullOrEmpty(current.ActiveOneTimeTokenHash) &&
                     TokenGenerator.ConstantTimeEquals(current.ActiveOneTimeTokenHash, presentedHash))
            {
                current.ActiveOneTimeTokenFailedAuthenticationCodeAttempts++;
                attempts = current.ActiveOneTimeTokenFailedAuthenticationCodeAttempts;
            }
            else
            {
                // Another process has already consumed or revoked the OTT.
                // Treat it as permanently failed rather than recreating state.
                return true;
            }

            var retryAt = AuthenticationCodeAbusePolicy.NextRetryUtc(attempts, DateTimeOffset.UtcNow);
            if (pending is not null)
                pending.AuthenticationCodeRetryNotBeforeUtc = retryAt;
            if (!string.IsNullOrEmpty(current.ActiveOneTimeTokenHash) &&
                TokenGenerator.ConstantTimeEquals(current.ActiveOneTimeTokenHash, presentedHash))
            {
                current.ActiveOneTimeTokenFailedAuthenticationCodeAttempts = attempts;
                current.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc = retryAt;
            }

            var revoked = attempts >= MaximumAuthenticationCodeAttempts;
            if (revoked)
            {
                current.PendingOneTimeTokens.RemoveAll(p =>
                    TokenGenerator.ConstantTimeEquals(p.OneTimeTokenHash, presentedHash));

                if (!string.IsNullOrEmpty(current.ActiveOneTimeTokenHash) &&
                    TokenGenerator.ConstantTimeEquals(current.ActiveOneTimeTokenHash, presentedHash))
                {
                    current.ActiveOneTimeTokenHash = null;
                    current.ActiveOneTimeTokenFailedAuthenticationCodeAttempts = 0;
                    current.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc = null;
                }
            }

            await PersistConfigAsync(configPath, current, ct).ConfigureAwait(false);
            return revoked;
        }
    }

    private static void ReportEnrollmentSecurityEvent(string eventName, int? failedAttempts)
    {
        // Deliberately excludes the OTT, Authentication Code, public key, and
        // fingerprint. The stable event name is suitable for local collection
        // without placing enrollment credentials in logs.
        Console.Error.WriteLine(
            failedAttempts is int count
                ? $"[security] event={eventName} failedAttempts={count}"
                : $"[security] event={eventName}");
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

        // EP1 + EP2 + EP3 - the tunnel/session admission.
        //
        // The client is authenticated (its fingerprint is in .index.dat with
        // IsAuthorized, and its signature over THIS connection's server nonce
        // verified), so identity authorization has already succeeded. The
        // license must now independently permit the protected operation. The
        // gate reserves the max_concurrent_tunnels and
        // max_concurrent_sessions slots atomically with the decision, so two
        // connections racing for the last slot cannot both be admitted; the
        // reservation is held here and either adopted by the gateway
        // (TakeTunnelAdmission) or released by Dispose.
        //
        // Fail closed: on denial nothing is sent back that could be turned into
        // a session key, no slot is consumed, and the connection is refused.
        var admission = _license.AdmitTunnel();
        if (!admission.IsAdmitted)
        {
            admission.Dispose();
            await SendOutcomeAsync(
                stream,
                false,
                "server licensing does not permit this connection",
                ct).ConfigureAwait(false);
            throw new UnauthorizedAccessException(
                $"License does not permit tunnel establishment ({admission.ReasonCode}).");
        }

        // Exactly one admission per connection; a previous one would mean this
        // handler ran twice on the same instance, which the gateway never does.
        _heldAdmission?.Dispose();
        _heldAdmission = admission;

        await SendOutcomeAsync(stream, true, "You verified", ct);
        try
        {
            return await ReceiveSessionKeyAsync(stream, ct, allowEof: false)
                ?? throw new IOException("Client closed before sending SessionKeyOffer.");
        }
        catch
        {
            // The tunnel never became active, so give the licensed slot back
            // here rather than waiting for the gateway to notice.
            _heldAdmission?.Dispose();
            _heldAdmission = null;
            throw;
        }
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

        // EP3 - SINGLE CHOKE POINT for every path that can produce an active
        // protected tunnel.
        //
        // A session key is what turns an authenticated connection into a data
        // plane: ServerGateway bridges traffic as soon as HandleAsync returns a
        // non-empty key. Both handlers reach that point through this method, so
        // this is where the license admission has to be guaranteed:
        //
        //   • future authorization already holds an admission, taken before the
        //     AuthorizationOutcome was sent (see HandleFutureAuthorizationAsync),
        //     so it is not taken twice;
        //   • enrollment reaches here holding none. Without this check an
        //     enrollment socket that offers a session key (which is exactly what
        //     ClientProtocol.ConnectAndAuthenticateAsync does with
        //     establishSessionKey: true) would open a fully authenticated,
        //     fully encrypted tunnel with NO licensing decision at all - an
        //     alternate path around EP3.
        //
        // On denial the offer is refused with the protocol's own
        // SessionKeyAck(Accepted=false), which the client already handles as a
        // rejection, and no tunnel is created. Nothing is decrypted: the offer
        // is refused before the RSA-OAEP unwrap, so a denied connection cannot
        // even cause session-key material to be processed.
        if (_heldAdmission is null)
        {
            var admission = _license.AdmitTunnel();
            if (!admission.IsAdmitted)
            {
                admission.Dispose();
                await MessageWire.WriteAsync(
                    stream, new SessionKeyAckMessage { Accepted = false }, ct).ConfigureAwait(false);
                Console.Error.WriteLine(
                    $"[license] data-plane session denied ({admission.ReasonCode}); " +
                    "refusing the session key offer.");
                return null;
            }

            _heldAdmission = admission;
        }

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
