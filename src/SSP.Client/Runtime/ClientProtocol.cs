// File: src/SSP.Client/Runtime/ClientProtocol.cs
//
// Client-side implementation of:
//   - Enrollment protocol (first connection; also EnsureEnrolledAsync)
//   - Future authorization protocol (subsequent connections)
//   - Session key establishment
//
// ConnectAndAuthenticateAsync returns an authenticated TcpClient with
// the AES-GCM session key already negotiated. EnsureEnrolledAsync is
// the startup-only enrollment path: it does not keep a data tunnel.

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SSP.Core.Crypto;
using SSP.Core.Models;
using SSP.Core.Protocol;

namespace SSP.Client.Runtime;

/// <summary>
/// User-facing enrollment failure. Program.Main prints only the
/// already-written console message — never a .NET stack trace.
/// </summary>
public sealed class EnrollmentFailedException : Exception
{
    public EnrollmentFailedException(string message) : base(message) { }
}

public sealed class ClientProtocol
{
    private readonly ClientRuntime _runtime;
    private readonly Func<Task<string>> _authenticationCodeReader;

    public ClientProtocol(ClientRuntime runtime, Func<Task<string>>? authenticationCodeReader = null)
    {
        _runtime = runtime;
        _authenticationCodeReader = authenticationCodeReader ?? (() => Task.FromResult(Console.ReadLine() ?? string.Empty));
    }

    /// <summary>
    /// Connect to the gateway and run whichever authentication flow
    /// applies: enrollment on the first connection, future authorization
    /// afterwards. Returns an authenticated TcpClient with the session
    /// key already negotiated.
    /// </summary>
    public async Task<(TcpClient tcp, byte[] sessionKey)> ConnectAndAuthenticateAsync(CancellationToken ct = default)
    {
        var host = GatewayHost(_runtime.Config);
        var port = _runtime.Config.GatewayPort;
        var tcp = CreateGatewayTcpClient(host);
        try
        {
            await ConnectToGatewayAsync(tcp, host, port, ct).ConfigureAwait(false);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }

        try
        {
            var stream = tcp.GetStream();

            byte[] sessionKey;
            if (_runtime.IsEnrolled)
            {
                sessionKey = await RunFutureAuthorizationAsync(stream, ct);
            }
            else
            {
                sessionKey = await RunEnrollmentAsync(stream, ct, establishSessionKey: true);
            }

            return (tcp, sessionKey);
        }
        catch
        {
            // Once the TCP connection has been established, authentication
            // failures must close the client side as well as relying on the
            // server to tear its handler down. Otherwise a failed enrollment or
            // authorization leaves a live client socket behind and obscures the
            // real admission lifecycle during retries and shutdown.
            tcp.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Complete enrollment (if needed) on a dedicated gateway connection
    /// that is then closed. The local tunnel listener must not be bound
    /// until this returns: the data plane is a later future-authorization
    /// connection opened only after a local application connects.
    /// </summary>
    public async Task EnsureEnrolledAsync(CancellationToken ct = default)
    {
        if (_runtime.IsEnrolled)
            return;

        var host = GatewayHost(_runtime.Config);
        var port = _runtime.Config.GatewayPort;

        Console.WriteLine("Connecting to server...");
        Console.WriteLine($"Enrollment required for connection {_runtime.ConnectionId} " +
                          $"({_runtime.Config.ApplicationName} @ {host}:{port}).");
        Console.WriteLine(
            "After the server accepts this connection's One-Time Token it displays a " +
            "10-digit Authentication Code for THIS connection (server console / that " +
            "service's Authcode.txt). Type it below when asked.");

        using var tcp = CreateGatewayTcpClient(host);
        try
        {
            await ConnectToGatewayAsync(tcp, host, port, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // The TCP connection to the gateway failed BEFORE any SSP
            // protocol message was exchanged (no ServerNonce, no
            // EnrollmentResult). This is a network-layer failure, not an
            // enrollment-state problem: the endpoint below is taken from
            // THIS connection's embedded configuration - it is exactly
            // the endpoint that was dialed and the same one printed at
            // startup. Fail cleanly (no stack trace, spec §14 UX) with an
            // actionable diagnosis instead of a raw SocketException.
            Console.WriteLine(GatewayUnreachableMessage(ex, host, port));
            Console.WriteLine("Enrollment failed.");
            throw new EnrollmentFailedException(
                $"Could not connect to the SSP gateway at {host}:{port}.");
        }
        var stream = tcp.GetStream();

        // Do not negotiate a session key on this socket. Enrollment is
        // identity provisioning; the AES-GCM tunnel is established later
        // when mstsc (or another local app) actually connects. Sending a
        // session key here would make the server connect to the protected
        // application with no client on the other end.
        await RunEnrollmentAsync(stream, ct, establishSessionKey: false);
        Console.WriteLine("Enrollment successful.");
    }

    /// <summary>
    /// Honest, actionable diagnostic for a gateway TCP-connect failure
    /// (e.g. SocketException 10060 timeout / 10061 refused). The failure
    /// happened before any protocol message, so the cause is between this
    /// machine and the server - most commonly an inbound firewall /
    /// port-forwarding rule that was never opened for this connection's
    /// gateway port (SSP setup never modifies the firewall). Never logs
    /// or prints any secret.
    /// </summary>
    private static string GatewayUnreachableMessage(Exception ex, string host, int port)
    {
        var detail = ex is SocketException se
            ? $"socket error {(int)se.SocketErrorCode} ({se.SocketErrorCode})"
            : ex.GetType().Name;

        return
            $"Could not connect to the SSP gateway at {host}:{port} ({detail})." + Environment.NewLine +
            "The TCP connect failed before any SSP protocol message was exchanged," + Environment.NewLine +
            "so this is a network problem, not an enrollment or authorization problem." + Environment.NewLine +
            $"If the server shows this service RUNNING and listening on {port}, the connection" + Environment.NewLine +
            "is usually dropped before it reaches the server by:" + Environment.NewLine +
            $"  - Windows Firewall on the server (no inbound rule for TCP {port}), or" + Environment.NewLine +
            "  - a router/NAT port-forwarding rule or cloud security group in front of it." + Environment.NewLine +
            $"Check from this machine : Test-NetConnection {host} -Port {port}" + Environment.NewLine +
            $"Open on the server (elevated): netsh advfirewall firewall add rule " +
            $"name=\"SSP Gateway {port}\" dir=in action=allow protocol=TCP localport={port}";
    }

    /// <summary>
    /// Gateway host of THIS connection only. Never falls back to another
    /// connection's address: an enrolled RDP endpoint must not be reused
    /// for a Web enrollment.
    /// </summary>
    internal static string GatewayHost(ClientConfig config) =>
        (config.GatewayPublicIpAddress ?? string.Empty).Trim();

    /// <summary>
    /// Build a TCP client whose address family matches an IP literal so
    /// dual-stack sockets cannot stall (10060) on an IPv4 gateway.
    /// </summary>
    internal static TcpClient CreateGatewayTcpClient(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
            return new TcpClient(ip.AddressFamily);
        return new TcpClient();
    }

    /// <summary>
    /// Dial THIS connection's gateway. IP literals are connected by
    /// <see cref="IPAddress"/> (no DNS) so the SYN goes to the embedded
    /// endpoint and nowhere else.
    /// </summary>
    internal static async Task ConnectToGatewayAsync(
        TcpClient tcp, string host, int port, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException("Gateway public IP address is missing from this connection's configuration.");
        if (port < 1 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "Gateway port is missing or out of range.");

        if (IPAddress.TryParse(host, out var ip))
            await tcp.ConnectAsync(ip, port, ct).ConfigureAwait(false);
        else
            await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Full enrollment flow:
    ///   Server sends ServerNonce + signature
    ///   Client verifies, generates its own ClientNonce, signs it,
    ///   sends EnrollmentBundle {pubkey, nonce, signature, OneTimeToken}
    ///   Server replies with EnrollmentResult {Success=true, ErrorOrWait="WAIT"}
    ///     -- the Authentication Code is NOT transmitted; the server
    ///     prints it on its own console and the human operator reads
    ///     it externally and types it into the client.
    ///   User enters AuthCode -> client sends it -> server finalizes.
    /// </summary>
    private async Task<byte[]> RunEnrollmentAsync(
        NetworkStream stream,
        CancellationToken ct,
        bool establishSessionKey)
    {
        // Step 1-3: receive ServerNonce + signature.
        var serverMsg = await MessageWire.ReadAsync(stream, ct)
            ?? throw new IOException("Server closed before sending ServerNonce.");
        if (serverMsg is not ServerNonceMessage sn)
            throw new InvalidDataException($"Expected ServerNonce, got {serverMsg.Type}.");

        var serverNonce = TokenGenerator.Base64UrlDecode(sn.ServerNonceB64);
        var serverNonceSig = Convert.FromBase64String(sn.ServerNonceSignatureB64);

        // Step 4: verify the signature using the embedded ServerPublicKey.
        using var serverRsa = RsaCrypto.ImportPublicKeyPem(_runtime.Config.ServerPublicKeyPem);
        if (!RsaCrypto.Verify(serverRsa, serverNonce, serverNonceSig))
            throw new CryptographicException("Server nonce signature verification failed.");

        // Step 5-7: build ClientNonce + EnrollmentBundle.
        var clientNonce = TokenGenerator.GenerateNonce(32);
        var clientNonceSig = RsaCrypto.Sign(_runtime.ClientPrivateKey, clientNonce);

        var bundle = new EnrollmentBundleMessage
        {
            ClientPublicKeyPem       = _runtime.ClientPublicKeyPem,
            ClientNonceB64           = TokenGenerator.Base64UrlEncode(clientNonce),
            ClientNonceSignatureB64  = Convert.ToBase64String(clientNonceSig),
            OneTimeToken             = _runtime.Config.OneTimeToken,
        };
        await MessageWire.WriteAsync(stream, bundle, ct);

        // Step 8-9: receive EnrollmentResult. Per spec §13 / §15 the
        // server DOES NOT transmit the Authentication Code to the client.
        // The server prints it on its own console; the human operator
        // must read it externally and type it into the client. The wire
        // message carries only Success=true with ErrorOrWait="WAIT".
        var resultMsg = await MessageWire.ReadAsync(stream, ct)
            ?? throw new IOException("Server closed before sending EnrollmentResult.");
        if (resultMsg is not EnrollmentResultMessage result)
            throw new InvalidDataException($"Expected EnrollmentResult, got {resultMsg.Type}.");
        if (!result.Success)
            throw new InvalidOperationException($"Enrollment rejected by server: {result.ErrorOrWait}");

        // Step 10: prompt the user for the AuthenticationCode. The user
        // obtains the code through the external channel (the server
        // administrator reads Authcode.txt). The client MUST NEVER
        // print the code itself and MUST NEVER read the server file.
        Console.Write("Enter Authentication Code: ");
        var userCode = (await _authenticationCodeReader()).Trim();
        if (string.IsNullOrEmpty(userCode))
        {
            Console.WriteLine("No Authentication Code entered.");
            Console.WriteLine("Enrollment failed.");
            throw new EnrollmentFailedException("No Authentication Code entered.");
        }

        // Step 11: send AuthenticationCode.
        var codeMsg = new AuthenticationCodeMessage { Code = userCode };
        await MessageWire.WriteAsync(stream, codeMsg, ct);

        // Step 12: receive final outcome.
        var outcomeMsg = await MessageWire.ReadAsync(stream, ct)
            ?? throw new IOException("Server closed before sending AuthorizationOutcome.");
        if (outcomeMsg is not AuthorizationOutcomeMessage outcome)
            throw new InvalidDataException($"Expected AuthorizationOutcome, got {outcomeMsg.Type}.");
        if (!outcome.Authorized)
            throw new UnauthorizedAccessException($"Enrollment failed: {outcome.Message}");

        Console.WriteLine("Enrollment completed successfully. You are now authorized.");

        // Mark this runtime as enrolled so that every SUBSEQUENT tunnel
        // connection in this same process uses the persistent-identity
        // (challenge/response) path instead of re-running enrollment with
        // the now-consumed One-Time Token.
        //
        // BUG FIX (spec §14 / §17 / §19 / §47): previously IsEnrolled was
        // never flipped to true after a successful first-run enrollment.
        // The client keys were persisted to disk during LoadOrCreateAsync,
        // so reloading them from disk re-derives the fingerprint and sets
        // IsEnrolled = true without generating any new identity.
        await _runtime.ReloadKeysAsync();

        if (!establishSessionKey)
            return Array.Empty<byte>();

        // Now establish the session key.
        return await EstablishSessionKeyAsync(stream, ct);
    }

    /// <summary>
    /// Future authorization flow:
    ///   Server sends ServerNonce + signature (the same first message
    ///   as in enrollment; the client interprets it as a challenge).
    ///   Client verifies, signs ServerNonce with its private key,
    ///   sends {fingerprint, signedChallenge}.
    ///   Server replies with AuthorizationOutcome.
    /// </summary>
    private async Task<byte[]> RunFutureAuthorizationAsync(NetworkStream stream, CancellationToken ct)
    {
        // The server always sends ServerNonce + signature first. In the
        // future-authorization flow we treat this nonce as the challenge.
        var snMsg = await MessageWire.ReadAsync(stream, ct)
            ?? throw new IOException("Server closed before sending ServerNonce.");
        if (snMsg is not ServerNonceMessage sn)
            throw new InvalidDataException($"Expected ServerNonce, got {snMsg.Type}.");

        var challenge = TokenGenerator.Base64UrlDecode(sn.ServerNonceB64);
        var challengeSig = Convert.FromBase64String(sn.ServerNonceSignatureB64);

        using var serverRsa = RsaCrypto.ImportPublicKeyPem(_runtime.Config.ServerPublicKeyPem);
        if (!RsaCrypto.Verify(serverRsa, challenge, challengeSig))
            throw new CryptographicException("Server nonce signature verification failed.");

        var signedChallenge = RsaCrypto.Sign(_runtime.ClientPrivateKey, challenge);

        var response = new ChallengeResponseMessage
        {
            ClientPublicKeyFingerprint = _runtime.ClientPublicKeyFingerprint,
            SignedChallengeB64         = Convert.ToBase64String(signedChallenge),
        };
        await MessageWire.WriteAsync(stream, response, ct);

        var outcomeMsg = await MessageWire.ReadAsync(stream, ct)
            ?? throw new IOException("Server closed before sending AuthorizationOutcome.");
        if (outcomeMsg is not AuthorizationOutcomeMessage outcome)
            throw new InvalidDataException($"Expected AuthorizationOutcome, got {outcomeMsg.Type}.");
        if (!outcome.Authorized)
            throw new UnauthorizedAccessException($"Authorization failed: {outcome.Message}");

        return await EstablishSessionKeyAsync(stream, ct);
    }

    /// <summary>
    /// Generate an AES-256 session key, wrap it with RSA-OAEP using the
    /// server's public key, send it, wait for ack.
    /// </summary>
    private async Task<byte[]> EstablishSessionKeyAsync(NetworkStream stream, CancellationToken ct)
    {
        var sessionKey = AesGcmCrypto.GenerateSessionKey();
        using var serverRsa = RsaCrypto.ImportPublicKeyPem(_runtime.Config.ServerPublicKeyPem);
        var wrapped = RsaCrypto.EncryptOaep(serverRsa, sessionKey);

        var offer = new SessionKeyOfferMessage
        {
            WrappedSessionKeyB64 = Convert.ToBase64String(wrapped),
        };
        await MessageWire.WriteAsync(stream, offer, ct);

        var ackMsg = await MessageWire.ReadAsync(stream, ct)
            ?? throw new IOException("Server closed before sending SessionKeyAck.");
        if (ackMsg is not SessionKeyAckMessage ack)
            throw new InvalidDataException($"Expected SessionKeyAck, got {ackMsg.Type}.");
        if (!ack.Accepted)
            throw new InvalidOperationException("Server rejected the session key offer.");

        return sessionKey;
    }
}
