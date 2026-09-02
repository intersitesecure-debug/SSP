// File: src/SSP.Server/Runtime/ServerGateway.cs
//
// Gateway runtime used in SERVICE MODE. Listens on 0.0.0.0:GatewayPort,
// one ServerProtocol per accepted connection, bridges the decrypted
// tunnel to 127.0.0.1:LocalApplicationPort.

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Protocol;

namespace SSP.Server.Runtime;

public sealed class ServerGateway : IAsyncDisposable
{
    private readonly ServiceConfig _config;
    private readonly string _serviceDir;
    private readonly RSA _serverPrivateKey;
    private readonly string _serverPublicKeyPem;
    private readonly ILicenseEnforcement? _enforcement;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    /// <summary>
    /// Set as soon as the TCP listener has been bound and is accepting
    /// connections. Used by the Windows Service host (SspWindowsService)
    /// to delay the return of OnStart until the gateway is ready, so
    /// the SCM does not report ERROR 1053 ("service did not respond in
    /// a timely fashion") on Windows Server 2022.
    ///
    /// The TaskCompletionSource is created with
    /// RunContinuationsAsynchronously so that a synchronous caller
    /// inside AcceptLoopAsync cannot accidentally run the continuation
    /// on the listener thread.
    /// </summary>
    private readonly TaskCompletionSource _listenerReady =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Exposed so the Windows Service host can await listener readiness.
    /// </summary>
    public Task ListenerReady => _listenerReady.Task;

    public ServerGateway(ServiceConfig config, RSA serverPrivateKey, string serverPublicKeyPem, string serviceDir, ILicenseEnforcement? enforcement = null)
    {
        _config = config;
        _serverPrivateKey = serverPrivateKey;
        _serverPublicKeyPem = serverPublicKeyPem;
        _serviceDir = serviceDir;
        _enforcement = enforcement;
        if (enforcement is not null && !enforcement.CanStartProtectedService(0).IsAllowed)
        {
            // Enforcement denied even before any client connects — this can happen when
            // the license state transitions to LockedDown after initial startup but before
            // the gateway accepts its first connection. Log and remain non-operational
            // until the license state recoverS (or the process restarts with a valid license).
            Console.Error.WriteLine($"[gateway] License enforcement denied protected service start: {enforcement.CanStartProtectedService(0).ReasonCode}");
        }
    }

    /// <summary>
    /// Run the accept loop. Optionally accepts a caller-supplied
    /// TaskCompletionSource that is signaled as soon as the listener
    /// is bound. The caller (Windows Service host) uses this to delay
    /// reporting "started" to the SCM until the socket is ready.
    /// </summary>
    public Task RunAsync(CancellationToken externalToken, TaskCompletionSource? readySignal = null)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
        return AcceptLoopAsync(_cts.Token, readySignal ?? _listenerReady);
    }

    private async Task AcceptLoopAsync(CancellationToken ct, TaskCompletionSource readySignal)
    {
        try
        {
            _listener = new TcpListener(IPAddress.Any, _config.GatewayPort);
            _listener.Start();

            // Signal readiness BEFORE the first accept call. This lets
            // the Windows Service host return from OnStart as soon as
            // the socket is bound, without waiting for a client.
            readySignal.TrySetResult();

            Console.WriteLine($"[gateway] listening on 0.0.0.0:{_config.GatewayPort} -> 127.0.0.1:{_config.LocalApplicationPort}");

            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(ct); }
                catch (OperationCanceledException) { break; }

                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
        }
        catch (Exception ex)
        {
            // Make sure the caller does not hang waiting for readiness.
            readySignal.TrySetException(ex);
            throw;
        }
        finally
        {
            try { _listener?.Stop(); } catch { /* best effort */ }
        }
    }

    private async Task HandleClientAsync(TcpClient tcp, CancellationToken ct)
    {
        try
        {
            // EP0 — License bootstrap / startup gate:
            // Ensure licensing is initialized before protected functionality becomes available.
            // Fail closed: if enforcement is configured and the license state does not permit
            // protected services, deny the connection rather than silently proceeding.
            if (_enforcement is not null && !_enforcement.CanStartProtectedService(1).IsAllowed)
            {
                Console.Error.WriteLine($"[gateway] Protected operation denied (license state not valid); closing connection.");
                tcp.Close();
                return;
            }

            var protocol = new ServerProtocol(_config, _serverPrivateKey, _serverPublicKeyPem, _serviceDir);
            var sessionKey = await protocol.HandleAsync(tcp, ct);
            if (sessionKey is not { Length: > 0 })
                return;
            using var codec = new TunnelCodec(sessionKey);

            // Connect to the local protected application. We connect
            // eagerly (not lazily) because some protected applications
            // (including RDP's X.224 layer in some configurations, and
            // many SSH/HTTP server implementations) push an initial
            // handshake to the client BEFORE waiting for client input.
            // Lazy connect would break that "server speaks first" pattern.
            //
            // The RDP "Connecting..." hang scenario documented by
            // TunnelInactivityTests is handled correctly by the existing
            // BridgeAsync: when the local app times out and closes,
            // BridgeAsync closes both streams, the tunnel TCP closes,
            // and the client's mstsc gets immediate feedback (EOF or
            // IOException) when it finally connects - rather than
            // hanging forever, which was the original bug.
            var localClient = new TcpClient();
            await localClient.ConnectAsync(IPAddress.Loopback, _config.LocalApplicationPort, ct);
            await using var localStream = localClient.GetStream();
            var remoteStream = tcp.GetStream();

            Console.WriteLine($"[tunnel] authenticated, bridging to 127.0.0.1:{_config.LocalApplicationPort}");

            await TunnelRelay.BridgeAsync(localStream, codec, remoteStream, ct);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[gateway] client error: {ex.Message}");
        }
        finally
        {
            tcp.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { /* best effort */ }
        await Task.CompletedTask;
    }
}
