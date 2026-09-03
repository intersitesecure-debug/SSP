// File: src/SSP.Server/Runtime/ServerGateway.cs
//
// Gateway runtime used in SERVICE MODE. Listens on 0.0.0.0:GatewayPort,
// one ServerProtocol per accepted connection, bridges the decrypted
// tunnel to 127.0.0.1:LocalApplicationPort.
//
// LICENSING (P3):
//   The gate is a MANDATORY, non-nullable constructor dependency. There is no
//   overload and no default value, so "protected runtime with no enforcement
//   object" is not representable: the compiler rejects it and the constructor
//   rejects null. Production obtains the gate from
//   SspRuntimeLicense.CreateForService (which refuses to return unless the
//   build has a compiled-in trust anchor AND the license is Valid); tests
//   supply their own explicit, loudly named gate.
//
//   Boundary semantics:
//     EP1 (service startup, max_services, feature) is enforced ONCE by the
//         composition root BEFORE this gateway is constructed - a service that
//         is not licensed never binds its port at all. It is deliberately NOT
//         re-checked per inbound connection: an accepted TCP connection is not
//         "starting a protected service", and using CanStartProtectedService
//         there both mis-states the operation being authorized and mis-counts
//         the limit (the usage argument is the count BEFORE the grant).
//     EP1/EP2/EP3 (feature, max_concurrent_tunnels, max_concurrent_sessions)
//         are enforced per connection by ServerProtocol through
//         ISspLicenseGate.AdmitTunnel(), after the client has been
//         cryptographically authenticated and before the tunnel becomes active.
//         Every one of those decisions is taken live against the LicenseManager,
//         so a Valid -> LockedDown transition denies the next connection
//         immediately without a restart. This class caches no licensing state.

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Protocol;
using SSP.Server.Activation;

namespace SSP.Server.Runtime;

public sealed class ServerGateway : IAsyncDisposable
{
    private readonly ServiceConfig _config;
    private readonly string _serviceDir;
    private readonly RSA _serverPrivateKey;
    private readonly string _serverPublicKeyPem;
    private readonly ISspLicenseGate _license;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoopTask;
    private Task? _disposeTask;
    private readonly object _disposeGate = new();
    private readonly ConcurrentDictionary<Task, byte> _clientTasks = new();

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

    /// <param name="license">
    /// The mandatory licensing gate for this service. Never null: a protected
    /// gateway without one would be a fail-open path.
    /// </param>
    public ServerGateway(
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
            "A protected SSP gateway requires a licensing gate. Production callers obtain one from " +
            "SspRuntimeLicense.CreateForService; tests must pass an explicit gate.");
    }

    /// <summary>
    /// The licensing gate this gateway runs under. Exposed for diagnostics and
    /// for tests that assert runtime decisions; it is never used to cache a
    /// licensing verdict.
    /// </summary>
    public ISspLicenseGate License => _license;

    /// <summary>
    /// Tunnels currently admitted by the license gate and not yet released.
    /// This is the usage figure <c>max_concurrent_tunnels</c> is enforced
    /// against; it is owned by the gate, not by this class.
    /// </summary>
    public long ActiveTunnels => _license.ActiveTunnels;

    /// <summary>
    /// Run the accept loop. Optionally accepts a caller-supplied
    /// TaskCompletionSource that is signaled as soon as the listener
    /// is bound. The caller (Windows Service host) uses this to delay
    /// reporting "started" to the SCM until the socket is ready.
    /// </summary>
    public Task RunAsync(CancellationToken externalToken, TaskCompletionSource? readySignal = null)
    {
        if (_acceptLoopTask is not null)
            throw new InvalidOperationException("The gateway can only be started once.");

        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
        _acceptLoopTask = AcceptLoopAsync(_cts.Token, readySignal ?? _listenerReady);
        return _acceptLoopTask;
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

                if (ct.IsCancellationRequested)
                {
                    client.Dispose();
                    break;
                }

                // Do not pass ct to Task.Run: if shutdown races this point,
                // Task.Run could return an already-canceled task without ever
                // invoking HandleClientAsync, leaking the accepted socket and
                // bypassing its admission-release finally block.
                var clientTask = Task.Run(() => HandleClientAsync(client, ct));
                _clientTasks.TryAdd(clientTask, 0);
                _ = clientTask.ContinueWith(
                    completed => _clientTasks.TryRemove(completed, out _),
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
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
        // The license slot reserved for this connection. Adopted from the
        // protocol handler the moment the tunnel is authorized, and released
        // exactly once in the finally block below - whether the tunnel ran to
        // completion, the client disconnected, or anything threw in between.
        SspTunnelAdmission? admission = null;

        // One ServerProtocol per connection, and it is disposable precisely
        // because it may still be holding the admission if the handshake failed
        // after the tunnel was authorized (see ServerProtocol.Dispose).
        var protocol = new ServerProtocol(_config, _serverPrivateKey, _serverPublicKeyPem, _serviceDir, _license);

        try
        {
            var sessionKey = await protocol.HandleAsync(tcp, ct);

            // Ownership of the reserved slot transfers to this method; the
            // protocol no longer releases it.
            admission = protocol.TakeTunnelAdmission();

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
            using var localClient = new TcpClient();
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
            // Release the licensed slot first: a disconnected client must give
            // its max_concurrent_tunnels / max_concurrent_sessions reservation
            // back immediately, or a limit would leak on every dropped call.
            // Both disposals are idempotent, so the failure path (protocol
            // still holding the admission) and the success path (this method
            // holding it) each release it exactly once.
            admission?.Dispose();
            protocol.Dispose();
            tcp.Dispose();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeGate)
        {
            // IAsyncDisposable callers are allowed to dispose concurrently or
            // more than once. Share one shutdown task so a second caller does
            // not race a CancellationTokenSource.Dispose call.
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    private async Task DisposeCoreAsync()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { /* best effort */ }

        // Stop is not enough by itself: accepted handlers own admissions and
        // release them in their finally blocks. Join the accept loop first so
        // no new handler can be added, then join every tracked handler before
        // declaring the gateway disposed.
        var acceptLoop = _acceptLoopTask;
        if (acceptLoop is not null)
        {
            try { await acceptLoop.ConfigureAwait(false); } catch { /* startup/shutdown is best effort */ }
        }

        while (!_clientTasks.IsEmpty)
        {
            var clients = _clientTasks.Keys.ToArray();
            try { await Task.WhenAll(clients).ConfigureAwait(false); } catch { /* handlers log and clean up */ }
        }

        _cts?.Dispose();
    }
}
