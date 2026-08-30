// File: src/SSP.Client/Runtime/ClientTunnelRuntime.cs
//
// Runtime loop for an authenticated client:
//   1. If this process is not yet enrolled, connect to the gateway and
//      complete enrollment. The local tunnel port is NOT bound yet.
//   2. Only after enrollment (or if already enrolled): start a local
//      TCP listener on ClientTunnelPort and advertise it as ready.
//   3. For each local connection (mstsc, etc.):
//      a. Open a fresh gateway TCP connection.
//      b. Run future-authorization to negotiate a fresh AES-GCM session
//         key. Enrollment never runs here — it already completed in (1).
//      c. Bridge the local connection to that one tunnel.
//      d. Tear down both ends when either side closes.
//
// One local TCP connection == one tunnel TCP connection. This is the
// only correct architecture: a TCP connection is a single bidirectional
// byte stream, and an encrypted tunnel frame stream is also a single
// bidirectional byte stream. Multiplexing N local connections onto one
// tunnel requires a connection-id field in every frame (which SSP does
// not have). So we use the simpler N-to-N mapping.
//
// The persistent Client identity (RSA key pair, fingerprint) is reused
// across every tunnel connection - that is what makes future-authorization
// work without re-enrollment.

using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using SSP.Core.Protocol;

namespace SSP.Client.Runtime;

public sealed class ClientTunnelRuntime
{
    private readonly ClientRuntime _runtime;
    private readonly Func<Task<string>>? _authenticationCodeReader;

    public ClientTunnelRuntime(
        ClientRuntime runtime,
        Func<Task<string>>? authenticationCodeReader = null)
    {
        _runtime = runtime;
        _authenticationCodeReader = authenticationCodeReader;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        // The local tunnel port must not accept connections until this
        // client is enrolled. Binding first is what made mstsc trigger
        // enrollment in production.
        var enrollProtocol = new ClientProtocol(_runtime, _authenticationCodeReader);
        await enrollProtocol.EnsureEnrolledAsync(ct);

        var listener = new TcpListener(IPAddress.Loopback, _runtime.Config.ClientTunnelPort);
        listener.Start();
        Console.WriteLine("Tunnel ready:");
        Console.WriteLine($"  127.0.0.1:{_runtime.Config.ClientTunnelPort} -> {_runtime.Config.LocalApplicationPort}");
        Console.WriteLine("Waiting for Connection");

        // Optionally launch the protected application.
        if (_runtime.Config.AutoLaunchApplication)
            TryLaunchProtectedApplication();

        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient localClient;
                try { localClient = await listener.AcceptTcpClientAsync(ct); }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[tunnel] accept error: {ex.Message}");
                    continue;
                }

                // Each local connection gets its own tunnel connection
                // (with its own AES-GCM session key). The Client identity
                // (RSA key pair, fingerprint) is reused across all of them
                // via future-authorization - no re-enrollment required.
                _ = Task.Run(() => HandleLocalConnectionAsync(localClient, ct), ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleLocalConnectionAsync(TcpClient localClient, CancellationToken ct)
    {
        TcpClient? remoteClient = null;
        try
        {
            // Open a FRESH tunnel connection for THIS local connection.
            // Enrollment already completed in RunAsync, so this is
            // always future-authorization + a fresh session key.
            var protocol = new ClientProtocol(_runtime, _authenticationCodeReader);
            var (tcp, sessionKey) = await protocol.ConnectAndAuthenticateAsync(ct);
            remoteClient = tcp;
            using var codec = new TunnelCodec(sessionKey);

            await using var localStream = localClient.GetStream();
            var remoteStream = remoteClient.GetStream();

            // On the client side the local app is the plaintext side
            // (mstsc talks plaintext to ClientTunnelPort). We use the
            // eager BridgeAsync (not the lazy one) because the client
            // already knows the local app is connected.
            await TunnelRelay.BridgeAsync(localStream, codec, remoteStream, ct);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[tunnel] {ex.Message}");
        }
        finally
        {
            try { localClient.Dispose(); } catch { }
            try { remoteClient?.Dispose(); } catch { }
        }
    }

    /// <summary>
    /// Launch the protected application for the configured ApplicationName.
    /// For RDP this is mstsc.exe pointed at 127.0.0.1:ClientTunnelPort.
    /// For other application names this is a no-op (the administrator
    /// connects manually).
    /// </summary>
    private void TryLaunchProtectedApplication()
    {
        try
        {
            var appName = _runtime.Config.ApplicationName.ToUpperInvariant();
            if (appName == "RDP" && OperatingSystem.IsWindows())
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "mstsc.exe",
                    Arguments = $"/v:127.0.0.1:{_runtime.Config.ClientTunnelPort}",
                    UseShellExecute = true,
                };
                Process.Start(psi);
                Console.WriteLine("Launched mstsc.exe pointed at the tunnel.");
            }
            else
            {
                Console.WriteLine($"No automatic launcher for '{appName}'. Connect your client to 127.0.0.1:{_runtime.Config.ClientTunnelPort}.");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[launcher] {ex.Message}");
        }
    }
}
