// File: src/SSP.Client/Runtime/ClientSessionHost.cs
//
// Explicit multi-connection host: one process, N independent SSP
// connections. No tunnel multiplexing: each connection (Server +
// Service) has its own ClientRuntime, RSA identity, enrollment state,
// GatewayPort, ClientTunnelPort and TCP connection. A failure in one
// session is logged and does not stop the others.
//
// NOTE: a PATCHED executable never reaches this host anymore - Program
// scopes a patched executable to the single connection in its own
// patch slot (ClientServiceBundle.SelectProcessConnections), so the
// lifecycle of connection A can never be started by the executable of
// connection B. This host remains for the unpatched-template mode and
// for callers that deliberately run several connections in one
// process; every runtime still enrolls strictly as ITS OWN
// Server + Service identity.

namespace SSP.Client.Runtime;

public sealed class ClientSessionHost
{
    private readonly IReadOnlyList<ClientRuntime> _runtimes;
    private readonly Func<ClientRuntime, Func<Task<string>>?>? _authenticationCodeReaderFactory;

    public ClientSessionHost(
        IReadOnlyList<ClientRuntime> runtimes,
        Func<ClientRuntime, Func<Task<string>>?>? authenticationCodeReaderFactory = null)
    {
        _runtimes = runtimes;
        _authenticationCodeReaderFactory = authenticationCodeReaderFactory;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        // Enrollment uses Console.ReadLine and Authcode.txt on the server.
        // Run it sequentially so codes cannot interleave. Each runtime is
        // one ConnectionIdentity: an already-enrolled RDP session is a
        // no-op here and must not skip or rewrite a later Web enrollment.
        foreach (var runtime in _runtimes)
        {
            ct.ThrowIfCancellationRequested();
            var app = runtime.ConnectionId;
            try
            {
                var reader = _authenticationCodeReaderFactory?.Invoke(runtime);
                var protocol = new ClientProtocol(runtime, reader);
                await protocol.EnsureEnrolledAsync(ct).ConfigureAwait(false);
            }
            catch (EnrollmentFailedException)
            {
                Console.Error.WriteLine($"[{app}] Enrollment failed.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[{app}] Enrollment failed: {ex.Message}");
            }
        }

        var tasks = _runtimes.Select(runtime => Task.Run(() => RunOneAsync(runtime, ct), ct)).ToArray();
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task RunOneAsync(ClientRuntime runtime, CancellationToken ct)
    {
        var app = runtime.ConnectionId;
        try
        {
            var reader = _authenticationCodeReaderFactory?.Invoke(runtime);
            var tunnel = new ClientTunnelRuntime(runtime, reader);
            await tunnel.RunAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // shutdown
        }
        catch (EnrollmentFailedException)
        {
            Console.Error.WriteLine($"[{app}] Enrollment failed.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[{app}] session ended: {ex.Message}");
        }
    }
}
