// File: tests/SSP.Tests/Helpers/SspTestHarness.cs
//
// Reusable harness for F4-F10 tests. Spins up:
//   * a fake "protected application" TCP listener (acts as the local
//     service the gateway forwards to)
//   * a real ServerGateway on a free port, using a fresh RSA key pair
//     and service directory
//   * a real ClientRuntime / ClientProtocol pointed at the gateway

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Client.Runtime;
using SSP.Server.Runtime;

namespace SSP.Tests.Helpers;

public sealed class SspTestHarness : IAsyncDisposable
{
    public string ServiceDir { get; }
    public ServiceConfig Config { get; }
    public RSA ServerPrivateKey { get; }
    public string ServerPublicKeyPem { get; }
    public ServerGateway Gateway { get; }
    public TcpListener FakeAppListener { get; }
    public int GatewayPort { get; }
    public int LocalAppPort { get; }
    public int ClientTunnelPort { get; }

    private readonly CancellationTokenSource _cts = new();
    private readonly bool _ownsServiceDir;

    private SspTestHarness(
        string serviceDir,
        ServiceConfig config,
        RSA serverPrivateKey,
        string serverPublicKeyPem,
        ServerGateway gateway,
        TcpListener fakeAppListener,
        int gatewayPort,
        int localAppPort,
        int clientTunnelPort,
        bool ownsServiceDir)
    {
        ServiceDir = serviceDir;
        Config = config;
        ServerPrivateKey = serverPrivateKey;
        ServerPublicKeyPem = serverPublicKeyPem;
        Gateway = gateway;
        FakeAppListener = fakeAppListener;
        GatewayPort = gatewayPort;
        LocalAppPort = localAppPort;
        ClientTunnelPort = clientTunnelPort;
        _ownsServiceDir = ownsServiceDir;
    }

    // ServiceConfig.ApplicationName is non-nullable, so the app name is too
    // (a null here used to be flagged by the nullable analysis as a possible
    // null reference assignment).
    public static async Task<SspTestHarness> CreateAsync(string? oneTimeToken = null, string appName = "TEST")
    {
        var serviceDir = Path.Combine(System.IO.Path.GetTempPath(), "ssp-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(serviceDir);

        var gatewayPort = FreePort();
        var localAppPort = FreePort();
        var clientTunnelPort = FreePort();

        var rsa = RsaCrypto.GenerateKeyPair();
        var privPem = RsaCrypto.ExportPrivateKeyPem(rsa);
        var pubPem = RsaCrypto.ExportPublicKeyPem(rsa);
        await PemStore.SavePrivateKeyAsync(Path.Combine(serviceDir, ".sysdata.bin"), privPem);
        await PemStore.SavePublicKeyAsync(Path.Combine(serviceDir, ".runtime.dat"), pubPem);

        var ott = oneTimeToken ?? TokenGenerator.GenerateOneTimeToken();
        var ottHash = TokenGenerator.HashOneTimeToken(ott);

        var config = new ServiceConfig
        {
            ApplicationName         = appName,
            GatewayPublicIpAddress  = "127.0.0.1",
            GatewayPort             = gatewayPort,
            LocalApplicationPort    = localAppPort,
            ClientTunnelPort        = clientTunnelPort,
            ActiveOneTimeTokenHash  = ottHash,
            PendingOneTimeTokens    = new List<PendingOneTimeToken>
            {
                new PendingOneTimeToken
                {
                    ClientName = "Client01",
                    OneTimeTokenHash = ottHash,
                    CreatedAtUtc = DateTime.UtcNow.ToString("o"),
                }
            },
            CreatedAtUtc            = DateTime.UtcNow.ToString("o"),
        };
        await ServiceConfigStore.SaveAsync(Path.Combine(serviceDir, ".cache.dat"), config);
        await AuthorisedUsersStore.SaveAsync(Path.Combine(serviceDir, ".index.dat"), new AuthorisedUsersFile());

        var fakeAppListener = new TcpListener(IPAddress.Loopback, localAppPort);
        fakeAppListener.Start();

        var gateway = new ServerGateway(config, rsa, pubPem, serviceDir);

        var harness = new SspTestHarness(
            serviceDir, config, rsa, pubPem, gateway,
            fakeAppListener, gatewayPort, localAppPort, clientTunnelPort,
            ownsServiceDir: true);

        _ = gateway.RunAsync(harness._cts.Token);
        await Task.Delay(150);
        return harness;
    }

    /// <summary>
    /// The plaintext One-Time Token the harness was created with.
    /// </summary>
    public string OneTimeToken { get; set; } = string.Empty;

    public static async Task<SspTestHarness> CreateWithExplicitTokenAsync(string oneTimeToken, string appName = "TEST")
    {
        var h = await CreateAsync(oneTimeToken, appName);
        h.OneTimeToken = oneTimeToken;
        return h;
    }

    public static async Task<SspTestHarness> CreateFromExistingConfigAsync(string serviceDir, ServiceConfig config, string privPem, string pubPem)
    {
        var rsa = RsaCrypto.ImportPrivateKeyPem(privPem);

        // Ensure ports are free and listeners created accordingly
        var fakeAppListener = new TcpListener(IPAddress.Loopback, config.LocalApplicationPort);
        try { fakeAppListener.Start(); }
        catch
        {
            // If port already taken, try to find free and update config
            fakeAppListener.Stop();
            var free = FreePort();
            config.LocalApplicationPort = free;
            await ServiceConfigStore.SaveAsync(Path.Combine(serviceDir, ".cache.dat"), config);
            fakeAppListener = new TcpListener(IPAddress.Loopback, free);
            fakeAppListener.Start();
        }

        var gateway = new ServerGateway(config, rsa, pubPem, serviceDir);
        // Caller owns the Application directory. Do not delete it on dispose —
        // additional-client provisioning after enrollment must still see
        // .cache.dat and the existing RSA key pair.
        var harness = new SspTestHarness(
            serviceDir, config, rsa, pubPem, gateway,
            fakeAppListener, config.GatewayPort, config.LocalApplicationPort, config.ClientTunnelPort,
            ownsServiceDir: false);

        _ = gateway.RunAsync(harness._cts.Token);
        await Task.Delay(150);
        return harness;
    }

    public async Task<(ClientRuntime runtime, string clientDir)> CreateClientRuntimeAsync(string oneTimeToken)
    {
        var clientDir = Path.Combine(System.IO.Path.GetTempPath(), "ssp-client-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(clientDir);

        var cfg = new ClientConfig
        {
            ApplicationName        = Config.ApplicationName,
            ServerPublicKeyPem     = ServerPublicKeyPem,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = GatewayPort,
            LocalApplicationPort   = LocalAppPort,
            ClientTunnelPort       = ClientTunnelPort,
            OneTimeToken           = oneTimeToken,
        };
        var runtime = await ClientRuntime.LoadOrCreateAsync(clientDir, cfg);
        return (runtime, clientDir);
    }

    public async Task<TcpClient> AcceptFakeAppClientAsync(CancellationToken ct = default)
    {
        return await FakeAppListener.AcceptTcpClientAsync(ct);
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        FakeAppListener.Stop();
        ServerPrivateKey.Dispose();
        if (_ownsServiceDir)
        {
            try { Directory.Delete(ServiceDir, true); } catch { }
        }
        await Task.Delay(50);
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
