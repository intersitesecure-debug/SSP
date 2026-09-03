// File: tests/SSP.Tests/MultiClientProvisioningTests.cs
// Multi-Client Provisioning functional tests
// Validates that an existing Application can have multiple independent Clients

using System.Security.Cryptography;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Util;
using SSP.Server.Setup;
using SSP.Client.Runtime;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class MultiClientProvisioningTests
{
    private static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public async Task ExistingApplication_Detection_PreservesServerKeys()
    {
        using var baseDir = new TempDir();
        var appName = "RDP";
        var gatewayPort = FreePort();
        var localAppPort = FreePort();
        var tunnelPort = FreePort();

        var firstParams = new SetupParameters
        {
            ApplicationName = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = gatewayPort,
            LocalApplicationPort = localAppPort,
            ClientTunnelPort = tunnelPort,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var engine1 = new SetupEngine(UnlicensedTestGate.Instance);
        await engine1.RunAsync(firstParams);

        var privKey1 = await PemStore.LoadPrivateKeyAsync(Path.Combine(baseDir.Path, ".sysdata.bin"));
        var pubKey1 = await PemStore.LoadPublicKeyAsync(Path.Combine(baseDir.Path, ".runtime.dat"));
        var client01ExeHash = SHA256.HashData(await File.ReadAllBytesAsync(engine1.Result.ClientExecutablePath));

        // Second client provisioning for same app
        var secondParams = new SetupParameters
        {
            ApplicationName = appName,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client02",
        };
        var engine2 = new SetupEngine(UnlicensedTestGate.Instance);
        await engine2.RunAsync(secondParams);

        var privKey2 = await PemStore.LoadPrivateKeyAsync(Path.Combine(baseDir.Path, ".sysdata.bin"));
        var pubKey2 = await PemStore.LoadPublicKeyAsync(Path.Combine(baseDir.Path, ".runtime.dat"));

        Assert.Equal(privKey1, privKey2);
        Assert.Equal(pubKey1, pubKey2);

        // Client01 exe unchanged
        var client01Path = engine1.Result.ClientExecutablePath;
        Assert.True(File.Exists(client01Path));
        var client01HashAfter = SHA256.HashData(await File.ReadAllBytesAsync(client01Path));
        Assert.Equal(client01ExeHash, client01HashAfter);

        // Client02 exists separately
        Assert.True(File.Exists(engine2.Result.ClientExecutablePath));
        Assert.NotEqual(engine1.Result.ClientExecutablePath, engine2.Result.ClientExecutablePath);
        Assert.Contains("Client02", engine2.Result.ClientExecutablePath);
    }

    [Fact]
    public async Task Provisioning_DoesNotEraseAuthorizedUsers()
    {
        using var baseDir = new TempDir();
        var appName = "RDP";
        var gp = FreePort();
        var ap = FreePort();
        var tp = FreePort();

        var p1 = new SetupParameters
        {
            ApplicationName = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = gp,
            LocalApplicationPort = ap,
            ClientTunnelPort = tp,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var e1 = new SetupEngine(UnlicensedTestGate.Instance);
        await e1.RunAsync(p1);

        // Simulate enrollment by adding a user to .index.dat
        var authPath = Path.Combine(baseDir.Path, ".index.dat");
        var users = await AuthorisedUsersStore.LoadAsync(authPath);
        using var rsa = RsaCrypto.GenerateKeyPair();
        var pubPem = RsaCrypto.ExportPublicKeyPem(rsa);
        var fp = RsaCrypto.ComputePublicKeyFingerprint(rsa);
        users.Users.Add(new AuthorisedUser
        {
            ClientPublicKeyPem = pubPem,
            ClientPublicKeyFingerprint = fp,
            IsAuthorized = true,
            EnrolledAtUtc = DateTime.UtcNow.ToString("o"),
            Label = "Client01",
        });
        await AuthorisedUsersStore.SaveAsync(authPath, users);

        var usersBefore = await AuthorisedUsersStore.LoadAsync(authPath);
        Assert.Single(usersBefore.Users);

        // Provision second client
        var p2 = new SetupParameters
        {
            ApplicationName = appName,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client02",
        };
        var e2 = new SetupEngine(UnlicensedTestGate.Instance);
        await e2.RunAsync(p2);

        var usersAfter = await AuthorisedUsersStore.LoadAsync(authPath);
        Assert.Single(usersAfter.Users);
        Assert.Equal(fp, usersAfter.Users[0].ClientPublicKeyFingerprint);
    }

    [Fact]
    public async Task ClientExecutables_ContainEmbeddedOTT_And_DifferentOTTs_SameServerKey()
    {
        using var baseDir = new TempDir();
        var appName = "RDP";
        var gp = FreePort();
        var ap = FreePort();
        var tp = FreePort();

        var p1 = new SetupParameters
        {
            ApplicationName = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = gp,
            LocalApplicationPort = ap,
            ClientTunnelPort = tp,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var e1 = new SetupEngine(UnlicensedTestGate.Instance);
        await e1.RunAsync(p1);

        var p2 = new SetupParameters
        {
            ApplicationName = appName,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client02",
        };
        var e2 = new SetupEngine(UnlicensedTestGate.Instance);
        await e2.RunAsync(p2);

        // OTT different
        Assert.NotEqual(e1.Result.OneTimeToken, e2.Result.OneTimeToken);
        Assert.NotEqual(e1.Result.OneTimeTokenHash, e2.Result.OneTimeTokenHash);

        // Read embedded configs
        var bytes1 = await File.ReadAllBytesAsync(e1.Result.ClientExecutablePath);
        var cfg1 = ClientTemplate.ReadPatchSlot(bytes1);
        var bytes2 = await File.ReadAllBytesAsync(e2.Result.ClientExecutablePath);
        var cfg2 = ClientTemplate.ReadPatchSlot(bytes2);

        Assert.Equal(e1.Result.OneTimeToken, cfg1.OneTimeToken);
        Assert.Equal(e2.Result.OneTimeToken, cfg2.OneTimeToken);
        Assert.NotEqual(cfg1.OneTimeToken, cfg2.OneTimeToken);

        // Same server public key
        Assert.Equal(cfg1.ServerPublicKeyPem, cfg2.ServerPublicKeyPem);
        Assert.Equal(cfg1.ApplicationName, cfg2.ApplicationName);
        Assert.Equal(cfg1.GatewayPort, cfg2.GatewayPort);

        // Server config contains both pending hashes
        var serverCfg = await ServiceConfigStore.LoadAsync(Path.Combine(baseDir.Path, ".cache.dat"));
        Assert.Equal(2, serverCfg.PendingOneTimeTokens.Count);
        Assert.Contains(serverCfg.PendingOneTimeTokens, p => p.OneTimeTokenHash == e1.Result.OneTimeTokenHash);
        Assert.Contains(serverCfg.PendingOneTimeTokens, p => p.OneTimeTokenHash == e2.Result.OneTimeTokenHash);
    }

    [Fact]
    public async Task MultiplePendingOTTs_CanCoexist_And_OnlyMatchedIsConsumed()
    {
        // Create service with two pending clients
        using var baseDir = new TempDir();
        var appName = "RDP";
        var gp = FreePort();
        var ap = FreePort();
        var tp = FreePort();

        var p1 = new SetupParameters
        {
            ApplicationName = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = gp,
            LocalApplicationPort = ap,
            ClientTunnelPort = tp,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var e1 = new SetupEngine(UnlicensedTestGate.Instance);
        await e1.RunAsync(p1);

        var p2 = new SetupParameters
        {
            ApplicationName = appName,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client02",
        };
        var e2 = new SetupEngine(UnlicensedTestGate.Instance);
        await e2.RunAsync(p2);

        var p3 = new SetupParameters
        {
            ApplicationName = appName,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client03",
        };
        var e3 = new SetupEngine(UnlicensedTestGate.Instance);
        await e3.RunAsync(p3);

        var cfgBefore = await ServiceConfigStore.LoadAsync(Path.Combine(baseDir.Path, ".cache.dat"));
        Assert.Equal(3, cfgBefore.PendingOneTimeTokens.Count);

        // Enroll Client02
        var ott02 = e2.Result.OneTimeToken;
        await using var harness = await CreateHarnessFromServiceDirAsync(baseDir.Path, ott02, optionalExtraOtts: new[] { e1.Result.OneTimeToken, e3.Result.OneTimeToken });

        // Actually harness already contains one OTT hash; but we need gateway that uses service dir's pending list
        // We'll test enrollment directly via harness helpers

        // For simplicity, test consumption logic via ServerProtocol unit: we will enroll via full flow
        // Using helper EnrollAsync with OTT02
        var (runtime02, _) = await harness.CreateClientRuntimeAsync(ott02);
        await EnrollmentHelper.EnrollAsync(runtime02);

        var cfgAfter = await ServiceConfigStore.LoadAsync(Path.Combine(baseDir.Path, ".cache.dat"));
        Assert.Equal(2, cfgAfter.PendingOneTimeTokens.Count);
        Assert.DoesNotContain(cfgAfter.PendingOneTimeTokens, p => p.OneTimeTokenHash == e2.Result.OneTimeTokenHash);
        Assert.Contains(cfgAfter.PendingOneTimeTokens, p => p.OneTimeTokenHash == e1.Result.OneTimeTokenHash);
        Assert.Contains(cfgAfter.PendingOneTimeTokens, p => p.OneTimeTokenHash == e3.Result.OneTimeTokenHash);

        // Now enroll Client03, ensure Client01 still pending
        var (runtime03, _) = await harness.CreateClientRuntimeAsync(e3.Result.OneTimeToken);
        await EnrollmentHelper.EnrollAsync(runtime03);

        var cfgAfter2 = await ServiceConfigStore.LoadAsync(Path.Combine(baseDir.Path, ".cache.dat"));
        Assert.Single(cfgAfter2.PendingOneTimeTokens);
        Assert.Contains(cfgAfter2.PendingOneTimeTokens, p => p.OneTimeTokenHash == e1.Result.OneTimeTokenHash);
    }

    [Fact]
    public async Task Enrollment_Client02_After_Client01_RemainsAuthorized()
    {
        using var baseDir = new TempDir();
        var appName = "RDP";
        var gp = FreePort();
        var ap = FreePort();
        var tp = FreePort();

        var p1 = new SetupParameters
        {
            ApplicationName = appName,
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = gp,
            LocalApplicationPort = ap,
            ClientTunnelPort = tp,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var e1 = new SetupEngine(UnlicensedTestGate.Instance);
        await e1.RunAsync(p1);

        await using var harness1 = await CreateHarnessFromServiceDirAsync(baseDir.Path, e1.Result.OneTimeToken);
        var (runtime1, clientDir1) = await harness1.CreateClientRuntimeAsync(e1.Result.OneTimeToken);
        await EnrollmentHelper.EnrollAsync(runtime1);

        var authPath = Path.Combine(baseDir.Path, ".index.dat");
        var usersAfter1 = await AuthorisedUsersStore.LoadAsync(authPath);
        Assert.Single(usersAfter1.Users);
        var fp1 = usersAfter1.Users[0].ClientPublicKeyFingerprint;

        // Provision Client02
        var p2 = new SetupParameters
        {
            ApplicationName = appName,
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client02",
        };
        var e2 = new SetupEngine(UnlicensedTestGate.Instance);
        await e2.RunAsync(p2);

        // Enrollment of Client02 using same service dir (gateway reloads config)
        // Need new harness that loads updated config
        await using var harness2 = await CreateHarnessFromServiceDirAsync(baseDir.Path, e2.Result.OneTimeToken);
        var (runtime2, _) = await harness2.CreateClientRuntimeAsync(e2.Result.OneTimeToken);
        await EnrollmentHelper.EnrollAsync(runtime2);

        var usersAfter2 = await AuthorisedUsersStore.LoadAsync(authPath);
        Assert.Equal(2, usersAfter2.Users.Count);
        Assert.Contains(usersAfter2.Users, u => u.ClientPublicKeyFingerprint == fp1);
    }

    [Fact]
    public async Task WrongOTT_Rejected_And_DoesNotConsumeValidOTT()
    {
        using var baseDir = new TempDir();
        var p1 = new SetupParameters
        {
            ApplicationName = "RDP",
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = FreePort(),
            LocalApplicationPort = FreePort(),
            ClientTunnelPort = FreePort(),
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var e1 = new SetupEngine(UnlicensedTestGate.Instance);
        await e1.RunAsync(p1);

        await using var harness = await CreateHarnessFromServiceDirAsync(baseDir.Path, e1.Result.OneTimeToken);
        var (runtimeWrong, _) = await harness.CreateClientRuntimeAsync("wrong-token-123");
        var protocol = new ClientProtocol(runtimeWrong);
        await Assert.ThrowsAnyAsync<Exception>(() => protocol.ConnectAndAuthenticateAsync());

        var cfg = await ServiceConfigStore.LoadAsync(Path.Combine(baseDir.Path, ".cache.dat"));
        Assert.Single(cfg.PendingOneTimeTokens);
        Assert.Equal(e1.Result.OneTimeTokenHash, cfg.PendingOneTimeTokens[0].OneTimeTokenHash);
    }

    [Fact]
    public async Task WrongAuthenticationCode_DoesNotConsumeOTT()
    {
        using var baseDir = new TempDir();
        var p1 = new SetupParameters
        {
            ApplicationName = "RDP",
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = FreePort(),
            LocalApplicationPort = FreePort(),
            ClientTunnelPort = FreePort(),
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var e1 = new SetupEngine(UnlicensedTestGate.Instance);
        await e1.RunAsync(p1);

        await using var harness = await CreateHarnessFromServiceDirAsync(baseDir.Path, e1.Result.OneTimeToken);
        var (runtime, _) = await harness.CreateClientRuntimeAsync(e1.Result.OneTimeToken);

        var originalOut = Console.Out;
        var output = new StringWriter();
        Console.SetOut(output);
        try
        {
            var protocol = new ClientProtocol(runtime, () => Task.FromResult("0000000000")); // wrong code
            await Assert.ThrowsAnyAsync<Exception>(() => protocol.ConnectAndAuthenticateAsync());
        }
        finally
        {
            Console.SetOut(originalOut);
        }

        var cfg = await ServiceConfigStore.LoadAsync(Path.Combine(baseDir.Path, ".cache.dat"));
        Assert.Single(cfg.PendingOneTimeTokens);
        Assert.Equal(e1.Result.OneTimeTokenHash, cfg.PendingOneTimeTokens[0].OneTimeTokenHash);
    }

    [Fact]
    public async Task DuplicateClientName_Rejected()
    {
        using var baseDir = new TempDir();
        var p1 = new SetupParameters
        {
            ApplicationName = "RDP",
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort = FreePort(),
            LocalApplicationPort = FreePort(),
            ClientTunnelPort = FreePort(),
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var e1 = new SetupEngine(UnlicensedTestGate.Instance);
        await e1.RunAsync(p1);

        var pDup = new SetupParameters
        {
            ApplicationName = "RDP",
            ServiceDirectory = baseDir.Path,
            InstallWindowsService = false,
            ClientName = "Client01",
        };
        var eDup = new SetupEngine(UnlicensedTestGate.Instance);
        await Assert.ThrowsAnyAsync<Exception>(() => eDup.RunAsync(pDup));
    }

    [Fact]
    public async Task Client03_CanBeProvisionedAndEnrolled_After_Client01_Client02()
    {
        using var baseDir = new TempDir();
        var appName = "RDP";
        var gp = FreePort();
        var ap = FreePort();
        var tp = FreePort();

        for (int i = 1; i <= 3; i++)
        {
            var clientName = $"Client0{i}";
            SetupParameters p;
            if (i == 1)
            {
                p = new SetupParameters
                {
                    ApplicationName = appName,
                    GatewayPublicIpAddress = "127.0.0.1",
                    GatewayPort = gp,
                    LocalApplicationPort = ap,
                    ClientTunnelPort = tp,
                    ServiceDirectory = baseDir.Path,
                    InstallWindowsService = false,
                    ClientName = clientName,
                };
            }
            else
            {
                p = new SetupParameters
                {
                    ApplicationName = appName,
                    ServiceDirectory = baseDir.Path,
                    InstallWindowsService = false,
                    ClientName = clientName,
                };
            }
            var engine = new SetupEngine(UnlicensedTestGate.Instance);
            await engine.RunAsync(p);
            var cfg = await ServiceConfigStore.LoadAsync(Path.Combine(baseDir.Path, ".cache.dat"));
            // Before enrollment, pending count equals i minus enrolled count
            // For this test we enroll immediately after each provisioning
            var ott = engine.Result.OneTimeToken;
            await using var harness = await CreateHarnessFromServiceDirAsync(baseDir.Path, ott);
            var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
            await EnrollmentHelper.EnrollAsync(runtime);
        }

        var authPath = Path.Combine(baseDir.Path, ".index.dat");
        var users = await AuthorisedUsersStore.LoadAsync(authPath);
        Assert.Equal(3, users.Users.Count);
        Assert.Equal(3, users.Users.Select(u => u.ClientPublicKeyFingerprint).Distinct().Count());
    }

    // Helper to create a harness that uses the service dir's keys and config with pending list
    private static async Task<SspTestHarness> CreateHarnessFromServiceDirAsync(string serviceDir, string oneTimeToken, string[]? optionalExtraOtts = null)
    {
        var configPath = Path.Combine(serviceDir, ".cache.dat");
        var cfg = await ServiceConfigStore.LoadAsync(configPath);

        // We need free ports for gateway, but cfg already has ports - we will reuse cfg's ports but ensure free
        // For test isolation, override ports to free ones
        cfg.GatewayPort = FreePort();
        cfg.LocalApplicationPort = FreePort();
        cfg.ClientTunnelPort = FreePort();

        await ServiceConfigStore.SaveAsync(configPath, cfg);

        var privPem = await PemStore.LoadPrivateKeyAsync(Path.Combine(serviceDir, ".sysdata.bin"));
        var pubPem = await PemStore.LoadPublicKeyAsync(Path.Combine(serviceDir, ".runtime.dat"));

        // Create harness using the updated config but preserving serviceDir
        var harness = await SspTestHarness.CreateFromExistingConfigAsync(serviceDir, cfg, privPem, pubPem);
        harness.OneTimeToken = oneTimeToken;
        return harness;
    }

    internal sealed class TempDir : IDisposable
    {
        public string Path { get; }
        public TempDir() { Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ssp-multi-" + Guid.NewGuid().ToString("N")); System.IO.Directory.CreateDirectory(Path); }
        public void Dispose() { try { System.IO.Directory.Delete(Path, true); } catch { } }
    }
}
