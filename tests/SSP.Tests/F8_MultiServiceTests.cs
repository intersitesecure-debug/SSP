// File: tests/SSP.Tests/F8_MultiServiceTests.cs
//
// F8 - Multi-Service Support functional tests.
//
// Validates that multiple independent services (RDP, WEB, SSH, SQL) can
// coexist: each gets its own directory, RSA keys, config, authorized
// users file, and client executable.

using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Server.Setup;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class F8_MultiServiceTests
{
    /// <summary>
    /// Build four services (RDP, WEB, SSH, SQL) using the SetupEngine.
    /// Each one must have:
    ///   - its own service directory
    ///   - its own RSA key pair (different fingerprints)
    ///   - its own .cache.dat
    ///   - its own .index.dat
    ///   - its own SSP.Client.<App>.exe
    /// </summary>
    [Fact]
    public async Task MultiService_FourIndependentServicesCreated()
    {
        var baseDir = Path.Combine(System.IO.Path.GetTempPath(), "ssp-multi-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseDir);

        var specs = new[]
        {
            new { Name = "RDP", GP = 4433, AP = 3389, TP = 3390 },
            new { Name = "WEB", GP = 4434, AP = 80,   TP = 8080 },
            new { Name = "SSH", GP = 4435, AP = 22,   TP = 2222 },
            new { Name = "SQL", GP = 4436, AP = 1433, TP = 1440 },
        };

        var engines = new List<SetupResult>();

        try
        {
            foreach (var s in specs)
            {
                var parameters = new SetupParameters
                {
                    ApplicationName        = s.Name,
                    GatewayPublicIpAddress = "127.0.0.1",
                    GatewayPort            = s.GP,
                    LocalApplicationPort   = s.AP,
                    ClientTunnelPort       = s.TP,
                    ServiceDirectory       = Path.Combine(baseDir, s.Name),
                    InstallWindowsService  = false,
                };
                var engine = new SetupEngine(UnlicensedTestGate.Instance);
                await engine.RunAsync(parameters);
                engines.Add(engine.Result);
            }

            // Each engine must have produced all required artifacts.
            foreach (var r in engines)
            {
                Assert.True(File.Exists(r.ServerPrivateKeyPath));
                Assert.True(File.Exists(r.ServerPublicKeyPath));
                Assert.True(File.Exists(r.ServerConfigPath));
                Assert.True(File.Exists(r.AuthorisedUsersPath));
                Assert.True(File.Exists(r.ClientExecutablePath));
                var clientDir = Path.GetDirectoryName(r.ClientExecutablePath)!;
                // The service bundle is embedded in the client EXE; no
                // client_services.json file is written beside it.
                Assert.False(File.Exists(Path.Combine(clientDir, "client_services.json")));
                Assert.NotNull(ClientServiceBundle.LoadEmbedded(r.ClientExecutablePath));
            }

            // All four service directories must be distinct.
            var dirs = engines.Select(e => e.ServiceDirectory).ToHashSet();
            Assert.Equal(4, dirs.Count);

            // All four RSA public keys must have distinct fingerprints.
            var fingerprints = new HashSet<string>();
            foreach (var r in engines)
            {
                var pubPem = await PemStore.LoadPublicKeyAsync(r.ServerPublicKeyPath);
                var fp = RsaCrypto.ComputePublicKeyFingerprintFromPem(pubPem);
                Assert.True(fingerprints.Add(fp), $"Duplicate RSA fingerprint across services: {fp}");
            }
            Assert.Equal(4, fingerprints.Count);

            // All four One-Time Tokens must be distinct.
            var otts = engines.Select(e => e.OneTimeToken).ToHashSet();
            Assert.Equal(4, otts.Count);

            // All four client executables must contain a ClientConfig
            // with the correct application name.
            foreach (var r in engines)
            {
                var bytes = await File.ReadAllBytesAsync(r.ClientExecutablePath);
                var cfg = SSP.Core.Util.ClientTemplate.ReadPatchSlot(bytes);
                Assert.Equal(Path.GetFileName(r.ServiceDirectory!), cfg.ApplicationName);
            }
        }
        finally
        {
            try { Directory.Delete(baseDir, true); } catch { }
        }
    }

    /// <summary>
    /// Each service's config file must reflect that service's parameters.
    /// </summary>
    [Fact]
    public async Task MultiService_EachConfigReflectsItsParameters()
    {
        var baseDir = Path.Combine(System.IO.Path.GetTempPath(), "ssp-cfg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseDir);

        try
        {
            var parameters = new SetupParameters
            {
                ApplicationName        = "WEB",
                GatewayPublicIpAddress = "192.0.2.50",
                GatewayPort            = 4444,
                LocalApplicationPort   = 8080,
                ClientTunnelPort       = 9000,
                ServiceDirectory       = Path.Combine(baseDir, "WEB"),
                InstallWindowsService  = false,
            };

            var engine = new SetupEngine(UnlicensedTestGate.Instance);
            await engine.RunAsync(parameters);

            var cfg = await ServiceConfigStore.LoadAsync(engine.Result.ServerConfigPath);
            Assert.Equal("WEB",            cfg.ApplicationName);
            Assert.Equal("192.0.2.50",     cfg.GatewayPublicIpAddress);
            Assert.Equal(4444,             cfg.GatewayPort);
            Assert.Equal(8080,             cfg.LocalApplicationPort);
            Assert.Equal(9000,             cfg.ClientTunnelPort);
            Assert.NotNull(cfg.ActiveOneTimeTokenHash);
            Assert.Equal("SSP WEB 4444",  cfg.WindowsServiceName);
        }
        finally
        {
            try { Directory.Delete(baseDir, true); } catch { }
        }
    }
}
