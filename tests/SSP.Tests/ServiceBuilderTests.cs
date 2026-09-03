// File: tests/SSP.Tests/ServiceBuilderTests.cs
//
// Validates the SSP.ServiceBuilder CLI by invoking SetupEngine with
// the same parameters the CLI accepts. The CLI itself is a thin
// wrapper around SetupEngine; full subprocess invocation is exercised
// in the F10 integration tests.

using SSP.Core.Models;
using SSP.Server.Setup;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class ServiceBuilderTests
{
    /// <summary>
    /// ServiceBuilder-equivalent parameters create a working RDP service
    /// directory with every required artifact.
    /// </summary>
    [Fact]
    public async Task ServiceBuilder_RdpService_AllArtifactsPresent()
    {
        var baseDir = Path.Combine(System.IO.Path.GetTempPath(), "ssp-sb-rdp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(baseDir);

        try
        {
            var parameters = new SetupParameters
            {
                ApplicationName        = "RDP",
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = 4433,
                LocalApplicationPort   = 3389,
                ClientTunnelPort       = 3390,
                ServiceDirectory       = baseDir,
                InstallWindowsService  = false,
                ClientName             = "Client01",
            };
            var engine = new SetupEngine(UnlicensedTestGate.Instance);
            await engine.RunAsync(parameters);

            Assert.True(File.Exists(Path.Combine(baseDir, ".sysdata.bin")));
            Assert.True(File.Exists(Path.Combine(baseDir, ".runtime.dat")));
            Assert.True(File.Exists(Path.Combine(baseDir, ".cache.dat")));
            Assert.True(File.Exists(Path.Combine(baseDir, ".index.dat")));
            Assert.True(File.Exists(engine.Result.ClientExecutablePath));
            Assert.True(File.Exists(Path.Combine(baseDir, "Client01", "SSP.Client.RDP.Client01.exe")));
            // client_services.json is embedded in the client executable:
            // it must NOT exist as a file next to the EXE.
            Assert.False(File.Exists(Path.Combine(baseDir, "Client01", "client_services.json")));
            var bundle = ClientServiceBundle.LoadEmbedded(engine.Result.ClientExecutablePath)
                         ?? throw new InvalidOperationException("Client executable has no embedded service bundle.");
            Assert.Single(bundle.Services);
            Assert.Equal("RDP", bundle.Services[0].ApplicationName);
            Assert.Equal(4433, bundle.Services[0].GatewayPort);
            Assert.Equal("SSP RDP 4433", engine.Result.WindowsServiceName);
        }
        finally
        {
            try { Directory.Delete(baseDir, true); } catch { }
        }
    }

    /// <summary>
    /// Build all four reference services (RDP, WEB, SSH, SQL) using the
    /// same path the ServiceBuilder CLI would use. Each must produce a
    /// standalone service directory.
    /// </summary>
    [Theory]
    [InlineData("RDP", 4433, 3389, 3390)]
    [InlineData("WEB", 4434, 80,   8080)]
    [InlineData("SSH", 4435, 22,   2222)]
    [InlineData("SQL", 4436, 1433, 1440)]
    public async Task ServiceBuilder_AllReferenceServicesCreated(string name, int gp, int ap, int tp)
    {
        var baseDir = Path.Combine(System.IO.Path.GetTempPath(), $"ssp-sb-{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(baseDir);

        try
        {
            var parameters = new SetupParameters
            {
                ApplicationName        = name,
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = gp,
                LocalApplicationPort   = ap,
                ClientTunnelPort       = tp,
                ServiceDirectory       = baseDir,
                InstallWindowsService  = false,
                ClientName             = "Client01",
            };
            var engine = new SetupEngine(UnlicensedTestGate.Instance);
            await engine.RunAsync(parameters);

            Assert.True(File.Exists(engine.Result.ClientExecutablePath));
            Assert.True(File.Exists(Path.Combine(baseDir, "Client01", $"SSP.Client.{name}.Client01.exe")));
            Assert.Equal($"SSP {name} {gp}", engine.Result.WindowsServiceName);
        }
        finally
        {
            try { Directory.Delete(baseDir, true); } catch { }
        }
    }

    /// <summary>
    /// SetupEngine rejects invalid parameters (empty name, out-of-range ports).
    /// </summary>
    [Theory]
    [InlineData("", "127.0.0.1", 4433, 3389, 3390)]
    [InlineData("RDP", "", 4433, 3389, 3390)]
    [InlineData("RDP", "127.0.0.1", 0, 3389, 3390)]
    [InlineData("RDP", "127.0.0.1", 70000, 3389, 3390)]
    public async Task ServiceBuilder_InvalidParameters_Throws(string name, string ip, int gp, int ap, int tp)
    {
        var parameters = new SetupParameters
        {
            ApplicationName        = name,
            GatewayPublicIpAddress = ip,
            GatewayPort            = gp,
            LocalApplicationPort   = ap,
            ClientTunnelPort       = tp,
        };
        var engine = new SetupEngine(UnlicensedTestGate.Instance);
        await Assert.ThrowsAsync<ArgumentException>(() => engine.RunAsync(parameters));
    }
}
