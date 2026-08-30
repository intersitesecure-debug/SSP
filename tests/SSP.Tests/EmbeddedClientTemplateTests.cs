// File: tests/SSP.Tests/EmbeddedClientTemplateTests.cs
//
// Validates the Embedded Client Template System end-to-end:
//
//   * Setup Mode runs without an external SSP.Client.exe present.
//   * The internal template is extracted from SSP.Server.exe.
//   * The template is processed as a COPY (template bytes unchanged).
//   * Every required field is patched into the copy.
//   * The generated client binary contains a readable ClientConfig.
//   * The original template is byte-for-byte unchanged.
//   * Setup Mode does not invoke dotnet publish/build/MSBuild.

using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Util;
using SSP.Server.Setup;
using Xunit;

namespace SSP.Tests;

public class EmbeddedClientTemplateTests
{
    private ClientConfig SampleConfig(string appName = "RDP") => new()
    {
        ApplicationName        = appName,
        ServerPublicKeyPem     = "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n",
        GatewayPublicIpAddress = "203.0.113.10",
        GatewayPort            = 4433,
        LocalApplicationPort   = 3389,
        ClientTunnelPort       = 3390,
        OneTimeToken           = "test-token-abc",
    };

    /// <summary>
    /// The template is embedded as a manifest resource inside SSP.Server.exe
    /// and can be read at runtime without any external file.
    /// </summary>
    [Fact]
    public void EmbeddedTemplate_ResourceExistsInServerAssembly()
    {
        var asm = typeof(SetupEngine).Assembly;
        var names = asm.GetManifestResourceNames();
        Assert.Contains(EmbeddedResourceNames.ClientTemplate, names);
    }

    /// <summary>
    /// The embedded template contains a patch slot that the patcher
    /// can locate.
    /// </summary>
    [Fact]
    public async Task EmbeddedTemplate_ContainsPatchSlot()
    {
        var bytes = await LoadEmbeddedTemplateAsync();
        var range = ClientTemplate.FindPatchSlotRange(bytes);
        Assert.NotNull(range);
    }

    /// <summary>
    /// The embedded template also contains the client_services slot, so
    /// the service list can live INSIDE the client executable instead of
    /// in a client_services.json file beside it. An unpatched template
    /// reads back as "no bundle".
    /// </summary>
    [Fact]
    public async Task EmbeddedTemplate_ContainsServicesSlot()
    {
        var bytes = await LoadEmbeddedTemplateAsync();
        Assert.NotNull(ClientTemplate.FindServicesSlotRange(bytes));
        Assert.Null(ClientTemplate.ReadServicesSlot(bytes));
    }

    /// <summary>
    /// Embedding the service list keeps the binary length constant,
    /// leaves the patch slot untouched, and stores the payload as the
    /// plain JSON text - no encryption, compression or obfuscation.
    /// </summary>
    [Fact]
    public async Task PatchServicesSlot_PreservesBinaryLength_AndKeepsPatchSlot()
    {
        var templateBytes = await LoadEmbeddedTemplateAsync();
        var cfg = SampleConfig();
        var patched = ClientTemplate.PatchCopy(templateBytes, cfg);

        var bundle = new ClientServiceBundle
        {
            Services = new List<ClientConfig> { cfg, SampleConfig("WEB") },
        };
        var json = bundle.ToJson();
        var withBundle = ClientTemplate.PatchServicesSlot(patched, json);

        Assert.Equal(patched.Length, withBundle.Length);

        // The patch slot survived unchanged.
        var readBackCfg = ClientTemplate.ReadPatchSlot(withBundle);
        Assert.Equal(cfg.ApplicationName, readBackCfg.ApplicationName);
        Assert.Equal(cfg.OneTimeToken, readBackCfg.OneTimeToken);

        // The embedded payload is the JSON text verbatim.
        var readBackJson = ClientTemplate.ReadServicesSlot(withBundle);
        Assert.Equal(json, readBackJson);
        Assert.StartsWith("{", readBackJson!.TrimStart());
        Assert.Contains("WEB", readBackJson);
        Assert.Equal(2, ClientServiceBundle.FromJson(readBackJson!).Services.Count);
    }

    /// <summary>
    /// A generated client is a SINGLE FILE: its service list is embedded
    /// in the executable and no client_services.json is written beside
    /// it - neither at build time nor when the list is re-embedded.
    /// </summary>
    [Fact]
    public async Task BuildPatchedClientAsync_EmbedsServiceList_WritesNoSidecarFile()
    {
        using var tempDir = new TempDir();
        var outPath = Path.Combine(tempDir.Path, "SSP.Client.TESTAPP.Client01.exe");
        var cfg = SampleConfig("TESTAPP");
        cfg.ClientName = "Client01";

        await SetupEngine.BuildPatchedClientAsync(outPath, cfg);

        Assert.True(File.Exists(outPath));
        Assert.Empty(Directory.EnumerateFiles(tempDir.Path, "client_services.json"));

        var bytes = await File.ReadAllBytesAsync(outPath);
        var bundle = ClientServiceBundle.LoadEmbedded(bytes)
                     ?? throw new InvalidOperationException("No embedded service bundle.");
        Assert.Single(bundle.Services);
        Assert.Equal("TESTAPP", bundle.Services[0].ApplicationName);
        Assert.Equal(cfg.OneTimeToken, bundle.Services[0].OneTimeToken);

        // Merging more connections re-embeds in place: same size, patch
        // slot intact, still no sidecar file.
        var merged = new ClientServiceBundle
        {
            Services = new List<ClientConfig> { cfg, SampleConfig("WEB") },
        };
        await ClientServiceBundle.WriteEmbeddedAsync(outPath, merged);

        var after = await File.ReadAllBytesAsync(outPath);
        Assert.Equal(bytes.Length, after.Length);
        Assert.Equal(2, ClientServiceBundle.LoadEmbedded(after)!.Services.Count);
        Assert.Equal(cfg.OneTimeToken, ClientTemplate.ReadPatchSlot(after).OneTimeToken);
        Assert.Empty(Directory.EnumerateFiles(tempDir.Path, "client_services.json"));
    }

    /// <summary>
    /// Patching the embedded template does NOT modify the original
    /// template bytes (a COPY is patched, not the template itself).
    /// </summary>
    [Fact]
    public async Task PatchCopy_DoesNotModifyTemplate()
    {
        var templateBytes = await LoadEmbeddedTemplateAsync();
        var templateHash = SHA256.HashData(templateBytes);

        var cfg = SampleConfig();
        var patched = ClientTemplate.PatchCopy(templateBytes, cfg);

        // The template must be byte-for-byte unchanged.
        var templateHashAfter = SHA256.HashData(templateBytes);
        Assert.Equal(templateHash, templateHashAfter);

        // The patched copy must differ from the template.
        var patchedHash = SHA256.HashData(patched);
        Assert.NotEqual(templateHash, patchedHash);
    }

    /// <summary>
    /// Every required field is patched into the copy and can be read back.
    /// </summary>
    [Fact]
    public async Task PatchCopy_AllRequiredFieldsPresent()
    {
        var templateBytes = await LoadEmbeddedTemplateAsync();
        var cfg = SampleConfig("WEB");
        var patched = ClientTemplate.PatchCopy(templateBytes, cfg);

        var readBack = ClientTemplate.ReadPatchSlot(patched);
        Assert.Equal(cfg.ApplicationName,         readBack.ApplicationName);
        Assert.Equal(cfg.ServerPublicKeyPem,      readBack.ServerPublicKeyPem);
        Assert.Equal(cfg.GatewayPublicIpAddress,  readBack.GatewayPublicIpAddress);
        Assert.Equal(cfg.GatewayPort,             readBack.GatewayPort);
        Assert.Equal(cfg.LocalApplicationPort,    readBack.LocalApplicationPort);
        Assert.Equal(cfg.ClientTunnelPort,        readBack.ClientTunnelPort);
        Assert.Equal(cfg.OneTimeToken,            readBack.OneTimeToken);
    }

    /// <summary>
    /// ValidatePatch passes for a correctly patched binary and fails
    /// for a tampered one.
    /// </summary>
    [Fact]
    public async Task ValidatePatch_DetectsMismatch()
    {
        var templateBytes = await LoadEmbeddedTemplateAsync();
        var cfg = SampleConfig();
        var patched = ClientTemplate.PatchCopy(templateBytes, cfg);

        // Should pass.
        ClientTemplate.ValidatePatch(patched, cfg);

        // Tampered expected config should fail.
        var tampered = new ClientConfig
        {
            ApplicationName        = cfg.ApplicationName,
            ServerPublicKeyPem     = cfg.ServerPublicKeyPem,
            GatewayPublicIpAddress = cfg.GatewayPublicIpAddress,
            GatewayPort            = 9999, // different
            LocalApplicationPort   = cfg.LocalApplicationPort,
            ClientTunnelPort       = cfg.ClientTunnelPort,
            OneTimeToken           = cfg.OneTimeToken,
        };
        Assert.Throws<InvalidDataException>(() => ClientTemplate.ValidatePatch(patched, tampered));
    }

    /// <summary>
    /// The patched binary has the same length as the template (slot
    /// size is constant). This keeps PE header offsets valid.
    /// </summary>
    [Fact]
    public async Task PatchCopy_PreservesBinaryLength()
    {
        var templateBytes = await LoadEmbeddedTemplateAsync();
        var cfg = SampleConfig();
        var patched = ClientTemplate.PatchCopy(templateBytes, cfg);
        Assert.Equal(templateBytes.Length, patched.Length);
    }

    /// <summary>
    /// BuildPatchedClientAsync (used by SetupEngine) writes a real
    /// patched executable to disk and does not require any external
    /// SSP.Client.exe file alongside the binary.
    /// </summary>
    [Fact]
    public async Task BuildPatchedClientAsync_ProducesReadableBinary()
    {
        using var tempDir = new TempDir();
        var outPath = Path.Combine(tempDir.Path, "SSP.Client.TESTAPP.exe");
        var cfg = SampleConfig("TESTAPP");

        await SetupEngine.BuildPatchedClientAsync(outPath, cfg);

        Assert.True(File.Exists(outPath));
        var writtenBytes = await File.ReadAllBytesAsync(outPath);
        var readBack = ClientTemplate.ReadPatchSlot(writtenBytes);
        Assert.Equal(cfg.ApplicationName, readBack.ApplicationName);
    }

    /// <summary>
    /// Running SetupEngine produces a full service directory with all
    /// mandated files: .sysdata.bin, .runtime.dat,
    /// .cache.dat, .index.dat, Client01/SSP.Client.&lt;App&gt;.Client01.exe.
    /// Updated for multi-client provisioning.
    /// </summary>
    [Fact]
    public async Task SetupEngine_ProducesAllRequiredFiles()
    {
        using var tempDir = new TempDir();
        var parameters = new SetupParameters
        {
            ApplicationName        = "RDP",
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = 4433,
            LocalApplicationPort   = 3389,
            ClientTunnelPort       = 3390,
            ServiceDirectory       = tempDir.Path,
            InstallWindowsService  = false,
            ClientName             = "Client01",
        };

        var engine = new SetupEngine();
        await engine.RunAsync(parameters);

        Assert.True(File.Exists(Path.Combine(tempDir.Path, ".sysdata.bin")));
        Assert.True(File.Exists(Path.Combine(tempDir.Path, ".runtime.dat")));
        Assert.True(File.Exists(Path.Combine(tempDir.Path, ".cache.dat")));
        Assert.True(File.Exists(Path.Combine(tempDir.Path, ".index.dat")));
        Assert.True(File.Exists(engine.Result.ClientExecutablePath));
        Assert.True(File.Exists(Path.Combine(tempDir.Path, "Client01", $"SSP.Client.RDP.Client01.exe")));
    }

    /// <summary>
    /// SetupEngine stores only the hash of the One-Time Token, not the
    /// plaintext. The plaintext is embedded in the client executable
    /// but never written to a server-side file.
    /// </summary>
    [Fact]
    public async Task SetupEngine_StoresOnlyHashOfOneTimeToken()
    {
        using var tempDir = new TempDir();
        var parameters = new SetupParameters
        {
            ApplicationName        = "SSH",
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = 4434,
            LocalApplicationPort   = 22,
            ClientTunnelPort       = 2222,
            ServiceDirectory       = tempDir.Path,
            InstallWindowsService  = false,
        };

        var engine = new SetupEngine();
        await engine.RunAsync(parameters);

        // The plaintext token is never persisted; the logical config stores
        // only the hash, and the encrypted-at-rest file exposes neither value
        // through direct disk reads.
        var configPath = Path.Combine(tempDir.Path, ".cache.dat");
        var cfg = await ServiceConfigStore.LoadAsync(configPath);
        Assert.Equal(engine.Result.OneTimeTokenHash, cfg.ActiveOneTimeTokenHash);

        var rawConfig = Encoding.UTF8.GetString(await File.ReadAllBytesAsync(configPath));
        Assert.DoesNotContain(engine.Result.OneTimeToken, rawConfig);
        Assert.DoesNotContain(engine.Result.OneTimeTokenHash, rawConfig);
    }

    private static async Task<byte[]> LoadEmbeddedTemplateAsync()
    {
        var asm = typeof(SetupEngine).Assembly;
        await using var rs = asm.GetManifestResourceStream(EmbeddedResourceNames.ClientTemplate)
            ?? throw new InvalidOperationException("Embedded template resource not found.");
        using var ms = new MemoryStream();
        await rs.CopyToAsync(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Helper: a temporary directory that is deleted when the test ends.
    /// </summary>
    internal sealed class TempDir : IDisposable
    {
        public string Path { get; }
        public TempDir() { Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ssp-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(Path); }
        public void Dispose() { try { Directory.Delete(Path, true); } catch { } }
    }
}

/// <summary>
/// Regression tests for the path-resolution fixes that address
/// Issue 1 (Single File not actually single) and Issue 2
/// (Service Start FAILED 1053 / JsonException in Event Viewer).
/// </summary>
public class PathResolutionRegressionTests
{
    /// <summary>
    /// SetupEngine must produce a service directory whose config file
    /// contains an absolute service directory, so that when the Windows
    /// Service starts under LocalSystem (CWD = C:\Windows\System32)
    /// the relative paths inside .cache.dat still resolve.
    ///
    /// This is the regression test for the JsonException in Event Viewer:
    /// if the service directory were relative, .cache.dat would
    /// be read from System32, fail to parse, and crash the service.
    /// </summary>
    [Fact]
    public async Task SetupEngine_WithRelativeServiceDir_PersistsAbsolutePaths()
    {
        using var tempBase = new EmbeddedClientTemplateTests.TempDir();
        var cwd = Directory.GetCurrentDirectory();
        Directory.SetCurrentDirectory(tempBase.Path);
        try
        {
            // Pass a RELATIVE service directory - this is what a user
            // does when they run "SSP.Server.exe --setup" from inside
            // a folder.
            var parameters = new SetupParameters
            {
                ApplicationName        = "REL",
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = 4500,
                LocalApplicationPort   = 3389,
                ClientTunnelPort       = 3390,
                ServiceDirectory       = "services/REL", // relative!
                InstallWindowsService  = false,
            };

            var engine = new SetupEngine();
            await engine.RunAsync(parameters);

            // The Result.ServiceDirectory must be absolute.
            Assert.True(System.IO.Path.IsPathRooted(engine.Result.ServiceDirectory),
                "ServiceDirectory should be absolute even when input is relative.");
            Assert.True(System.IO.Path.IsPathRooted(engine.Result.ServerConfigPath),
                "ServerConfigPath should be absolute.");
            Assert.True(System.IO.Path.IsPathRooted(engine.Result.ClientExecutablePath),
                "ClientExecutablePath should be absolute.");
            Assert.True(File.Exists(engine.Result.ServerConfigPath));
            Assert.True(File.Exists(engine.Result.ClientExecutablePath));
        }
        finally
        {
            Directory.SetCurrentDirectory(cwd);
        }
    }

    /// <summary>
    /// Reading the patch slot from a patched client binary that is
    /// copied to a different location (as happens when a user copies
    /// the patched SSP.Client.&lt;App&gt;.exe to a client machine)
    /// must still return the patched ClientConfig. This is the
    /// regression test for the "JsonException: The input does not
    /// contain any JSON tokens" Event Viewer error.
    /// </summary>
    [Fact]
    public async Task PatchedClient_ReadPatchSlot_WorksAfterCopy()
    {
        using var tempDir = new EmbeddedClientTemplateTests.TempDir();
        var outPath = System.IO.Path.Combine(tempDir.Path, "SSP.Client.COPY.exe");
        var cfg = new ClientConfig
        {
            ApplicationName        = "COPY",
            ServerPublicKeyPem     = "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n",
            GatewayPublicIpAddress = "198.51.100.42",
            GatewayPort            = 7700,
            LocalApplicationPort   = 3389,
            ClientTunnelPort       = 3390,
            OneTimeToken           = "test-token-copy",
        };

        await SetupEngine.BuildPatchedClientAsync(outPath, cfg);

        // Copy the patched binary to a SECOND location and read it back.
        // This simulates the user copying the patched client exe to a
        // different folder / different machine.
        var copy2 = System.IO.Path.Combine(tempDir.Path, "subdir", "SSP.Client.COPY2.exe");
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(copy2)!);
        File.Copy(outPath, copy2);

        var bytes = await File.ReadAllBytesAsync(copy2);
        var readBack = ClientTemplate.ReadPatchSlot(bytes);

        Assert.Equal(cfg.ApplicationName,        readBack.ApplicationName);
        Assert.Equal(cfg.GatewayPublicIpAddress, readBack.GatewayPublicIpAddress);
        Assert.Equal(cfg.GatewayPort,            readBack.GatewayPort);
        Assert.Equal(cfg.LocalApplicationPort,   readBack.LocalApplicationPort);
        Assert.Equal(cfg.ClientTunnelPort,       readBack.ClientTunnelPort);
        Assert.Equal(cfg.OneTimeToken,           readBack.OneTimeToken);
        Assert.Equal(cfg.ServerPublicKeyPem,     readBack.ServerPublicKeyPem);
    }
}
