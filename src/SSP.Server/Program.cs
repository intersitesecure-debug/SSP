// File: src/SSP.Server/Program.cs
//
// SSP.Server entry point. Three operating modes; a direct executable launch
// with no arguments enters the same interactive setup mode:
//
//   dotnet SSP.Server.dll --setup
//       Interactive: prompts for service parameters and runs SetupEngine.
//
//   dotnet SSP.Server.dll --setup-batch <json-file>
//       Non-interactive: reads a SetupParameters JSON file and runs
//       SetupEngine. Used by ServiceBuilder and by tests.
//
//   dotnet SSP.Server.dll --service <serviceDir> [serviceName]
//       SERVICE MODE: connect to the SCM immediately, then load the config
//       and keys and start the gateway inside OnStart. This is also the
//       command line of the standalone Windows Service image
//       (SSP.ServiceHost.exe, src/SSP.ServiceHost), which forwards to this
//       entry point so installed services run the identical code without
//       referencing the setup executable. Nothing fallible runs before
//       ServiceBase.Run - see ServiceHost/SspWindowsService.cs for the SCM
//       start contract.
//
//   dotnet SSP.Server.dll --run-once <serviceDir>
//       Same as --service but runs in the foreground without Windows
//       Service plumbing. Used by integration tests on Linux.

using System.CommandLine;
using System.ServiceProcess;
using System.Text.Json;
using SSP.Activation;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Server.Activation;
using SSP.Server.Runtime;
using SSP.Server.Setup;
using SSP.Server.ServiceHost;

namespace SSP.Server;

/// <summary>
/// Public (previously internal) solely so the standalone service image,
/// src/SSP.ServiceHost (SSP.ServiceHost.exe), can enter the exact same
/// mode handling through the exact same entry point. Every argument SSP
/// passes today - and every behaviour of --service, --setup,
/// --setup-batch and --run-once - is unchanged; making the class public
/// adds no new behaviour, it only removes the need for a second
/// implementation of the service start path in the host.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Windows Service fast path. The SCM launches the service process
        // and waits for StartServiceCtrlDispatcher (ServiceBase.Run) to
        // connect; if the process exits or delays before that handshake,
        // the SCM reports ERROR 1053. ServiceBase.Run must therefore happen
        // promptly on the entry thread, and NOTHING that can throw may run
        // before it. RunWindowsService only resolves the SCM service name
        // defensively; the config read, the RSA import and the TCP listener
        // are all deferred to OnStart, where a failure is reported to the
        // SCM as a diagnosed failed start instead of an opaque 1053.
        if (args.Length >= 2 &&
            string.Equals(args[0], "--service", StringComparison.Ordinal))
        {
            var serviceName = args.Length >= 3 ? args[2] : null;
            return RunWindowsService(args[1], serviceName);
        }

        // A foreground server executable first launched outside Program Files
        // is handed off to the canonical executable through its Desktop
        // shortcut. Keep the SERVICE MODE entry paths and the licensing
        // diagnosis out of this flow: the SCM fast path above and --run-once
        // must retain their existing lifecycle behaviour, and --license-status
        // must answer from wherever the operator runs it (that is the whole
        // point of the diagnosis when a service refuses to start).
        var isRunOnce = args.Length >= 1 &&
            string.Equals(args[0], "--run-once", StringComparison.Ordinal);
        var isLicenseStatus = args.Length >= 1 &&
            string.Equals(args[0], "--license-status", StringComparison.Ordinal);
        var isLicenseInstall = args.Length >= 1 &&
            string.Equals(args[0], "--install-license", StringComparison.Ordinal);
        if (!isRunOnce && !isLicenseStatus && !isLicenseInstall && ServerInstallationBootstrapper.InstallAndLaunchSetupIfNeeded())
            return 0;

        var root = new RootCommand("SSP secure tunneling server");

        var setupCmd = new Command("--setup", "Run interactive SETUP MODE");
        setupCmd.SetHandler(async context =>
        {
            context.ExitCode = await RunInteractiveSetupAsync() ? 0 : 1;
        });
        root.Add(setupCmd);

        var setupBatchOpt = new Argument<string>("file", "Path to a SetupParameters JSON file.");
        var setupBatchCmd = new Command("--setup-batch", "Run SETUP MODE from a JSON file");
        setupBatchCmd.AddArgument(setupBatchOpt);
        setupBatchCmd.SetHandler(async ctx =>
        {
            var file = ctx.ParseResult.GetValueForArgument(setupBatchOpt);
            ctx.ExitCode = await RunBatchSetupAsync(file) ? 0 : 1;
        });
        root.Add(setupBatchCmd);

        var serviceDirArg = new Argument<string>("serviceDir", "Path to the service directory.");
        var serviceCmd = new Command("--service", "Run in Windows SERVICE MODE");
        serviceCmd.AddArgument(serviceDirArg);
        serviceCmd.SetHandler(async ctx =>
        {
            var dir = ctx.ParseResult.GetValueForArgument(serviceDirArg);
            await RunServiceModeAsync(dir, runAsWindowsService: true);
        });
        root.Add(serviceCmd);

        var runOnceCmd = new Command("--run-once", "Run SERVICE MODE in the foreground (no Windows Service plumbing)");
        runOnceCmd.AddArgument(serviceDirArg);
        runOnceCmd.SetHandler(async ctx =>
        {
            var dir = ctx.ParseResult.GetValueForArgument(serviceDirArg);
            await RunServiceModeAsync(dir, runAsWindowsService: false);
        });
        root.Add(runOnceCmd);

        // Operator licensing diagnosis. Reads and validates the license artifact
        // and prints a secret-free report; it never starts a protected service.
        var licenseRootOpt = new Option<string?>(
            "--license-root",
            "Optional licensing directory override (defaults to SSP_LICENSE_ROOT, then the canonical product root).");
        var licenseStatusCmd = new Command("--license-status", "Report the SSP licensing state and exit");
        licenseStatusCmd.AddOption(licenseRootOpt);
        licenseStatusCmd.SetHandler(async ctx =>
        {
            var licenseRoot = ctx.ParseResult.GetValueForOption(licenseRootOpt);
            ctx.ExitCode = await RunLicenseStatusAsync(licenseRoot) ? 0 : 1;
        });
        root.Add(licenseStatusCmd);

        // Validate an artifact completely before atomically replacing the
        // canonical installed license. Invalid artifacts never touch the
        // currently installed license.
        var installLicenseFileArg = new Argument<string>("file", "Path to a signed SSP license artifact.");
        var installLicenseRootOpt = new Option<string?>(
            "--license-root",
            "Optional licensing directory override (defaults to SSP_LICENSE_ROOT, then the canonical product root).");
        var installLicenseCmd = new Command("--install-license", "Validate and install a license artifact");
        installLicenseCmd.AddArgument(installLicenseFileArg);
        installLicenseCmd.AddOption(installLicenseRootOpt);
        installLicenseCmd.SetHandler(async ctx =>
        {
            var file = ctx.ParseResult.GetValueForArgument(installLicenseFileArg);
            var licenseRoot = ctx.ParseResult.GetValueForOption(installLicenseRootOpt);
            ctx.ExitCode = await RunInstallLicenseAsync(file, licenseRoot) ? 0 : 1;
        });
        root.Add(installLicenseCmd);

        // The Desktop shortcut intentionally has no arguments, so a direct
        // launch from the canonical executable location enters the existing
        // interactive SETUP MODE without creating another copy or shortcut.
        if (args.Length == 0)
            return await RunInteractiveSetupAsync() ? 0 : 1;

        return await root.InvokeAsync(args);
    }

    private static async Task<bool> RunInteractiveSetupAsync()
    {
        Console.Write("Application Name (e.g. RDP, WEB, SSH): ");
        var appName = Console.ReadLine()?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(appName))
        {
            Console.Error.WriteLine("Application Name is required.");
            return false;
        }

        var defaultServiceDir = Path.Combine(SetupEngine.GetCanonicalServicesRoot(), appName);
        var serviceDirFull = Path.GetFullPath(defaultServiceDir);
        var configPath = Path.Combine(serviceDirFull, ".cache.dat");
        var privPath = Path.Combine(serviceDirFull, ".sysdata.bin");
        var pubPath = Path.Combine(serviceDirFull, ".runtime.dat");
        bool isExisting = File.Exists(configPath) && File.Exists(privPath) && File.Exists(pubPath);

        SetupParameters p;

        if (isExisting)
        {
            Console.WriteLine();
            Console.WriteLine("=== EXISTING APPLICATION ===");
            Console.WriteLine($"Application: {appName}");
            Console.WriteLine($"Service Directory: {serviceDirFull}");
            Console.WriteLine();
            Console.Write("Client Name (e.g. Client02): ");
            var clientName = Console.ReadLine()?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(clientName))
            {
                Console.Error.WriteLine("Client Name is required for additional client provisioning.");
                return false;
            }

            p = new SetupParameters
            {
                ApplicationName = appName,
                ClientName = clientName,
                ServiceDirectory = serviceDirFull,
                // Gateway fields not needed for existing, but keep empty; SetupEngine will load from existing config
                GatewayPublicIpAddress = string.Empty,
                GatewayPort = 0,
                LocalApplicationPort = 0,
                ClientTunnelPort = 0,
            };
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("=== SSP SETUP MODE ===");
            Console.Write("Gateway Public IP Address: ");
            var ip = Console.ReadLine()?.Trim() ?? string.Empty;
            Console.Write("Gateway Port: ");
            var gp = int.Parse(Console.ReadLine() ?? "0");
            Console.Write("Local Application Port: ");
            var lap = int.Parse(Console.ReadLine() ?? "0");
            Console.Write("Client Tunnel Port: ");
            var ctp = int.Parse(Console.ReadLine() ?? "0");
            Console.Write("Client Name (e.g. Client01): ");
            var clientNameInput = Console.ReadLine()?.Trim();
            var clientName = string.IsNullOrWhiteSpace(clientNameInput) ? "Client01" : clientNameInput;

            p = new SetupParameters
            {
                ApplicationName = appName,
                GatewayPublicIpAddress = ip,
                GatewayPort = gp,
                LocalApplicationPort = lap,
                ClientTunnelPort = ctp,
                ClientName = clientName,
                ServiceDirectory = serviceDirFull,
            };
        }

        // EP0a/EP0b: provisioning-time licensing is mandatory. A build without
        // a trust anchor, or an invalid/missing artifact, cannot create a setup
        // engine and cannot lay out protected-service material.
        using var provisioningLicense = SspRuntimeLicense.TryCreateForProvisioning(p.ApplicationName);
        if (provisioningLicense is null)
            return false;
        var engine = new SetupEngine(provisioningLicense);
        try
        {
            await engine.RunAsync(p);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[setup] Failed: {ex.Message}");
            return false;
        }
        PrintSetupResult(engine.Result);
        return engine.Result.Success;
    }

    private static async Task<bool> RunBatchSetupAsync(string jsonFile)
    {
        var json = await File.ReadAllTextAsync(jsonFile);
        var p = JsonSerializer.Deserialize<SetupParameters>(json, JsonOptions.Default)
                ?? throw new InvalidDataException($"Failed to deserialize {jsonFile}.");

        // EP0a/EP0b: same mandatory provisioning-time checks as the
        // interactive path, so batch setup cannot step around them.
        using var provisioningLicense = SspRuntimeLicense.TryCreateForProvisioning(p.ApplicationName);
        if (provisioningLicense is null)
            return false;
        var engine = new SetupEngine(provisioningLicense);
        await engine.RunAsync(p);
        PrintSetupResult(engine.Result);
        return engine.Result.Success;
    }

    private static void PrintSetupResult(SetupResult r)
    {
        Console.WriteLine();
        Console.WriteLine(r.Success ? "=== SETUP COMPLETE ===" : "=== SETUP FAILED ===");
        if (r.IsAdditionalClient)
            Console.WriteLine($"Mode               : Additional Client Provisioning");
        else
            Console.WriteLine($"Mode               : New Application Setup");
        Console.WriteLine($"Service Directory : {r.ServiceDirectory}");
        Console.WriteLine($"Server Private Key: {r.ServerPrivateKeyPath}");
        Console.WriteLine($"Server Public Key : {r.ServerPublicKeyPath}");
        Console.WriteLine($"Server Config     : {r.ServerConfigPath}");
        Console.WriteLine($"Authorised Users  : {r.AuthorisedUsersPath}");
        if (!string.IsNullOrWhiteSpace(r.ClientName))
            Console.WriteLine($"Client Name       : {r.ClientName}");
        Console.WriteLine($"Client Executable : {r.ClientExecutablePath}");
        Console.WriteLine($"One-Time Token    : {r.OneTimeToken}");
        Console.WriteLine($"OTT Hash          : {r.OneTimeTokenHash}");
        if (r.WindowsServiceName != null)
            Console.WriteLine($"Windows Service   : {r.WindowsServiceName}");
    }

    /// <summary>
    /// Connect to the SCM. NOTHING that can throw may run before
    /// ServiceBase.Run: the SCM is waiting for StartServiceCtrlDispatcher to
    /// connect, and a process that exits before that handshake leaves it with
    /// no status and no AutoLog entry, which the operator sees as an
    /// undiagnosable ERROR 1053.
    ///
    /// The SCM service name is therefore resolved defensively (ImagePath
    /// token first, best-effort fallbacks after) and all fallible work -
    /// .cache.dat, the RSA key import and the TCP listener - is done
    /// inside SspWindowsService.OnStart, where a failure is reported to the
    /// SCM as a diagnosed failed start instead.
    /// </summary>
    private static int RunWindowsService(string serviceDir, string? serviceName)
    {
        // Resolve against the process CWD. For an SCM-launched service that
        // is System32, so Setup always stores an absolute path in binPath.
        serviceDir = SafeGetFullPath(serviceDir);

        if (!OperatingSystem.IsWindows())
        {
            RunServiceModeAsync(serviceDir, runAsWindowsService: false).GetAwaiter().GetResult();
            return 0;
        }

        var resolvedName = SspWindowsService.ResolveServiceName(serviceDir, serviceName);

        try
        {
            ServiceBase.Run(new SspWindowsService(serviceDir, resolvedName));
            return 0;
        }
        catch (Exception ex)
        {
            // ServiceBase.Run rethrows the exception captured from OnStart,
            // so this is the last chance to record the real cause before the
            // process dies. The exception is rethrown, never swallowed.
            ServiceDiagnostics.WriteStartupFailure(serviceDir, ex);
            throw;
        }
    }

    private static string SafeGetFullPath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch { return path; }
    }

    private static async Task RunServiceModeAsync(string serviceDir, bool runAsWindowsService)
    {
        // Resolve the service directory to an absolute path. When the
        // service is started by the SCM under LocalSystem, the current
        // working directory is C:\Windows\System32 - NOT the directory
        // of the executable. If the user (or SetupEngine) passed a
        // relative serviceDir, every subsequent Path.Combine would
        // resolve against System32 and we would fail to find
        // .cache.dat, .sysdata.bin, etc.
        //
        // We resolve against the current working directory (which for
        // a manually-launched --service invocation is the user's CWD,
        // and for an SCM-launched service is System32). If the path
        // is already absolute this is a no-op.
        serviceDir = Path.GetFullPath(serviceDir);

        if (runAsWindowsService)
        {
            // Delegate to the SCM fast path. In particular, do NOT load the
            // configuration here: that read would happen before
            // ServiceBase.Run and any failure would surface as ERROR 1053.
            RunWindowsService(serviceDir, serviceName: null);
            return;
        }

        var configPath = Path.Combine(serviceDir, ".cache.dat");
        var config = await ServiceConfigStore.LoadAsync(configPath);

        // EP1 - service startup licensing gate. This is the semantically correct
        // boundary for CanStartProtectedService: ONE protected service instance
        // is about to become operational. It runs before the keys are imported
        // and before the gateway (and therefore the listening socket) exists, so
        // an unlicensed service never binds its port at all.
        //
        // Fail closed: CreateForService throws SspActivationException unless this
        // build has a compiled-in Licensing Authority trust anchor AND the
        // license validates to Valid AND the protected protocol is in the
        // licensed feature set AND max_services is not exhausted.
        SspRuntimeLicense license;
        try
        {
            license = SspRuntimeLicense.CreateForService(config, serviceDir);
        }
        catch (SspActivationException ex)
        {
            Console.Error.WriteLine($"[activation] {ex.Message}");
            Console.Error.WriteLine(
                "[activation] The protected service was NOT started. Install a valid SSP license " +
                "and restart, or run 'SSP.Server --license-status' for the licensing diagnosis.");
            ServiceDiagnostics.WriteStartupFailure(serviceDir, ex);
            throw;
        }

        using (license)
        {
            var privPath = Path.Combine(serviceDir, config.ServerPrivateKeyPath);
            var privPem = await PemStore.LoadPrivateKeyAsync(privPath);
            using var rsa = RsaCrypto.ImportPrivateKeyPem(privPem);
            var pubPath = Path.Combine(serviceDir, config.ServerPublicKeyPath);
            var pubPem = await PemStore.LoadPublicKeyAsync(pubPath);

            var gateway = new ServerGateway(config, rsa, pubPem, serviceDir, license);
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, ev) => { ev.Cancel = true; cts.Cancel(); };
            await gateway.RunAsync(cts.Token);
        }
    }

    /// <summary>
    /// Operator licensing diagnosis. Composes the activation runtime, reads and
    /// validates the license artifact and prints a secret-free status report
    /// (state, reason code, product, installation id, feature/limit summary and
    /// the paths in use). Never starts a protected service and never starts the
    /// periodic refresh: this is a one-shot query.
    /// </summary>
    private static async Task<bool> RunInstallLicenseAsync(string sourcePath, string? licenseRoot)
    {
        try
        {
            var paths = SspLicensePaths.Resolve(licenseRoot);
            if (!SspTrustAnchor.IsCompiledIn)
            {
                Console.Error.WriteLine("[activation] license installation failed: no Licensing Authority trust anchor is compiled into this build.");
                return false;
            }

            using var activation = SspActivationService.Create(paths);
            var result = await SspLicenseInstaller.InstallAsync(activation, sourcePath);
            if (!result.IsValid)
            {
                // Keep the status vocabulary and secret-free diagnostics used by
                // --license-status; importantly, the target was not replaced.
                Console.Error.WriteLine($"[activation] license rejected: {result.State} ({result.ReasonCode}): {result.Detail}");
                return false;
            }

            Console.WriteLine($"License installed: {paths.LicenseFilePath}");
            Console.WriteLine($"State: {result.State} ({result.ReasonCode})");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[activation] license installation failed: {ex.Message}");
            return false;
        }
    }

    private static async Task<bool> RunLicenseStatusAsync(string? licenseRoot)
    {
        await Task.CompletedTask;

        try
        {
            var paths = SspLicensePaths.Resolve(licenseRoot);

            if (!SspTrustAnchor.IsCompiledIn)
            {
                Console.Error.WriteLine("=== SSP LICENSE STATUS ===");
                Console.Error.WriteLine(
                    "UNLICENSED BUILD: no Licensing Authority trust anchor is compiled into this " +
                    "binary (SspTrustAnchor.AuthorityPublicKeyPem is empty).");
                Console.Error.WriteLine(
                    "This is fail-closed: no license can validate, so no protected SSP service can " +
                    "start. Set the authority public key at the release key ceremony and rebuild.");
                Console.Error.WriteLine($"  License file       : {paths.LicenseFilePath}");
                Console.Error.WriteLine($"  State store        : {paths.StateStorePath}");
                Console.Error.WriteLine($"  Security log       : {Path.Combine(paths.SecurityLogDirectory, SspSecurityEventSink.LogFileName)}");
                return false;
            }

            using var activation = SspActivationService.Create(paths);
            activation.Load();
            Console.WriteLine(activation.DescribeStatus());
            return activation.CurrentState == LicenseState.Valid;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[activation] license status failed: {ex.Message}");
            return false;
        }
    }
}
