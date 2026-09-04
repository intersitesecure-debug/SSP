// File: src/SSP.Server/Setup/WindowsServiceInstaller.cs
//
// Windows Service installation for SETUP MODE.  Keeping this plumbing in
// one place makes four details explicit:
//
//   * sc.exe receives each argument through ProcessStartInfo.ArgumentList.
//     In particular, binPath= is one argument containing a correctly quoted
//     Windows command line.  Hand-building sc.exe's command line with nested
//     quotes corrupts paths containing spaces.
//   * every newly created service runs its OWN standalone host executable:
//     the published self-contained SSP.ServiceHost.exe (src/SSP.ServiceHost)
//     is EXTRACTED from this setup image's embedded build resources into the
//     service directory it was created for, and ImagePath points at that
//     file.  The host is a separately compiled executable with its own
//     identity - it is NOT a copy of the setup executable and it never
//     references it.  Setup (C:\Program Files\SSP\SSP.Server.exe) is purely
//     the tool that creates/installs services: the moment creation has
//     finished it can be moved or deleted, and the service still starts.
//   * the service binary forwards --service verbatim into SSP.Server's
//     entry point, so config, encryption, gateway and client behaviour -
//     and the whole SCM start contract - are identical to the established
//     ones.  The --service argument tokens (<serviceDir> <serviceName>)
//     do not change.
//   * developer/test layouts (SSP.ServiceBuilder, testhost, the elevated
//     SCM regression test) keep their existing framework-dependent launch
//     through the dotnet host unchanged; registering the current process
//     in those cases would create a service which exits as soon as SCM
//     passes it the unsupported --service command.  Existing services are
//     never migrated - only services created from now on get the host.

using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Util;

namespace SSP.Server.Setup;

internal static class WindowsServiceInstaller
{
    private static readonly TimeSpan ServiceStartTimeout = TimeSpan.FromSeconds(30);

    // File name of the standalone service host the SCM runs. It is the
    // service's own executable, extracted from the embedded build-time
    // image, and deliberately NOT named after - or byte-identical to -
    // the setup executable.
    internal const string ServiceHostExecutableName = "SSP.ServiceHost.exe";

    // Test/developer seam: when set, this file is used as the service host
    // image instead of the embedded resource, so the extraction contract
    // can be exercised without a self-contained win-x64 publish.
    // Production setups never set it.
    internal const string ServiceHostImageOverrideVariable = "SSP_SERVICE_HOST_IMAGE";

    // Name of the setup executable, used only to recognise the production
    // layout when resolving the launch command. It is never copied into a
    // service directory and never appears in any ImagePath.
    private const string ServerExecutableName = "SSP.Server.exe";
    private const string ServerAssemblyName = "SSP.Server";

    /// <summary>
    /// Creates the service, starts it immediately, and returns true only if
    /// SCM reports RUNNING and the configured gateway socket is listening.
    /// sc.exe output is always forwarded verbatim, including access-denied
    /// diagnostics such as "OpenSCManager FAILED 5".
    /// </summary>
    public static async Task<bool> CreateStartAndVerifyAsync(
        ServiceConfig config,
        string serviceDirectory,
        CancellationToken cancellationToken)
    {
        var serviceName = config.WindowsServiceName;
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            Console.Error.WriteLine("[windows-service] WindowsServiceName is missing.");
            return false;
        }

        try
        {
            var launch = ResolveServerLaunchCommand();

            // Give the service its own standalone host image inside its own
            // directory, extracted from the embedded build resource. After
            // this the setup executable is referenced by no ImagePath, was
            // never copied, and is not held open by the service, so it can
            // be moved or deleted immediately.
            var serviceDirFull = Path.GetFullPath(serviceDirectory);
            launch = await PrepareServiceHostImageAsync(
                launch, serviceDirFull, cancellationToken).ConfigureAwait(false);

            var launchArguments = new List<string>(launch.Arguments)
            {
                "--service",
                serviceDirFull,
                serviceName,
            };
            var imagePath = BuildWindowsCommandLine(launch.FileName, launchArguments);

            var createExitCode = await RunScAsync(
                ["create", serviceName, "binPath=", imagePath, "start=", "auto"],
                cancellationToken).ConfigureAwait(false);
            if (createExitCode != 0)
            {
                // Do not reinterpret or suppress sc.exe failures.  In
                // particular, an unelevated process must continue to expose
                // OpenSCManager FAILED 5 and setup must remain unsuccessful.
                Console.Error.WriteLine(
                    $"[windows-service] sc create failed (exit code {createExitCode}).");
                return false;
            }

            var startExitCode = await RunScAsync(
                ["start", serviceName], cancellationToken).ConfigureAwait(false);
            if (startExitCode != 0)
            {
                Console.Error.WriteLine(
                    $"[windows-service] sc start failed (exit code {startExitCode}).");
                return false;
            }

            if (!WaitForRunning(serviceName, ServiceStartTimeout))
                return false;

            // SspWindowsService.OnStart does not return until
            // TcpListener.Start has succeeded.  Therefore a RUNNING service
            // must already be visible in the active-listener snapshot; no
            // arbitrary post-start sleep or retry delay is necessary.
            if (!IsPortListening(config.GatewayPort))
            {
                Console.Error.WriteLine(
                    $"[windows-service] gateway port {config.GatewayPort} is not listening. " +
                    "The service reported RUNNING without a ready gateway.");
                return false;
            }

            Console.WriteLine(
                $"[windows-service] service '{serviceName}' is RUNNING and the gateway is " +
                $"listening on 0.0.0.0:{config.GatewayPort}.");

            // The verification above is LOCAL: it proves the socket is
            // bound on this machine, not that a client can reach it. Every
            // additional SSP service listens on its OWN port, and Windows
            // Firewall / NAT rules are per port - a rule opened for the
            // first service (e.g. TCP 4433) does NOT cover the next one
            // (e.g. TCP 4480). Without an inbound allow rule the service
            // still reports RUNNING while clients time out (10060). State
            // that explicitly instead of letting "listening" imply
            // "reachable".
            Console.WriteLine(BuildReachabilityNotice(config));
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[windows-service] {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Materializes the service's standalone host image: the published,
    /// self-contained SSP.ServiceHost.exe embedded in this setup assembly
    /// is EXTRACTED into the service directory and the returned launch
    /// command's file name becomes that file. The image comes from the
    /// build-time embedded resource - the setup executable's own bytes are
    /// never read, copied or referenced - so the setup file
    /// (<c>C:\Program Files\SSP\SSP.Server.exe</c>) can be moved or deleted
    /// the moment the service exists.
    ///
    /// Framework-dependent launches resolved through the dotnet host are
    /// developer/test-layout artefacts with no standalone setup image to
    /// extract alongside; they are returned unchanged exactly as before,
    /// and existing services are never migrated.
    ///
    /// A missing host image is a hard setup failure on purpose: falling
    /// back to the setup executable would silently re-create the very
    /// dependency this design removes.
    /// </summary>
    internal static async Task<ServerLaunchCommand> PrepareServiceHostImageAsync(
        ServerLaunchCommand launch,
        string serviceDirectory,
        CancellationToken cancellationToken)
    {
        if (!launch.IsServerAppHost)
            return launch;

        var serviceDirFull = Path.GetFullPath(serviceDirectory);
        var hostImagePath = Path.Combine(serviceDirFull, ServiceHostExecutableName);

        // The source is this assembly's manifest resource (or the explicit
        // test seam), never launch.FileName: the resolved setup executable
        // is not opened, so it is neither copied nor kept open by this
        // step. ReadServiceHostImageAsync throws before anything is
        // written when no image is available.
        var image = await ReadServiceHostImageAsync(cancellationToken).ConfigureAwait(false);

        Directory.CreateDirectory(serviceDirFull);
        await AtomicFile.WriteBytesAsync(hostImagePath, image, cancellationToken)
            .ConfigureAwait(false);

        if (!OperatingSystem.IsWindows())
        {
            // Mirrors BuildPatchedClientAsync: non-Windows test runners get
            // a runnable image too, and reinstallation overwrites a stale
            // host through the same atomic replace.
            try
            {
                File.SetUnixFileMode(hostImagePath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            catch { /* best effort */ }
        }

        Console.WriteLine(
            $"[windows-service] standalone service host extracted to '{hostImagePath}'. The " +
            "service runs its own SSP.ServiceHost.exe; the setup executable is not copied and " +
            "not referenced by any ImagePath, so it is fully movable/deletable right after " +
            "creation.");
        return launch with { FileName = hostImagePath };
    }

    /// <summary>
    /// The bytes of the standalone service host image: production always
    /// uses the build-time embedded resource; the environment override
    /// exists for tests and local development only. An empty image is
    /// rejected - it would install a service that can never start.
    /// </summary>
    internal static async Task<byte[]> ReadServiceHostImageAsync(CancellationToken cancellationToken)
    {
        var overridePath = Environment.GetEnvironmentVariable(ServiceHostImageOverrideVariable);
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            var full = Path.GetFullPath(overridePath);
            if (!File.Exists(full))
            {
                throw new FileNotFoundException(
                    $"The SSP.ServiceHost image override '{ServiceHostImageOverrideVariable}' " +
                    $"points at '{full}', which does not exist.",
                    full);
            }

            return ValidateServiceHostImage(
                await File.ReadAllBytesAsync(full, cancellationToken).ConfigureAwait(false),
                $"'{full}'");
        }

        var assembly = typeof(SetupEngine).Assembly;
        await using (var resource = assembly.GetManifestResourceStream(EmbeddedResourceNames.ServiceHostImage)
            ?? throw new InvalidOperationException(
                $"Embedded service host resource '{EmbeddedResourceNames.ServiceHostImage}' not found. " +
                "Rebuild SSP.Server without SSP_SKIP_EMBED so the PublishServiceHostTemplate " +
                "target embeds the published SSP.ServiceHost.exe. The service is not installed " +
                "by falling back to the setup executable - that dependency is exactly what this " +
                "design removes."))
        {
            using var buffer = new MemoryStream();
            await resource.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
            return ValidateServiceHostImage(
                buffer.ToArray(),
                $"resource '{EmbeddedResourceNames.ServiceHostImage}'");
        }
    }

    private static byte[] ValidateServiceHostImage(byte[] image, string origin)
    {
        if (image.Length == 0)
        {
            throw new InvalidDataException(
                $"The SSP.ServiceHost image from {origin} is empty. Rebuild and republish " +
                "SSP.Server so the embedded service host image is complete.");
        }

        return image;
    }

    /// <summary>
    /// Starts sc.exe without a shell and forwards both output streams.  The
    /// streams are drained concurrently so waiting for process exit cannot
    /// deadlock on a full redirected-output buffer.
    /// </summary>
    private static async Task<int> RunScAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "sc.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start sc.exe.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort only; retain the original cancellation/error.
            }

            throw;
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        // Write, rather than WriteLine, so sc.exe's diagnostic text is
        // preserved exactly. OpenSCManager FAILED 5 must remain visible.
        if (stdout.Length != 0)
            Console.Out.Write(stdout);
        if (stderr.Length != 0)
            Console.Error.Write(stderr);

        return process.ExitCode;
    }

    private static bool WaitForRunning(string serviceName, TimeSpan timeout)
    {
        // ServiceController is the client of the Windows Service Control
        // Manager, so on any other platform there is no SCM to poll. The
        // only caller is reached through a Windows-guarded setup path, and
        // the refusal below keeps that fact explicit instead of relying on a
        // PlatformNotSupportedException being swallowed by the catch below.
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine(
                $"[windows-service] service control is only available on Windows; " +
                $"cannot verify whether '{serviceName}' is RUNNING.");
            return false;
        }

        try
        {
            using var controller = new ServiceController(serviceName);

            // Poll instead of WaitForStatus(Running): the target status alone
            // cannot distinguish a slow start from a process that already
            // FAILED. A service that reports STOPPED while we are waiting for
            // its first start has died (SCM records the failed start; there
            // is no recovery action configured), so waiting for the remainder
            // of the timeout cannot change the outcome - fail fast with the
            // observed state instead of blocking setup for the full budget.
            var deadline = DateTime.UtcNow + timeout;
            while (true)
            {
                controller.Refresh();
                var status = controller.Status;

                if (status == ServiceControllerStatus.Running)
                {
                    return true;
                }

                if (status == ServiceControllerStatus.Stopped)
                {
                    Console.Error.WriteLine(
                        $"[windows-service] service '{serviceName}' stopped before reaching RUNNING. " +
                        "Diagnose with 'sc query' and the Windows Event Log (Application), and with " +
                        "ssp-service-startup.log in the service directory.");
                    return false;
                }

                if (DateTime.UtcNow >= deadline)
                {
                    Console.Error.WriteLine(
                        $"[windows-service] service '{serviceName}' did not reach RUNNING state " +
                        $"(last observed: {status}). Diagnose with 'sc query' and the Windows " +
                        "Event Log (Application).");
                    return false;
                }

                Thread.Sleep(250);
            }
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            Console.Error.WriteLine(
                $"[windows-service] service '{serviceName}' did not reach RUNNING state. " +
                "Diagnose with 'sc query' and the Windows Event Log (Application).");
            return false;
        }
        catch (Exception ex)
        {
            // Do not silently retry access-denied/query failures.  Report the
            // actual SCM error and leave setup unsuccessful.
            Console.Error.WriteLine(
                $"[windows-service] could not verify service '{serviceName}': {ex.Message}");
            return false;
        }
    }

    private static bool IsPortListening(int port)
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpListeners()
                .Any(endpoint => endpoint.Port == port);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[windows-service] could not verify gateway port {port}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Operational notice printed after a service is installed and verified
    /// RUNNING: the local bind check says nothing about reachability from
    /// client machines. Inbound TCP {GatewayPort} must be allowed by Windows
    /// Firewall on the server AND by any NAT router / cloud security group
    /// in front of it. SSP deliberately does not modify the firewall
    /// itself; this notice gives the operator the exact commands.
    /// </summary>
    internal static string BuildReachabilityNotice(ServiceConfig config)
    {
        var port = config.GatewayPort;
        var ip = string.IsNullOrWhiteSpace(config.GatewayPublicIpAddress)
            ? "<gateway public IP>"
            : config.GatewayPublicIpAddress;

        return
            "[windows-service] NOTE: the check above was LOCAL - it proves the gateway socket is" + Environment.NewLine +
            $"[windows-service] bound, not that clients can reach it. Inbound TCP {port} must ALSO be allowed by:" + Environment.NewLine +
            "[windows-service]   1. Windows Firewall on this server (elevated):" + Environment.NewLine +
            $"[windows-service]      netsh advfirewall firewall add rule name=\"SSP Gateway {port}\" dir=in action=allow protocol=TCP localport={port}" + Environment.NewLine +
            "[windows-service]   2. any NAT router port-forwarding rule / cloud security group in front of" + Environment.NewLine +
            $"[windows-service]      this server that should forward {ip}:{port} to it." + Environment.NewLine +
            $"[windows-service] Then verify FROM A CLIENT MACHINE: Test-NetConnection {ip} -Port {port}";
    }

    /// <summary>
    /// Resolves a command which actually enters SSP.Server.Program.  The
    /// current process may instead be ServiceBuilder or testhost, so it must
    /// never be used merely because it happens to host SetupEngine.
    /// </summary>
    internal static ServerLaunchCommand ResolveServerLaunchCommand()
    {
        var serverAssembly = typeof(SetupEngine).Assembly;
        var serverAssemblyPath = serverAssembly.Location;
        var serverDirectory = !string.IsNullOrWhiteSpace(serverAssemblyPath)
            ? Path.GetDirectoryName(serverAssemblyPath)!
            : AppContext.BaseDirectory;

        // Normal build/publish layout: prefer the server apphost.  It owns
        // the correct runtimeconfig/deps files and is also the production
        // self-contained single-file path.  Only this layout is treated as
        // the production setup image, and even then the apphost is only
        // consulted for layout recognition: the service's executable comes
        // from PrepareServiceHostImageAsync (the embedded standalone host),
        // not from this path.
        //
        // A stray SSP.Server.exe next to a *referenced* SSP.Server.dll
        // (testhost / ServiceBuilder developer output) is NOT that layout.
        // Accepting it as the production image would materialize an apphost
        // that has no runtimeconfig/deps of its own in the service
        // directory; the process would never reach
        // StartServiceCtrlDispatcher and sc start would report ERROR 1053.
        // Those hosts must keep using the framework-dependent `dotnet exec`
        // path below, which is what lets the elevated SCM regression test
        // start a real service.
        var appHostPath = Path.Combine(serverDirectory, ServerExecutableName);
        if (File.Exists(appHostPath) && ShouldUseServerAppHost(appHostPath))
            return new ServerLaunchCommand(Path.GetFullPath(appHostPath), [], IsServerAppHost: true);

        // A single-file server has an empty Assembly.Location.  It may have
        // been renamed, so use ProcessPath only when SSP.Server itself is
        // the entry assembly.  This deliberately excludes ServiceBuilder
        // and testhost.
        if (Assembly.GetEntryAssembly() == serverAssembly)
        {
            var processPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(processPath) &&
                processPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(Path.GetFileName(processPath), "dotnet.exe", StringComparison.OrdinalIgnoreCase))
            {
                return new ServerLaunchCommand(Path.GetFullPath(processPath), [], IsServerAppHost: true);
            }
        }

        if (string.IsNullOrWhiteSpace(serverAssemblyPath) || !File.Exists(serverAssemblyPath))
        {
            throw new FileNotFoundException(
                "Could not locate SSP.Server.exe or SSP.Server.dll. " +
                "Publish SSP.Server before installing the Windows Service.");
        }

        // Framework-dependent fallback.  This is also what lets an elevated
        // test host verify a real service: its output contains
        // SSP.Server.dll even though testhost itself is not a service host.
        var dotnetHost = ResolveDotnetHostPath();
        var serverRuntimeConfig = Path.Combine(serverDirectory, ServerAssemblyName + ".runtimeconfig.json");
        if (File.Exists(serverRuntimeConfig))
        {
            return new ServerLaunchCommand(dotnetHost, [Path.GetFullPath(serverAssemblyPath)], IsServerAppHost: false);
        }

        // Executable project references do not always copy the referenced
        // project's runtimeconfig. dotnet exec can use the calling app's
        // runtimeconfig/deps graph, which already contains SSP.Server and
        // its dependencies.
        var runtimeFiles = FindHostRuntimeFiles(serverDirectory);
        if (runtimeFiles is not null)
        {
            var args = new List<string> { "exec", "--runtimeconfig", runtimeFiles.Value.RuntimeConfig };
            if (runtimeFiles.Value.DepsFile is not null)
            {
                args.Add("--depsfile");
                args.Add(runtimeFiles.Value.DepsFile);
            }
            args.Add(Path.GetFullPath(serverAssemblyPath));
            return new ServerLaunchCommand(dotnetHost, args, IsServerAppHost: false);
        }

        throw new FileNotFoundException(
            $"SSP.Server.dll was found at '{serverAssemblyPath}', but no runtimeconfig was available. " +
            "Publish SSP.Server so the Service Control Manager has a runnable service image.");
    }

    /// <summary>
    /// True when <paramref name="appHostPath"/> is a self-sufficient
    /// production SSP.Server image - the layout whose service receives the
    /// extracted standalone SSP.ServiceHost.exe (PrepareServiceHostImageAsync
    /// is then applied; the recognized image itself is still never copied).
    /// A single-file publish has no sidecar DLL; a framework-dependent
    /// publish has the DLL and its runtimeconfig next to the apphost.
    /// Anything else (notably testhost output, which copies the referenced
    /// project's apphost without the runtimeconfig) is not a production
    /// layout and must keep the dotnet-host launch instead.
    /// </summary>
    internal static bool IsProductionServerImage(string appHostPath)
    {
        if (string.IsNullOrWhiteSpace(appHostPath) || !File.Exists(appHostPath))
            return false;

        string directory;
        try
        {
            directory = Path.GetDirectoryName(Path.GetFullPath(appHostPath)) ?? string.Empty;
        }
        catch
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(directory))
            return false;

        // Single-file / self-contained image: the apphost is the whole app.
        var serverDll = Path.Combine(directory, ServerAssemblyName + ".dll");
        if (!File.Exists(serverDll))
            return true;

        // Framework-dependent publish: the apphost only represents a
        // complete production layout when its own runtimeconfig travels
        // with it.
        var runtimeConfig = Path.Combine(directory, ServerAssemblyName + ".runtimeconfig.json");
        return File.Exists(runtimeConfig);
    }

    /// <summary>
    /// The production apphost layout is recognized (and the standalone host
    /// image gets extracted) only when the apphost is a complete
    /// self-sufficient image AND the current process is not a test host.
    /// Testhost output can look complete (SDK versions that also copy the
    /// referenced project's runtimeconfig) and still fail under LocalSystem
    /// because the deps/runtimes graph belongs to testhost, not to
    /// SSP.Server.
    /// </summary>
    private static bool ShouldUseServerAppHost(string appHostPath)
        => !IsTestHostProcess() && IsProductionServerImage(appHostPath);

    private static bool IsTestHostProcess()
    {
        try
        {
            if (IsTestHostName(Path.GetFileNameWithoutExtension(Environment.ProcessPath)))
                return true;

            if (IsTestHostName(Assembly.GetEntryAssembly()?.GetName().Name))
                return true;
        }
        catch
        {
            // If the process identity cannot be read, do not block a
            // production apphost layout on a false positive.
        }

        return false;
    }

    private static bool IsTestHostName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        return name.StartsWith("testhost", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("vstest", StringComparison.OrdinalIgnoreCase);
    }

    private static string ResolveDotnetHostPath()
    {
        var configuredHost = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(configuredHost) && File.Exists(configuredHost))
            return Path.GetFullPath(configuredHost);

        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath) &&
            string.Equals(Path.GetFileName(processPath), "dotnet.exe", StringComparison.OrdinalIgnoreCase) &&
            File.Exists(processPath))
        {
            return Path.GetFullPath(processPath);
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(programFiles))
        {
            var machineHost = Path.Combine(programFiles, "dotnet", "dotnet.exe");
            if (File.Exists(machineHost))
                return machineHost;
        }

        // Let CreateProcess resolve the system PATH. If dotnet is absent,
        // service start fails visibly and setup remains unsuccessful.
        return "dotnet.exe";
    }

    private static (string RuntimeConfig, string? DepsFile)? FindHostRuntimeFiles(string directory)
    {
        var entryName = Assembly.GetEntryAssembly()?.GetName().Name;
        if (!string.IsNullOrWhiteSpace(entryName))
        {
            var entryRuntimeConfig = Path.Combine(directory, entryName + ".runtimeconfig.json");
            if (File.Exists(entryRuntimeConfig))
            {
                var entryDeps = Path.Combine(directory, entryName + ".deps.json");
                return (Path.GetFullPath(entryRuntimeConfig),
                    File.Exists(entryDeps) ? Path.GetFullPath(entryDeps) : null);
            }
        }

        foreach (var runtimeConfig in Directory.EnumerateFiles(directory, "*.runtimeconfig.json"))
        {
            var stem = runtimeConfig[..^".runtimeconfig.json".Length];
            var deps = stem + ".deps.json";
            return (Path.GetFullPath(runtimeConfig), File.Exists(deps) ? Path.GetFullPath(deps) : null);
        }

        return null;
    }

    /// <summary>
    /// Builds the ImagePath command line stored by SCM. Every token is
    /// quoted with the Windows CommandLineToArgvW escaping rules.
    /// </summary>
    internal static string BuildWindowsCommandLine(string fileName, IEnumerable<string> arguments)
    {
        return string.Join(" ", new[] { fileName }.Concat(arguments).Select(QuoteWindowsArgument));
    }

    private static string QuoteWindowsArgument(string value)
    {
        var result = new StringBuilder(value.Length + 2);
        result.Append('"');

        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                result.Append('\\', backslashes * 2 + 1);
                result.Append('"');
                backslashes = 0;
                continue;
            }

            result.Append('\\', backslashes);
            backslashes = 0;
            result.Append(character);
        }

        // Backslashes immediately before the closing quote must be doubled.
        result.Append('\\', backslashes * 2);
        result.Append('"');
        return result.ToString();
    }

    /// <summary>
    /// The command SCM will run.  <see cref="IsServerAppHost"/> is true when
    /// the resolved layout is the production setup image (publish layout or
    /// renamed single-file image); that flag is ONLY a layout marker - the
    /// service never runs the setup executable or a copy of it, because
    /// FileName is replaced by the standalone SSP.ServiceHost.exe extracted
    /// in <see cref="PrepareServiceHostImageAsync"/>.  It is false for
    /// framework-dependent launches through the dotnet host (developer/test
    /// layouts), which have no standalone setup image and are returned
    /// unchanged.
    /// </summary>
    internal sealed record ServerLaunchCommand(
        string FileName,
        IReadOnlyList<string> Arguments,
        bool IsServerAppHost);
}
