// File: src/SSP.Client/Program.cs
//
// SSP.Client entry point.
//
// At runtime a patched client binary contains a ClientConfig embedded
// in its patch slot. On first run the client also generates its own
// RSA key pair and stores it in the canonical connections directory
// (C:\Program Files\SSP\connections\{ConnectionId}\). A first launch
// from anywhere else is handed off to the canonical executable there
// (ClientInstallationBootstrapper) before any of the steps below run.
//
// ONE EXECUTABLE == ONE SSP CONNECTION (Server + Service). The patch
// slot of the launched binary defines THIS process's connection, and
// only that connection:
//
//   1. Read the embedded ClientConfig from THIS executable's patch
//      slot. That slot is THIS executable's ConnectionIdentity.
//   2. Resolve the whole installation (the client_services.json
//      embedded in this executable + sibling binaries) so the folder's
//      connection universe is known, then
//      pin the launched slot as the authoritative definition of its
//      own connection (gateway, OTT, server key) and SELECT ONLY THAT
//      CONNECTION for this process. Starting the RDP executable never
//      enrolls - and never dials the gateway of - WEB, SQL or SSH:
//      each of those completes its own lifecycle when its OWN
//      executable is started. (Selecting all bundle connections here
//      used to make the first started executable consume the other
//      connections' One-Time Tokens / Authentication Codes and bind
//      their tunnel ports, so the second executable could never
//      complete its own enrollment lifecycle.)
//   3. Load or generate the RSA key pair of THAT connection only.
//   4. If THAT connection is not enrolled: connect to THAT
//      connection's gateway, send THAT connection's One-Time Token,
//      wait for EnrollmentResult, prompt "Enter Authentication Code:".
//      The Authentication Code is typed here, BEFORE any local port
//      is bound. The enrollment socket is then closed.
//   5. Only now: start the local listener on ClientTunnelPort.
//   6. Wait for the local application (mstsc.exe for RDP).
//   7. For each local connection: future-authorization + AES-GCM
//      session key + bridge. Enrollment never runs after step 4.
//
// The patch slot below is empty at build time. SETUP MODE locates the
// sentinels and overwrites them with a real ClientConfig. The lines
// between the sentinels MUST stay byte-for-byte identical in length
// because the patcher writes a fixed-size payload.

using System.Net.Sockets;
using System.Reflection;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Protocol;
using SSP.Core.Util;
using SSP.Client.Runtime;
using SSP.Client.Setup;

namespace SSP.Client;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            // Touch the embedded patch-slot resource so the linker
            // keeps it as data. The actual patching is done by
            // SetupEngine against the binary on disk, not against
            // this in-memory copy.
            var slotBytes = PatchSlot.TemplateBytes;
            if (slotBytes.Length == 0) return -1;

            // Resolve the path to the ACTUAL on-disk binary that
            // contains the patched patch slot. This is tricky:
            //
            //   * Environment.ProcessPath returns the path of the
            //     process image. For a regular framework-dependent
            //     app this is SSP.Client.<App>.exe (the apphost),
            //     which is the file SetupEngine patched - good.
            //
            //   * For a single-file publish, Environment.ProcessPath
            //     STILL returns the host .exe on disk (not the
            //     extracted bundle under %TEMP%), because the host
            //     .exe is the process image. So this also works.
            //
            //   * Assembly.GetExecutingAssembly().Location, in
            //     contrast, returns the EXTRACTED location under
            //     %TEMP% for single-file, which does NOT contain
            //     the patched bytes. We must NOT use it.
            //
            //   * Environment.GetCommandLineArgs()[0] is the path
            //     the user/SCM used to launch us; it is the most
            //     reliable source. We try it first.
            //
            // The patched patch slot is only present in the original
            // .exe on disk. If we read from the extracted location,
            // ReadPatchSlot would return the EMPTY template (4096
            // spaces), and FromBase64String would succeed but
            // JsonSerializer.Deserialize would throw
            // "The input does not contain any JSON tokens." - which
            // is exactly the Event Viewer error reported in the
            // field.
            string thisAssemblyPath = ResolveMainBinaryPath();

            // FIRST-RUN HANDOFF: a client executable first launched
            // outside its canonical location (C:\Program Files\SSP) is
            // copied there, represented by one Desktop shortcut pointing
            // at the copied file, and the canonical copy is launched.
            // A launch that already IS the canonical executable passes
            // through: no copy, no shortcut. When the handoff takes
            // over, this process exits so two processes of the same
            // connection never run.
            if (ClientInstallationBootstrapper.InstallAndLaunchCanonicalIfNeeded(thisAssemblyPath))
                return 0;

            var binaryBytes = File.ReadAllBytes(thisAssemblyPath);

            var patchedConfig = ClientTemplate.ReadPatchSlot(binaryBytes);
            var exeDir = Path.GetDirectoryName(thisAssemblyPath)!;

            // client_services.json is embedded in this executable as a
            // manifest resource: it is read straight from the resource
            // (with the on-disk binary as fallback) and no sidecar file
            // is ever created or required beside the EXE.
            var embeddedServicesJson = ClientServicesResource.Read(binaryBytes);

            var configs = (await ClientServiceBundle.ResolveAsync(
                exeDir, patchedConfig, embeddedServicesJson)).ToList();
            // Defense in depth: ResolveAsync already pins the launched
            // connection. Repeat it here so Web-C1 can never enroll as
            // RDP (or skip its own OTT) because of a merged embedded bundle.
            ClientServiceBundle.ApplyLaunchedConnection(configs, patchedConfig);

            // Per-connection lifecycle: a patched executable runs ONLY the
            // connection embedded in its own patch slot. The remaining
            // bundle entries are separate connections that enroll when
            // their own executables are started - never here.
            var processConnections =
                ClientServiceBundle.SelectProcessConnections(configs, patchedConfig).ToList();

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, ev) => { ev.Cancel = true; cts.Cancel(); };

            if (processConnections.Count == 1)
            {
                var clientConfig = processConnections[0];
                var connectionDir = ClientServiceBundle.PrepareIdentityDirectory(
                    exeDir, clientConfig, processConnections.Count, patchedConfig);
                var clientRuntime = await ClientRuntime.LoadOrCreateAsync(connectionDir, clientConfig);

                Console.WriteLine($"SSP Client for '{clientConfig.ApplicationName}' starting.");
                Console.WriteLine($"  Connection : {clientRuntime.ConnectionId}");
                Console.WriteLine($"  Gateway  : {clientConfig.GatewayPublicIpAddress}:{clientConfig.GatewayPort}");
                Console.WriteLine($"  Tunnel   : 127.0.0.1:{clientConfig.ClientTunnelPort} -> {clientConfig.LocalApplicationPort}");
                if (configs.Count > processConnections.Count)
                {
                    Console.WriteLine($"  This installation also holds {configs.Count - processConnections.Count} other " +
                                      "connection(s); each one starts and enrolls via its own client executable.");
                }

                var runtime = new ClientTunnelRuntime(clientRuntime);
                await runtime.RunAsync(cts.Token);
                return 0;
            }

            // Unpatched-template host mode: the launched binary has no
            // connection of its own, so this process hosts every resolved
            // connection (ClientSessionHost runs their lifecycles).
            Console.WriteLine($"SSP Client starting {processConnections.Count} connections.");
            var runtimes = new List<ClientRuntime>(processConnections.Count);
            foreach (var clientConfig in processConnections)
            {
                var idDir = ClientServiceBundle.PrepareIdentityDirectory(
                    exeDir, clientConfig, processConnections.Count, patchedConfig);
                var clientRuntime = await ClientRuntime.LoadOrCreateAsync(idDir, clientConfig);
                runtimes.Add(clientRuntime);
                Console.WriteLine($"  {clientRuntime.ConnectionId}: Gateway {clientConfig.GatewayPublicIpAddress}:{clientConfig.GatewayPort}  Tunnel 127.0.0.1:{clientConfig.ClientTunnelPort} -> {clientConfig.LocalApplicationPort}");
            }

            var host = new ClientSessionHost(runtimes);
            await host.RunAsync(cts.Token);
            return 0;
        }
        catch (EnrollmentFailedException)
        {
            // ClientProtocol already printed the short user message.
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[SSP.Client] Fatal: {ex}");
            return 1;
        }
    }

    /// <summary>
    /// Resolve the path of the on-disk binary that contains the
    /// patched patch slot. See Main for the rationale.
    /// </summary>
    private static string ResolveMainBinaryPath()
    {
        // 1. Try the first command-line argument. This is the path
        //    the user used to launch the .exe.
        try
        {
            var cmdArgs = Environment.GetCommandLineArgs();
            if (cmdArgs.Length > 0 && !string.IsNullOrWhiteSpace(cmdArgs[0]))
            {
                var p = Path.GetFullPath(cmdArgs[0]);
                if (File.Exists(p)) return p;
            }
        }
        catch { /* ignore */ }

        // 2. Fall back to Environment.ProcessPath. For both
        //    framework-dependent and single-file publishes this
        //    points to the .exe on disk (the process image).
        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(processPath) && File.Exists(processPath))
            return processPath;

        // 3. Last resort: AppContext.BaseDirectory + main module name.
        //    This is the directory the .exe lives in.
        var baseDir = AppContext.BaseDirectory;
        var exeName = "SSP.Client.exe";
        var candidate = Path.Combine(baseDir, exeName);
        if (File.Exists(candidate)) return candidate;

        // If we get here, give up and return ProcessPath (which may
        // be null). The caller will throw a clearer exception.
        return processPath ?? string.Empty;
    }
}
