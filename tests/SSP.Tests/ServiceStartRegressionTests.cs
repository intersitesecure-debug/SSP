// File: tests/SSP.Tests/ServiceStartRegressionTests.cs
//
// Regression tests for the Windows Service Start 1053 fix.
//
// Before the patch:
//   * SspWindowsService.OnStart used Task.Run and returned immediately.
//   * The SCM considered the service "started" before the TCP listener
//     was bound.
//   * On Windows Server 2022 with slower LocalSystem socket bind,
//     the SCM timed out with ERROR 1053.
//
// After the patch:
//   * ServerGateway exposes a ListenerReady task that completes as
//     soon as TcpListener.Start() returns.
//   * SspWindowsService.OnStart waits up to 25 seconds for
//     ListenerReady before returning, so the SCM only considers the
//     service "started" once the socket is actually accepting
//     connections.
//   * OnStart re-arms the SCM wait hint with RequestAdditionalTime while it
//     waits, instead of blocking the start path with dwWaitHint = 0 and
//     dwCheckPoint = 0 (ServiceBase.Initialize leaves both at 0, so the SCM
//     falls back to its fixed budget and reports ERROR 1053).
//   * Nothing fallible runs before ServiceBase.Run. The SCM service name is
//     resolved by SspWindowsService.ResolveServiceName, which never throws -
//     a throw there kills the process before StartServiceCtrlDispatcher
//     connects and the operator is left with an undiagnosable ERROR 1053.
//   * ServiceDiagnostics records the exception in full: type, message,
//     stack trace and every inner exception (AggregateException flattened),
//     so a 1053/1064 is always accompanied by the real cause.
//
// The portable tests run on every platform and verify the contract between
// SspWindowsService and ServerGateway. An additional Windows-only test uses
// the actual SCM whenever the test process has an elevated token.

using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Server.Runtime;
using SSP.Server.ServiceHost;
using SSP.Server.Setup;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class ServiceStartRegressionTests
{
    /// <summary>
    /// The service host must be constructible (and report the SCM name)
    /// without importing RSA keys or binding a socket. Those belong in
    /// OnStart, after ServiceBase.Run has already connected to SCM.
    /// </summary>
    [Fact]
    public void SspWindowsService_Construction_DoesNotRequireGateway()
    {
        var config = new ServiceConfig
        {
            ApplicationName    = "RDP",
            GatewayPort        = 4433,
            WindowsServiceName = "SSP RDP 4433",
        };

        // The SCM-facing half of the constructor (ServiceName and the rest of
        // the ServiceBase options) only exists on Windows, so this is the one
        // place where a Windows guard is required rather than a portable
        // assertion. xUnit 2.5 has no runtime Skip, hence the early return.
        if (!OperatingSystem.IsWindows())
            return;

        var service = new SspWindowsService(config, Path.GetTempPath());
        Assert.Equal("SSP RDP 4433", service.ServiceName);
    }

    /// <summary>
    /// When .cache.dat has no WindowsServiceName, the host must
    /// derive the SCM name from the application name and gateway port
    /// ("SSP {ApplicationName} {GatewayPort}") rather than failing. This is
    /// the fallback the production start path relies on when the name is not
    /// available from the ImagePath argument.
    /// </summary>
    [Fact]
    public void SspWindowsService_Construction_DerivesNameWhenConfigHasNoName()
    {
        var config = new ServiceConfig
        {
            ApplicationName    = "RDP",
            GatewayPort        = 4433,
            WindowsServiceName = null,
        };

        // Same platform note as the test above: the derived name is only
        // observable through ServiceBase.ServiceName.
        if (!OperatingSystem.IsWindows())
            return;

        var service = new SspWindowsService(config, Path.GetTempPath());
        Assert.Equal("SSP RDP 4433", service.ServiceName);
    }

    /// <summary>
    /// A fatal failure in the pre-dispatcher start path must never be silent:
    /// ServiceDiagnostics records it to a local log file and does not throw,
    /// so an ERROR 1053 is always accompanied by a discoverable cause.
    /// </summary>
    [Fact]
    public void ServiceDiagnostics_WriteStartupFailure_WritesLogWithoutThrowing()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-diag-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            var ex = new InvalidOperationException("boom");

            // Must not throw, even though event-logging is unavailable here.
            ServiceDiagnostics.WriteStartupFailure(dir, ex);

            var logPath = ServiceDiagnostics.ResolveLogFilePath(dir);
            Assert.True(File.Exists(logPath), $"Expected log file at {logPath}.");

            var content = File.ReadAllText(logPath);
            Assert.Contains("boom", content);
            Assert.Contains("InvalidOperationException", content);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// A startup failure must be diagnosable. The record has to carry the
    /// real exception type, its stack trace and every inner exception.
    /// Before the fix the diagnostic contained only GetType().FullName and
    /// Message, so the AggregateException raised by Task.Wait was recorded
    /// as "One or more errors occurred." and the actual cause was lost -
    /// which is why the 1053/1064 in the field was undiagnosable.
    /// </summary>
    [Fact]
    public void ServiceDiagnostics_WriteStartupFailure_IncludesStackTraceAndInnerException()
    {
        var dir = CreateTempDir();

        try
        {
            Exception captured;
            try
            {
                ThrowWrappedFailure();
                throw new InvalidOperationException("ThrowWrappedFailure did not throw.");
            }
            catch (Exception ex)
            {
                captured = ex;
            }

            ServiceDiagnostics.WriteStartupFailure(dir, captured);

            var content = File.ReadAllText(ServiceDiagnostics.ResolveLogFilePath(dir));

            // The real cause, reached through the AggregateException.
            Assert.Contains("ssp-inner-bind-cause", content);
            Assert.Contains("InvalidOperationException", content);
            Assert.Contains("AggregateException", content);
            Assert.Contains("SocketException", content);

            // A stack trace must be present.
            Assert.Contains("   at ", content);

            // Context needed to reproduce the failure under LocalSystem.
            Assert.Contains(dir, content);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// A gateway that dies after the service was already reported RUNNING
    /// must not fail silently: the accept loop exiting without a
    /// cancellation means the listener socket is gone while the SCM still
    /// shows the service as healthy.
    /// </summary>
    [Fact]
    public void ServiceDiagnostics_WriteGatewayFailure_RecordsPortAndCause()
    {
        var dir = CreateTempDir();

        try
        {
            ServiceDiagnostics.WriteGatewayFailure(
                dir, 4434, new SocketException((int)SocketError.ConnectionAborted));

            var content = File.ReadAllText(ServiceDiagnostics.ResolveLogFilePath(dir));

            Assert.Contains("gateway failed while running", content);
            Assert.Contains("GatewayPort=4434", content);
            Assert.Contains("SocketException", content);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// ResolveServiceName runs BEFORE ServiceBase.Run. Anything it throws
    /// kills the process before StartServiceCtrlDispatcher connects, and the
    /// SCM then reports ERROR 1053 with no diagnostic at all. It must
    /// therefore always return a usable name, whatever it is handed.
    /// </summary>
    [Fact]
    public void ResolveServiceName_NeverThrowsAndAlwaysReturnsAUsableName()
    {
        var missing = Path.Combine(Path.GetTempPath(), "ssp-missing-" + Guid.NewGuid().ToString("N"));

        // The ImagePath token the installer writes is used verbatim.
        Assert.Equal("SSP test2 4434",
            SspWindowsService.ResolveServiceName(missing, "SSP test2 4434"));

        // A blank token is not a name.
        Assert.False(string.IsNullOrWhiteSpace(
            SspWindowsService.ResolveServiceName(missing, "   ")));

        foreach (var serviceDir in new[] { missing, string.Empty, "   ", @"C:\" })
        {
            var name = SspWindowsService.ResolveServiceName(serviceDir, null);

            Assert.False(string.IsNullOrWhiteSpace(name), $"no name resolved for '{serviceDir}'.");
            Assert.True(name.Length <= ServiceBase.MaxNameLength);
            Assert.DoesNotContain('\\', name);
            Assert.DoesNotContain('/', name);
        }
    }

    /// <summary>
    /// With no ImagePath token, the name persisted by SetupEngine in
    /// .cache.dat is authoritative.
    /// </summary>
    [Fact]
    public void ResolveServiceName_FallsBackToConfiguredWindowsServiceName()
    {
        var dir = CreateTempDir();

        try
        {
            File.WriteAllText(
                Path.Combine(dir, ".cache.dat"),
                JsonSerializer.Serialize(new ServiceConfig
                {
                    ApplicationName    = "test2",
                    GatewayPort        = 4434,
                    WindowsServiceName = "SSP test2 4434",
                }, JsonOptions.Default));

            Assert.Equal("SSP test2 4434", SspWindowsService.ResolveServiceName(dir, null));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// A corrupt or partially written .cache.dat must degrade to a
    /// usable name, not abort the process before the SCM handshake.
    /// </summary>
    [Fact]
    public void ResolveServiceName_SurvivesCorruptServiceConfig()
    {
        var dir = CreateTempDir();

        try
        {
            File.WriteAllText(Path.Combine(dir, ".cache.dat"), "{ not json");

            var name = SspWindowsService.ResolveServiceName(dir, null);

            Assert.False(string.IsNullOrWhiteSpace(name));
            Assert.True(name.Length <= ServiceBase.MaxNameLength);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// ServiceBase.ServiceName rejects names longer than
    /// ServiceBase.MaxNameLength and names containing a path separator by
    /// throwing ArgumentException. That throw used to happen before
    /// ServiceBase.Run, which is how an over-long application name became an
    /// undiagnosable ERROR 1053.
    /// </summary>
    [Fact]
    public void SanitizeServiceName_ProducesANameServiceBaseAccepts()
    {
        var longName = new string('a', 200);

        var sanitized = SspWindowsService.SanitizeServiceName(longName);
        Assert.True(sanitized.Length <= ServiceBase.MaxNameLength);

        Assert.Equal("SSP test2 4434", SspWindowsService.SanitizeServiceName(@"  SSP\test2/4434  "));
        Assert.False(string.IsNullOrWhiteSpace(SspWindowsService.SanitizeServiceName("   ")));

        // The service host must accept every sanitized name. Assigning and
        // reading ServiceBase.ServiceName is Windows-only, so this half of the
        // test is guarded; the portable name sanitising above is not.
        if (OperatingSystem.IsWindows())
        {
            var service = new SspWindowsService(
                Path.GetTempPath(), SspWindowsService.SanitizeServiceName(longName));
            Assert.True(service.ServiceName.Length <= ServiceBase.MaxNameLength);

            // The limit SspWindowsService truncates against is a restatement
            // of the BCL constant (so that SanitizeServiceName stays callable
            // everywhere); pin the two together so they cannot drift apart.
            Assert.Equal(ServiceBase.MaxNameLength, SspWindowsService.MaxServiceNameLength);
        }
    }

    private static void ThrowWrappedFailure()
    {
        try
        {
            throw new SocketException((int)SocketError.AddressAlreadyInUse);
        }
        catch (Exception inner)
        {
            throw new AggregateException(
                "SSP gateway could not bind its listener",
                new InvalidOperationException("ssp-inner-bind-cause", inner));
        }
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-reg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>
    /// ServerGateway.RunAsync must complete ListenerReady BEFORE
    /// blocking on AcceptTcpClientAsync. This is the contract that
    /// SspWindowsService.OnStart relies on so Setup can observe
    /// RUNNING + a listening gateway without an extra sleep.
    /// </summary>
    [Fact]
    public async Task ServerGateway_ListenerReady_CompletesBeforeAccept()
    {
        var port = FreeTcpPort();
        var config = new ServiceConfig
        {
            ApplicationName        = "REG",
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = port,
            LocalApplicationPort   = 3389,
            ClientTunnelPort       = 3390,
        };

        using var rsa = RsaCrypto.GenerateKeyPair();
        var pubPem = RsaCrypto.ExportPublicKeyPem(rsa);
        var gateway = new ServerGateway(config, rsa, pubPem, "/tmp", UnlicensedTestGate.Instance);

        using var cts = new CancellationTokenSource();
        var runTask = gateway.RunAsync(cts.Token);

        // ListenerReady must complete within a short timeout. Before
        // the fix this would hang forever because the gateway would
        // block on AcceptTcpClientAsync before signaling readiness.
        await gateway.ListenerReady.WaitAsync(TimeSpan.FromSeconds(5));

        // Sanity check: the port must now be bound.
        Assert.True(IsPortBound(port));

        cts.Cancel();
        await Task.WhenAny(runTask, Task.Delay(2000));
    }

    /// <summary>
    /// If the gateway fails to bind (e.g. port already in use),
    /// ListenerReady must propagate the exception rather than hang.
    /// This ensures SspWindowsService.OnStart reports the failure to
    /// the SCM instead of timing out.
    /// </summary>
    [Fact]
    public async Task ServerGateway_ListenerReady_PropagatesExceptionOnBindFailure()
    {
        var port = FreeTcpPort();

        // Occupy the port so the gateway cannot bind it.
        using var blocker = new TcpListener(IPAddress.Any, port);
        blocker.Start();

        var config = new ServiceConfig
        {
            ApplicationName        = "REG2",
            GatewayPublicIpAddress = "127.0.0.1",
            GatewayPort            = port,
            LocalApplicationPort   = 3389,
            ClientTunnelPort       = 3390,
        };

        using var rsa = RsaCrypto.GenerateKeyPair();
        var pubPem = RsaCrypto.ExportPublicKeyPem(rsa);
        var gateway = new ServerGateway(config, rsa, pubPem, "/tmp", UnlicensedTestGate.Instance);

        using var cts = new CancellationTokenSource();
        var runTask = gateway.RunAsync(cts.Token);

        // ListenerReady must complete with an exception, not hang.
        await Assert.ThrowsAnyAsync<Exception>(
            () => gateway.ListenerReady.WaitAsync(TimeSpan.FromSeconds(5)));

        cts.Cancel();
        await Task.WhenAny(runTask, Task.Delay(2000));
    }

    /// <summary>
    /// On an elevated Windows runner, exercise the actual SCM path rather
    /// than only the ServerGateway/ServiceBase seam. Setup must return only
    /// after the newly-created service is RUNNING and its gateway listener
    /// is present. Non-Windows and non-elevated runners retain the portable
    /// contract tests above; production installation is never downgraded to
    /// success when sc.exe reports access denied.
    /// </summary>
    [Fact]
    public async Task SetupEngine_WhenElevated_CreatesRealRunningServiceWithListeningGateway()
    {
        if (!OperatingSystem.IsWindows() || !IsElevatedWindowsProcess())
            return;

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var applicationName = $"REG{suffix}";
        var gatewayPort = FreeTcpPort();
        var serviceName = $"SSP {applicationName} {gatewayPort}";
        var serviceDirectory = Path.Combine(
            Path.GetTempPath(), $"ssp-service-regression-{suffix}");
        Directory.CreateDirectory(serviceDirectory);

        try
        {
            var engine = new SetupEngine(UnlicensedTestGate.Instance);
            await engine.RunAsync(new SetupParameters
            {
                ApplicationName        = applicationName,
                GatewayPublicIpAddress = "127.0.0.1",
                GatewayPort            = gatewayPort,
                LocalApplicationPort   = FreeTcpPort(),
                ClientTunnelPort       = FreeTcpPort(),
                ServiceDirectory       = serviceDirectory,
                InstallWindowsService  = true,
            });

            Assert.True(
                engine.Result.Success,
                "Elevated Windows setup did not create and start a ready SCM service.");

            using var controller = new ServiceController(serviceName);
            controller.Refresh();
            Assert.Equal(ServiceControllerStatus.Running, controller.Status);

            Assert.Contains(
                IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners(),
                endpoint => endpoint.Port == gatewayPort);
        }
        finally
        {
            StopAndDeleteService(serviceName);
            try { Directory.Delete(serviceDirectory, recursive: true); } catch { }
        }
    }

    private static bool IsElevatedWindowsProcess()
    {
        // WindowsIdentity/WindowsPrincipal are Windows-only APIs. Callers use
        // this to decide whether the real SCM path can be exercised, and
        // there is no SCM anywhere else.
        if (!OperatingSystem.IsWindows())
            return false;

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity)
            .IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void StopAndDeleteService(string serviceName)
    {
        // Stopping through ServiceController is the Windows SCM client, so
        // only that half of the cleanup is platform-gated; the sc.exe delete
        // below is best effort and portable on its own.
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var controller = new ServiceController(serviceName);
                controller.Refresh();
                if (controller.Status != ServiceControllerStatus.Stopped)
                {
                    controller.Stop();
                    controller.WaitForStatus(
                        ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                }
            }
            catch (InvalidOperationException)
            {
                // The create step may have failed before a service existed.
            }
            catch (System.ServiceProcess.TimeoutException ex)
            {
                Console.Error.WriteLine(
                    $"[test-cleanup] service '{serviceName}' did not stop: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"[test-cleanup] could not stop service '{serviceName}': {ex.Message}");
            }
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("delete");
            startInfo.ArgumentList.Add(serviceName);
            using var process = Process.Start(startInfo);
            process?.WaitForExit();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[test-cleanup] could not delete service '{serviceName}': {ex.Message}");
        }
    }

    private static int FreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static bool IsPortBound(int port)
    {
        try
        {
            using var client = new TcpClient();
            client.Connect(IPAddress.Loopback, port);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
