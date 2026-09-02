// File: src/SSP.Server/ServiceHost/SspWindowsService.cs
//
// Windows Service host. Wraps a ServerGateway inside a ServiceBase so
// the gateway can be managed by the Windows Service Control Manager.
//
// On non-Windows platforms this class compiles but cannot run; the caller
// falls back to the foreground --run-once mode instead.
//
// ========================================================================
// SCM START CONTRACT (ERROR 1053 vs ERROR 1064)
// ========================================================================
//
// The SCM reports two different failures and they have different causes:
//
//   ERROR 1053 - "The service did not respond to the start or control
//   request in a timely fashion." Reported when the service process
//   disappears (or throws) BEFORE StartServiceCtrlDispatcher has
//   connected, or when the service stays in SERVICE_START_PENDING longer
//   than the budget derived from SERVICE_STATUS.dwWaitHint / dwCheckPoint.
//   Nothing at all reaches the Application event log through AutoLog in
//   this case, because ServiceBase.EventLog only becomes usable once the
//   dispatcher is connected. This is the classic *und diagnosable* failure.
//
//   ERROR 1064 - ERROR_EXCEPTION_IN_SERVICE. Reported by
//   ServiceBase.ServiceMainCallback when an exception escapes OnStart
//   (it sets _status.win32ExitCode = ERROR_EXCEPTION_IN_SERVICE and then
//   ServiceBase.Run rethrows the captured exception).
//
// Both are avoided by the same two rules, which this type now enforces:
//
//   1. NOTHING that can throw runs before ServiceBase.Run. Not the read
//      of .cache.dat, not the JSON parse, and not the assignment
//      of ServiceName from an unvalidated name. Everything fallible is
//      inside OnStart, where the SCM already has a dispatcher to talk to
//      and a failure is reported as a *diagnosed* failed start instead of
//      an opaque 1053.
//
//   2. OnStart advertises how long the bring-up may take by calling
//      RequestAdditionalTime, and re-arms it while it waits for the
//      gateway listener. ServiceBase.Initialize() leaves dwWaitHint = 0
//      and dwCheckPoint = 0, so without this the SCM applies its fixed
//      default budget, which on Windows Server 2022 has to absorb
//      single-file bundle extraction under LocalSystem, CLR/JIT startup
//      and RSA-3072 key import. Re-arming also increments dwCheckPoint,
//      which is the documented signal that a start is progressing rather
//      than hung. This is entirely in-process: no SCM timeout value, no
//      ServicesPipeTimeout, no registry key is read or written anywhere.
//
// Every failure on this path is additionally recorded in full (type,
// message, stack trace, inner exceptions) through ServiceDiagnostics.

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.ServiceProcess;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Server.Activation;
using SSP.Server.Runtime;

namespace SSP.Server.ServiceHost;

public sealed class SspWindowsService : ServiceBase
{
    /// <summary>
    /// Maximum length the SCM accepts for a service name. This mirrors
    /// <c>ServiceBase.MaxNameLength</c>, restated as a plain constant because
    /// that BCL member is annotated Windows-only while
    /// <see cref="SanitizeServiceName"/> must stay callable from every
    /// platform (the portable name-resolution tests use it).
    /// <c>SanitizeServiceName_ProducesANameServiceBaseAccepts</c> pins the two
    /// values together on Windows so they cannot drift apart.
    /// </summary>
    internal const int MaxServiceNameLength = 80;

    /// <summary>
    /// Wait hint advertised to the SCM while OnStart brings the gateway up.
    /// </summary>
    private const int StartWaitHintMs = 60_000;

    /// <summary>
    /// How often the wait hint is re-armed while waiting for the listener.
    /// Each call also increments SERVICE_STATUS.dwCheckPoint.
    /// </summary>
    private const int CheckpointIntervalMs = 5_000;

    /// <summary>
    /// Absolute ceiling for waiting on the gateway listener. Comfortably
    /// inside <see cref="StartWaitHintMs"/> so a failure is reported by us,
    /// with a diagnosis, rather than by the SCM killing the process.
    /// </summary>
    private const int ListenerReadyTimeoutMs = 25_000;

    private readonly ServiceConfig? _preloadedConfig;
    private readonly string _serviceDir;
    private readonly CancellationTokenSource _cts = new();

    private RSA? _rsa;
    private ServerGateway? _gateway;
    private int _gatewayPort;

    /// <summary>
    /// The licensing runtime for this service, created inside OnStart once the
    /// SCM dispatcher is connected. It owns the periodic license refresh and is
    /// disposed by OnStop; the gateway holds a reference to it for the whole
    /// connection lifetime, so it must outlive the accept loop.
    /// </summary>
    private SspRuntimeLicense? _license;

    /// <summary>
    /// Background task that runs the gateway accept loop. Held so OnStop
    /// can wait for the gateway to release its listener socket before
    /// returning control to the SCM.
    /// </summary>
    private Task? _gatewayTask;

    /// <summary>
    /// Completed as soon as the gateway has bound its listener socket.
    /// OnStart waits on this before returning, so the SCM only considers
    /// the service "started" once the TCP listener is actually accepting
    /// connections. Created with RunContinuationsAsynchronously so a
    /// synchronous TrySetResult inside AcceptLoopAsync cannot run the
    /// waiting continuation on the listener thread.
    /// </summary>
    private readonly TaskCompletionSource _listenerReady =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Set once OnStop has been invoked, so the gateway loop can tell a
    /// requested shutdown apart from a genuine failure.
    /// </summary>
    private volatile bool _stopping;

    /// <summary>
    /// Production SCM start path. Takes only values already known from the
    /// ImagePath command line, so construction cannot throw on a missing,
    /// unreadable or malformed .cache.dat - that work belongs in
    /// OnStart, after the dispatcher has connected to the SCM.
    ///
    /// Windows-only because the SCM options it sets (ServiceName, AutoLog,
    /// CanStop, CanPauseAndContinue) are ServiceBase members; every call site
    /// is behind an <c>OperatingSystem.IsWindows()</c> check.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public SspWindowsService(string serviceDir, string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
            throw new ArgumentException("Windows service name is required.", nameof(serviceName));

        _serviceDir = Path.GetFullPath(serviceDir);
        ServiceName = serviceName;
        AutoLog = true;
        CanStop = true;
        CanPauseAndContinue = false;
    }

    /// <summary>
    /// Test / foreground seam: the configuration is already in memory, so
    /// OnStart does not have to read .cache.dat.
    ///
    /// Windows-only for the same reason as the other constructor: it hands
    /// the sanitized name to ServiceBase's SCM options.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public SspWindowsService(ServiceConfig config, string serviceDir)
    {
        _preloadedConfig = config;
        _serviceDir = Path.GetFullPath(serviceDir);
        ServiceName = SanitizeServiceName(
            string.IsNullOrWhiteSpace(config.WindowsServiceName)
                ? $"SSP {config.ApplicationName} {config.GatewayPort}"
                : config.WindowsServiceName!);
        AutoLog = true;
        CanStop = true;
        CanPauseAndContinue = false;
    }

    /// <summary>
    /// Resolve the SCM service name without ever throwing.
    ///
    /// This runs BEFORE ServiceBase.Run, i.e. before the process is
    /// connected to the SCM. Anything that escapes from here kills the
    /// process with no dispatcher, no AutoLog entry and no service status,
    /// which the operator sees as ERROR 1053 with nothing to go on. The
    /// previous implementation read and parsed .cache.dat here and
    /// assigned the result straight to ServiceBase.ServiceName - both can
    /// throw (missing file, malformed JSON, a name longer than
    /// <see cref="ServiceBase.MaxNameLength"/> or containing a path
    /// separator, which ServiceBase rejects with ArgumentException).
    /// </summary>
    internal static string ResolveServiceName(string serviceDir, string? nameFromImagePath)
    {
        // 1. The token the ImagePath command line carries. WindowsServiceInstaller
        //    always writes it, so this is the normal production path.
        if (!string.IsNullOrWhiteSpace(nameFromImagePath))
            return SanitizeServiceName(nameFromImagePath);

        // 2. Best effort: the name SetupEngine persisted in .cache.dat.
        try
        {
            var configPath = Path.Combine(Path.GetFullPath(serviceDir), ".cache.dat");
            if (File.Exists(configPath))
            {
                var config = ServiceConfigStore.LoadAsync(configPath).GetAwaiter().GetResult();

                if (!string.IsNullOrWhiteSpace(config.WindowsServiceName))
                    return SanitizeServiceName(config.WindowsServiceName);

                if (!string.IsNullOrWhiteSpace(config.ApplicationName))
                    return SanitizeServiceName($"SSP {config.ApplicationName} {config.GatewayPort}");
            }
        }
        catch
        {
            // A config problem must never abort the process before the
            // dispatcher connects. OnStart reports it properly.
        }

        // 3. Derive something unique from the service directory itself.
        try
        {
            var leaf = Path.GetFileName(
                Path.GetFullPath(serviceDir)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

            if (!string.IsNullOrWhiteSpace(leaf))
                return SanitizeServiceName($"SSP {leaf}");
        }
        catch
        {
            // fall through
        }

        // 4. Last resort: still a valid name, so ServiceBase.Run is reached
        //    and the real failure is reported from OnStart.
        try
        {
            var exe = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? string.Empty);
            if (!string.IsNullOrWhiteSpace(exe))
                return SanitizeServiceName(exe);
        }
        catch
        {
            // fall through
        }

        return "SSP.Server";
    }

    /// <summary>
    /// Make a name acceptable to <c>ServiceBase.ServiceName</c>, which
    /// rejects names longer than <see cref="ServiceBase.MaxNameLength"/>
    /// and names containing '\' or '/'. The setter throws ArgumentException
    /// for those, and a throw here happens before the SCM handshake.
    ///
    /// The limit is read from <see cref="MaxServiceNameLength"/> - the same
    /// value, restated so that this name sanitiser stays callable from
    /// non-Windows code paths while <c>ServiceBase.ServiceName</c> itself is
    /// only ever assigned on Windows.
    /// </summary>
    internal static string SanitizeServiceName(string? name)
    {
        var sanitized = (name ?? string.Empty).Trim().Replace('\\', ' ').Replace('/', ' ');

        if (sanitized.Length > MaxServiceNameLength)
            sanitized = sanitized[..MaxServiceNameLength].TrimEnd();

        return string.IsNullOrWhiteSpace(sanitized) ? "SSP.Server" : sanitized;
    }

    /// <summary>
    /// SCM start callback. Windows-only by contract: it is invoked by
    /// ServiceBase after the dispatcher has connected to the SCM, and it
    /// advertises/re-arms the start wait hint through ServiceBase.
    /// </summary>
    [SupportedOSPlatform("windows")]
    protected override void OnStart(string[] args)
    {
        base.OnStart(args);

        // Announce the start budget. ServiceBase.Initialize() sets
        // dwWaitHint = 0 / dwCheckPoint = 0, so without this the SCM
        // applies its fixed default budget and reports ERROR 1053 while a
        // cold start under LocalSystem is still perfectly healthy.
        TryRequestAdditionalTime();

        ServerGateway gateway;
        try
        {
            var config = LoadConfig();
            _gatewayPort = config.GatewayPort;

            // EP1 - service startup licensing gate, on the SCM path.
            //
            // This is inside OnStart, i.e. inside the existing fallible region
            // whose failure is recorded through ServiceDiagnostics and rethrown
            // as a DIAGNOSED failed start (ERROR 1064). The ERROR 1053 contract
            // is untouched: nothing fallible - not this, not the config read,
            // not the key import - runs before ServiceBase.Run connects the
            // dispatcher.
            //
            // Fail closed: CreateForService throws unless this build carries a
            // compiled-in Licensing Authority trust anchor AND the license
            // validates to Valid AND the protected protocol is in the licensed
            // feature set AND max_services is not exhausted. An unlicensed
            // service therefore never binds its gateway port, and the operator
            // gets the license reason code in ssp-service-startup.log and the
            // Application event log instead of a service that appears to be
            // running while silently unprotected.
            //
            // CreateForService also owns the periodic license refresh: it starts
            // the timer only after the runtime has been proven licensed, and
            // OnStop disposes it with the service.
            _license = SspRuntimeLicense.CreateForService(config, _serviceDir);

            var privPath = Path.Combine(_serviceDir, config.ServerPrivateKeyPath);
            var privPem = PemStore.LoadPrivateKeyAsync(privPath).GetAwaiter().GetResult();
            _rsa = RsaCrypto.ImportPrivateKeyPem(privPem);

            var pubPath = Path.Combine(_serviceDir, config.ServerPublicKeyPath);
            var pubPem = PemStore.LoadPublicKeyAsync(pubPath).GetAwaiter().GetResult();

            gateway = new ServerGateway(config, _rsa, pubPem, _serviceDir, _license);
            _gateway = gateway;
        }
        catch (Exception ex)
        {
            _rsa?.Dispose();
            _rsa = null;
            _gateway = null;
            _license?.Dispose();
            _license = null;

            // Rethrowing reports a failed start to the SCM (ERROR 1064).
            // Record the real cause first so the 1064 is never opaque.
            ServiceDiagnostics.WriteStartupFailure(_serviceDir, ex);
            throw;
        }

        _gatewayTask = Task.Run(() => RunGatewayAsync(gateway, _cts.Token));

        try
        {
            WaitForListenerReady();
        }
        catch (Exception ex)
        {
            // Signal the gateway to stop and rethrow so the SCM records the
            // service as failed instead of "running but broken".
            _cts.Cancel();
            ServiceDiagnostics.WriteStartupFailure(_serviceDir, ex);
            throw;
        }
    }

    private ServiceConfig LoadConfig()
    {
        if (_preloadedConfig is not null)
            return _preloadedConfig;

        var configPath = Path.Combine(_serviceDir, ".cache.dat");
        return ServiceConfigStore.LoadAsync(configPath).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Block until the gateway listener is bound, re-arming the SCM wait
    /// hint on every interval so the start is reported as progressing.
    /// </summary>
    private void WaitForListenerReady()
    {
        var ready = _listenerReady.Task;
        var elapsedMs = 0;

        while (!ready.Wait(CheckpointIntervalMs))
        {
            elapsedMs += CheckpointIntervalMs;
            if (elapsedMs >= ListenerReadyTimeoutMs)
            {
                throw new System.TimeoutException(
                    $"SSP gateway did not bind its listener on port {_gatewayPort} within " +
                    $"{ListenerReadyTimeoutMs / 1000} seconds.");
            }

            // Also increments dwCheckPoint - the SCM's signal that the
            // start is still making progress.
            TryRequestAdditionalTime();
        }

        // Propagate the real exception instead of the AggregateException
        // wrapper Task.Wait produces; the wrapper's Message is the useless
        // "One or more errors occurred."
        ready.GetAwaiter().GetResult();
    }

    private void TryRequestAdditionalTime()
    {
        // RequestAdditionalTime is a ServiceBase call into the SCM
        // dispatcher. Outside Windows there is no dispatcher to advertise a
        // wait hint to, and the foreground/--run-once host never connects one.
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            RequestAdditionalTime(StartWaitHintMs);
        }
        catch (InvalidOperationException)
        {
            // RequestAdditionalTime throws when the service is not in a
            // pending state. Nothing to advertise in that case.
        }
    }

    /// <summary>
    /// Run the gateway. ServerGateway signals <c>_listenerReady</c> from
    /// inside its accept loop as soon as TcpListener.Start returns.
    /// </summary>
    private async Task RunGatewayAsync(ServerGateway gateway, CancellationToken ct)
    {
        try
        {
            await gateway.RunAsync(ct, _listenerReady).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_stopping)
        {
            // Normal shutdown path.
        }
        catch (Exception ex)
        {
            // Unblock OnStart if the listener never came up.
            _listenerReady.TrySetException(ex);

            if (_stopping)
                return;

            // The accept loop died while the SCM still believes the service
            // is RUNNING and the gateway port is open. That must not be
            // silent: record the full exception. Rethrowing here is
            // deliberately avoided - a faulted Task nobody awaits only
            // resurfaces much later as an unobserved task exception with no
            // SCM diagnostic attached, which is how the failure became
            // invisible in the first place.
            ServiceDiagnostics.WriteGatewayFailure(_serviceDir, _gatewayPort, ex);
        }
    }

    /// <summary>
    /// SCM stop callback. Windows-only by contract, like
    /// <see cref="OnStart"/>: the base implementation completes the SERVICE_STOPPED
    /// transition the SCM is waiting for.
    /// </summary>
    [SupportedOSPlatform("windows")]
    protected override void OnStop()
    {
        _stopping = true;
        _cts.Cancel();

        // Wait briefly for the gateway to release the listener socket so the
        // SCM does not see a port still bound after STOPPED.
        var gatewayTask = _gatewayTask;
        if (gatewayTask is not null)
        {
            try
            {
                gatewayTask.Wait(TimeSpan.FromSeconds(10));
            }
            catch
            {
                // Stopping anyway. A fault was already recorded by
                // RunGatewayAsync, so there is nothing to swallow here.
            }
        }

        try { _rsa?.Dispose(); } catch { /* best effort */ }
        _rsa = null;

        // Dispose the licensing runtime only after the accept loop has stopped
        // and the RSA key is gone: connections still in flight consult the gate,
        // and the gate owns the periodic license refresh plus the trust anchor.
        // Disposing it here stops the timer (joining an in-flight refresh) so no
        // license work continues after the service reports STOPPED.
        try { _license?.Dispose(); } catch { /* best effort */ }
        _license = null;

        base.OnStop();
    }
}
