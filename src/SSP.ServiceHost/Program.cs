// File: src/SSP.ServiceHost/Program.cs
//
// SSP.ServiceHost.exe - the standalone Windows Service image.
//
// SCM starts this executable with the command line that
// WindowsServiceInstaller stores as the service ImagePath:
//
//     SSP.ServiceHost.exe --service <serviceDir> [serviceName]
//
// and the service is served for as long as the SCM wants. The file lives
// inside the service directory it was created for and belongs to no other
// service, so a created service is independent of the setup executable
// (C:\Program Files\SSP\SSP.Server.exe). That file is only the tool used
// to create/install services; it may be moved or deleted immediately
// after creation without affecting the service.
//
// The service logic is NOT duplicated here. All mode handling - the SCM
// fast path with its ERROR 1053 contract (see
// src/SSP.Server/ServiceHost/SspWindowsService.cs), the deferred config
// read, the RSA import, the gateway and the foreground --run-once mode -
// is delegated verbatim into SSP.Server.Program.Main, which is the exact
// entry code an `SSP.Server.exe --service` launch runs. Keeping one
// implementation guarantees that config, encryption, gateway and client
// generation behaviour are byte-for-byte the established ones.
//
// Like the server entry point itself, nothing fallible may run before
// ServiceBase.Run connects to the SCM; the delegation below preserves
// that because Program.Main's --service fast path goes straight to
// ServiceBase.Run without touching the file system first.

namespace SSP.ServiceHost;

internal static class Program
{
    /// <summary>
    /// The only modes this image serves. Anything else is a configuration
    /// error in the ImagePath (or a manual console launch), and must not
    /// silently turn the service host into a second setup tool.
    /// </summary>
    private static readonly string[] ServiceModes = ["--service", "--run-once"];

    public static Task<int> Main(string[] args) => RunAsync(args);

    /// <summary>
    /// Separated from Main so the unit tests can exercise the mode gate on
    /// every platform without entering the foreground service loop.
    /// </summary>
    internal static async Task<int> RunAsync(string[] args)
    {
        var mode = args.Length > 0 ? args[0] : string.Empty;
        if (!ServiceModes.Contains(mode, StringComparer.Ordinal))
        {
            Console.Error.WriteLine(
                "SSP.ServiceHost.exe is the standalone Windows Service image created by SSP Setup; " +
                "it only runs services.");
            Console.Error.WriteLine("Usage: SSP.ServiceHost.exe --service <serviceDirectory> [serviceName]");
            Console.Error.WriteLine("       SSP.ServiceHost.exe --run-once <serviceDirectory>");
            Console.Error.WriteLine("To create or provision a service, run SSP.Server.exe and use SETUP MODE.");
            return 2;
        }

        // Same entry point, same behaviour: this is exactly the code an
        // SSP.Server.exe --service / --run-once launch would execute.
        return await SSP.Server.Program.Main(args).ConfigureAwait(false);
    }
}
