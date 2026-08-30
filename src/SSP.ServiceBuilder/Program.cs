// File: src/SSP.ServiceBuilder/Program.cs
//
// SSP.ServiceBuilder.exe
//
// Standalone CLI tool that creates new SSP gateway services by
// invoking the SSP.Server SETUP MODE engine.
//
// Usage:
//   dotnet SSP.ServiceBuilder.dll --name RDP --ip 1.2.3.4 \
//       --gateway-port 4433 --app-port 3389 --tunnel-port 3390 \
//       --service-dir /var/lib/ssp/RDP
//
// On Windows the ServiceBuilder also registers the resulting service
// with the Service Control Manager (the SetupEngine handles that
// automatically when running on Windows).

using System.CommandLine;
using SSP.Core.Models;
using SSP.Server.Setup;

namespace SSP.ServiceBuilder;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var nameOpt   = new Option<string>("--name", "Application name (RDP, WEB, SSH, ...)") { IsRequired = true };
        var ipOpt     = new Option<string>("--ip", "Gateway public IP address") { IsRequired = true };
        var gPortOpt  = new Option<int>("--gateway-port", "Gateway TCP port") { IsRequired = true };
        var aPortOpt  = new Option<int>("--app-port", "Local protected application port") { IsRequired = true };
        var tPortOpt  = new Option<int>("--tunnel-port", "Client local tunnel port") { IsRequired = true };
        var dirOpt    = new Option<string?>("--service-dir", "Optional service output directory") { IsRequired = false };
        var clientNameOpt = new Option<string?>("--client-name", "Optional client name (Client01, Client02, ...)") { IsRequired = false };

        var root = new RootCommand("SSP Service Builder");
        root.AddOption(nameOpt);
        root.AddOption(ipOpt);
        root.AddOption(gPortOpt);
        root.AddOption(aPortOpt);
        root.AddOption(tPortOpt);
        root.AddOption(dirOpt);
        root.AddOption(clientNameOpt);

        root.SetHandler(async ctx =>
        {
            var name   = ctx.ParseResult.GetValueForOption(nameOpt)!;
            var ip     = ctx.ParseResult.GetValueForOption(ipOpt)!;
            var gPort  = ctx.ParseResult.GetValueForOption(gPortOpt);
            var aPort  = ctx.ParseResult.GetValueForOption(aPortOpt);
            var tPort  = ctx.ParseResult.GetValueForOption(tPortOpt);
            var dir    = ctx.ParseResult.GetValueForOption(dirOpt);
            var cName  = ctx.ParseResult.GetValueForOption(clientNameOpt);

            var parameters = new SetupParameters
            {
                ApplicationName        = name,
                GatewayPublicIpAddress = ip,
                GatewayPort            = gPort,
                LocalApplicationPort   = aPort,
                ClientTunnelPort       = tPort,
                ServiceDirectory       = dir,
                ClientName             = cName,
            };

            var engine = new SetupEngine();
            await engine.RunAsync(parameters);

            Console.WriteLine();
            Console.WriteLine(engine.Result.Success
                ? $"Service '{name}' created at {engine.Result.ServiceDirectory}"
                : $"Service '{name}' setup FAILED at {engine.Result.ServiceDirectory}");
            Console.WriteLine($"  Gateway    : {ip}:{gPort} -> 127.0.0.1:{aPort}");
            Console.WriteLine($"  Tunnel port: {tPort}");
            Console.WriteLine($"  Client exe : {engine.Result.ClientExecutablePath}");
            Console.WriteLine($"  One-Time Token: {engine.Result.OneTimeToken}");
            if (engine.Result.WindowsServiceName != null)
                Console.WriteLine($"  Service    : {engine.Result.WindowsServiceName}");

            // A failed sc create/start or readiness check is a failed setup,
            // not a successful artifact-generation run.
            ctx.ExitCode = engine.Result.Success ? 0 : 1;
        });

        if (args.Length == 0)
        {
            await root.InvokeAsync("--help");
            return 0;
        }
        return await root.InvokeAsync(args);
    }
}
