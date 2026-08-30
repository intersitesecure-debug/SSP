// File: tests/SSP.Tests/AssemblyInfo.cs
//
// Disable test parallelization. The enrollment tests redirect
// Console.In / Console.Out, which is a process-global resource and
// cannot be safely parallelized.

using System.Runtime.CompilerServices;
using SSP.Core.IO;
using SSP.Server.Runtime;
using SSP.Server.UI;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

internal static class TestAssemblyInit
{
    /// <summary>
    /// Runs once before any test in the assembly. The server normally
    /// shows a native MB_SERVICE_NOTIFICATION dialog during enrollment,
    /// which would block a headless CI agent (especially on Windows).
    /// Suppress it process-wide; the Console banner remains and is what
    /// the in-process harness reads to obtain the AuthCode.
    /// </summary>
    [ModuleInitializer]
    internal static void Initialize()
    {
        Environment.SetEnvironmentVariable(
            AuthenticationCodeDialog.SuppressEnvironmentVariable, "1");

        // Redirect the administrator readout file away from
        // C:\Program Files\SSP so in-process enrollment tests do
        // not require elevation and do not leave files behind.
        Environment.SetEnvironmentVariable(
            AuthenticationCodeFile.DirectoryOverrideVariable,
            Path.Combine(Path.GetTempPath(), "ssp-authcode-tests"));

        // Redirect the canonical client connections root away from
        // C:\Program Files\SSP\connections so in-process tests do not
        // require elevation and do not leave files behind. Individual
        // tests that need an isolated root use ClientConnectionRootScope
        // (safe: test parallelization is disabled).
        Environment.SetEnvironmentVariable(
            ClientInstallPaths.EnvironmentRootOverrideVariable,
            Path.Combine(Path.GetTempPath(), "ssp-client-root-tests"));
    }
}
