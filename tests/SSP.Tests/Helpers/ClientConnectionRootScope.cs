// File: tests/SSP.Tests/Helpers/ClientConnectionRootScope.cs
//
// Per-test redirect of the canonical client root
// (C:\Program Files\SSP, and its connections folder) to a fresh
// temporary directory, so a test gets an isolated, machine-wide
// connection state and cleans itself up on dispose.
//
// Safe process-wide because test parallelization is disabled
// (see tests/SSP.Tests/AssemblyInfo.cs).

using SSP.Core.IO;

namespace SSP.Tests.Helpers;

public sealed class ClientConnectionRootScope : IDisposable
{
    private readonly string? _previousOverride;

    /// <summary>The temporary product root (C:\Program Files\SSP stand-in).</summary>
    public string ProductRoot { get; }

    /// <summary>The temporary connections root ({ProductRoot}/connections).</summary>
    public string ConnectionsRoot =>
        Path.Combine(ProductRoot, ClientInstallPaths.ConnectionsDirectoryName);

    public ClientConnectionRootScope(string? baseDirectory = null)
    {
        var baseDir = string.IsNullOrWhiteSpace(baseDirectory)
            ? Path.GetTempPath()
            : baseDirectory;

        ProductRoot = Path.Combine(baseDir, "client-root-" + Guid.NewGuid().ToString("N"));

        // Environment.SetEnvironmentVariable returns void on .NET Core and
        // later (only the .NET Framework overload handed back the previous
        // value), so the value to restore on Dispose must be read first.
        _previousOverride = Environment.GetEnvironmentVariable(
            ClientInstallPaths.EnvironmentRootOverrideVariable);
        Environment.SetEnvironmentVariable(
            ClientInstallPaths.EnvironmentRootOverrideVariable, ProductRoot);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(
            ClientInstallPaths.EnvironmentRootOverrideVariable, _previousOverride);

        try { Directory.Delete(ProductRoot, recursive: true); }
        catch { /* best effort */ }
    }
}
