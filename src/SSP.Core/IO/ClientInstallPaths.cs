// File: src/SSP.Core/IO/ClientInstallPaths.cs
//
// Canonical on-disk locations of the CLIENT product.
//
// Every file and folder that SSP.Client.*.exe creates for its
// runtime / connection state lives under the canonical product root
// C:\Program Files\SSP - NOT next to the launched executable:
//
//   C:\Program Files\SSP\
//   ├── SSP.Client.*.exe                          (the canonical executables)
//   └── connections\
//       ├── {ConnectionId}\.cache.dat             (client private key, encrypted at rest)
//       ├── {ConnectionId}\.index.dat             (client public key, encrypted at rest)
//       └── {ConnectionId}\.runtime.dat           (per-connection profile, encrypted at rest)
//
// One machine therefore has exactly ONE state per ConnectionId, no
// matter which folder the executable was launched from. The
// ConnectionId structure, the file names and the encryption of the
// files are unchanged by the canonical location - only the root is.

namespace SSP.Core.IO;

/// <summary>
/// Canonical client installation locations (C:\Program Files\SSP and
/// its connections folder).
/// </summary>
public static class ClientInstallPaths
{
    /// <summary>Product directory name inside Program Files.</summary>
    public const string ProductDirectoryName = "SSP";

    /// <summary>Directory under the product root holding all connection folders.</summary>
    public const string ConnectionsDirectoryName = "connections";

    /// <summary>
    /// When set, the product root (and therefore the connections root)
    /// is redirected to this directory instead of
    /// C:\Program Files\SSP. Used by tests so they never touch
    /// Program Files.
    /// </summary>
    public const string EnvironmentRootOverrideVariable = "SSP_CLIENT_ROOT";

    /// <summary>
    /// Canonical product root: C:\Program Files\SSP (resolved through
    /// .NET), or the test override when
    /// <see cref="EnvironmentRootOverrideVariable"/> is set.
    /// </summary>
    public static string GetProductRoot()
    {
        var overrideRoot = Environment.GetEnvironmentVariable(EnvironmentRootOverrideVariable);
        if (!string.IsNullOrWhiteSpace(overrideRoot))
            return overrideRoot;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return Path.Combine(programFiles, ProductDirectoryName);
    }

    /// <summary>
    /// Canonical root of all per-connection state:
    /// C:\Program Files\SSP\connections (or the test override root).
    /// </summary>
    public static string GetConnectionsRoot() =>
        Path.Combine(GetProductRoot(), ConnectionsDirectoryName);
}
