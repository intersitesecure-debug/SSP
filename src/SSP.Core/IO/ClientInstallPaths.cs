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
    /// The <em>canonical</em> product root: C:\Program Files\SSP (resolved
    /// through .NET). Always the real machine-wide product installation.
    /// <para>
    /// This accessor deliberately ignores
    /// <see cref="EnvironmentRootOverrideVariable"/>. The override is a
    /// <em>client connection-state</em> test seam, not a general "where is
    /// SSP installed" seam, so code that must locate the canonical product
    /// root (for example the activation/licensing subsystem, which has its
    /// own dedicated <c>SSP_LICENSE_ROOT</c> seam) must use this method and
    /// never inherit the client test redirect.
    /// </para>
    /// </summary>
    public static string GetCanonicalProductRoot()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return Path.Combine(programFiles, ProductDirectoryName);
    }

    /// <summary>
    /// Product root that holds <em>client connection state</em>: the
    /// canonical product root, or the test override when
    /// <see cref="EnvironmentRootOverrideVariable"/> is set.
    /// <para>
    /// The override value is returned verbatim (unnormalized), exactly as
    /// callers set it. Use <see cref="GetCanonicalProductRoot"/> when the
    /// canonical machine location - not the redirected test location - is
    /// what matters.
    /// </para>
    /// </summary>
    public static string GetProductRoot()
    {
        var overrideRoot = Environment.GetEnvironmentVariable(EnvironmentRootOverrideVariable);
        if (!string.IsNullOrWhiteSpace(overrideRoot))
            return overrideRoot;

        return GetCanonicalProductRoot();
    }

    /// <summary>
    /// Canonical root of all per-connection state:
    /// C:\Program Files\SSP\connections (or the test override root).
    /// </summary>
    public static string GetConnectionsRoot() =>
        Path.Combine(GetProductRoot(), ConnectionsDirectoryName);
}
