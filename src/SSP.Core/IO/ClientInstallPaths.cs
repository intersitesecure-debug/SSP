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
// All three files are protected with DPAPI CurrentUser scope on Windows
// (see ClientConnectionProtectionScope below), because the client is a
// desktop application: the same interactive user both creates the
// client identity and reads it back, and no other local account may be
// able to recover the private key - not even by reading the file bytes,
// which C:\Program Files inherits as world-readable (Phase 3 / M-2 of
// the Security Correction roadmap).
//
// One machine therefore has exactly ONE state per ConnectionId, no
// matter which folder the executable was launched from. The
// ConnectionId structure, the file names and the encryption of the
// files are unchanged by the canonical location - only the root is.

using System.Security.Cryptography;

// CA1416 suppression (build-clean, platform-safe)
// ------------------------------------------------
// System.Security.Cryptography.DataProtectionScope is annotated
// [SupportedOSPlatform("windows")], so ANY reference to the type - even a
// pure enum member used as a scope MARKER in cross-platform code - is
// reported by the platform-compatibility analyzer as CA1416. The actual
// Windows-only APIs (ProtectedData.Protect / Unprotect) are never invoked
// off Windows: every call site is guarded by OperatingSystem.IsWindows()
// (see ProtectedFileStore.Protect / UnprotectWithWindowsDpapi, which throws
// PlatformNotSupportedException otherwise) and non-Windows hosts take the
// AES-GCM fallback. The enum reference itself carries no runtime dependency,
// so the diagnostic is a false positive here and is suppressed deliberately
// and locally rather than globally in the project file.
#pragma warning disable CA1416


namespace SSP.Core.IO;

/// <summary>
/// Canonical client installation locations (C:\Program Files\SSP and
/// its connections folder).
/// </summary>
public static class ClientInstallPaths
{
    /// <summary>Product directory name inside Program Files.</summary>
    public const string ProductDirectoryName = "SSP";

    /// <summary>
    /// The DPAPI protection scope of the CLIENT's own connection-state
    /// files (connections/{ConnectionId}/.cache.dat, .index.dat,
    /// .runtime.dat): <see cref="DataProtectionScope.CurrentUser"/>.
    ///
    /// The client is not a service - it is launched by the interactive
    /// user, and that same user both generates the client identity key
    /// pair (first run) and reads it back on every later start. No other
    /// identity (no Windows Service, no setup-mode elevation) ever reads
    /// these files, so the LocalMachine scope the SERVER-side service
    /// files require would only add an attack surface: it would let ANY
    /// local account on the machine decrypt the client private key
    /// (MS-CryptProtectData: "any user on the computer ... can use
    /// CryptUnprotectData to decrypt the data") and impersonate the
    /// enrolled client connection.
    ///
    /// CurrentUser scope binds decryption to the creating user's own DPAPI
    /// master key: every other account on the machine can read the file
    /// bytes but cannot recover the key material. A file copied to
    /// another user or another machine stays undecryptable, and a
    /// connection whose owner can no longer decrypt its own files fails
    /// closed ("local identity credential unavailable") instead of
    /// silently generating a replacement identity.
    /// </summary>
    public const DataProtectionScope ClientConnectionProtectionScope = DataProtectionScope.CurrentUser;

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
#pragma warning restore CA1416
