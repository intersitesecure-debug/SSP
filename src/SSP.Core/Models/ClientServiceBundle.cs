// File: src/SSP.Core/Models/ClientServiceBundle.cs
//
// The list of services this client installation belongs to. It is
// EMBEDDED inside SSP.Client.exe as a manifest resource instead of
// being written as a client_services.json file next to the executable,
// so a provisioned client is a single EXE with no sidecar.
//
// Patch-slot ClientConfig remains the single-service default; when the
// embedded bundle is non-empty it is the source of truth so one process
// can run independent tunnels without stuffing N RSA PEMs into the
// 4096-byte patch slot.
//
// SetupEngine writes and merges this bundle directly into the client
// executables. ResolveAsync also discovers other patched SSP.Client.*
// binaries in the same folder (same ClientName) so packages copied from
// several servers combine.
//
// EVERYTHING here is keyed by ConnectionIdentity.ConnectionId
// (Server + Service), never by ApplicationName alone: ServerA/WEB and
// ServerB/WEB are two independent connections that must coexist in one
// bundle and must never share an identity directory.

using System.Text.Json;
using SSP.Core.IO;
using SSP.Core.Util;

namespace SSP.Core.Models;

/// <summary>
/// Bundle embedded in the client executable
/// (<c>SSP.Client.ClientServices.json</c> manifest resource) listing
/// every connection the installation belongs to. The payload is the
/// plain JSON text of this object - no encryption, hashing, compression
/// or obfuscation.
/// </summary>
public sealed class ClientServiceBundle
{
    public List<ClientConfig> Services { get; set; } = new();

    /// <summary>
    /// Serialize exactly like the old <c>client_services.json</c> file
    /// did, so the embedded content is value-for-value identical.
    /// </summary>
    public string ToJson()
    {
        Services ??= new List<ClientConfig>();
        return JsonSerializer.Serialize(this, JsonOptions.Default);
    }

    /// <summary>Parse the embedded bundle JSON.</summary>
    public static ClientServiceBundle FromJson(string json)
    {
        var bundle = JsonSerializer.Deserialize<ClientServiceBundle>(json, JsonOptions.Default)
                     ?? throw new InvalidDataException("Failed to deserialize the embedded client services bundle.");
        bundle.Services ??= new List<ClientConfig>();
        return bundle;
    }

    /// <summary>
    /// The embedded <c>client_services.json</c> text of a patched client
    /// binary, or null when the binary carries no (or an empty) bundle.
    /// </summary>
    public static string? ReadEmbeddedJson(byte[] clientBinary) =>
        ClientTemplate.ReadServicesSlot(clientBinary);

    /// <summary>
    /// Deserialize the bundle embedded in a patched client binary.
    /// Returns null when the binary has no bundle at all.
    /// </summary>
    public static ClientServiceBundle? LoadEmbedded(byte[] clientBinary)
    {
        var json = ReadEmbeddedJson(clientBinary);
        return string.IsNullOrWhiteSpace(json) ? null : FromJson(json);
    }

    /// <summary>Same as <see cref="LoadEmbedded(byte[])"/> for a file path.</summary>
    public static ClientServiceBundle? LoadEmbedded(string clientExecutablePath) =>
        LoadEmbedded(File.ReadAllBytes(clientExecutablePath));

    /// <summary>
    /// Return a copy of <paramref name="clientBinary"/> whose embedded
    /// services resource now holds <paramref name="bundle"/>. The length
    /// is unchanged and the patch slot is untouched.
    /// </summary>
    public static byte[] SaveEmbedded(byte[] clientBinary, ClientServiceBundle bundle) =>
        ClientTemplate.PatchServicesSlot(clientBinary, bundle.ToJson());

    /// <summary>
    /// Write <paramref name="bundle"/> into the embedded services
    /// resource of the client executable at
    /// <paramref name="clientExecutablePath"/>. No sidecar file is
    /// created. The write is atomic and verified by reading the slot
    /// back before it replaces the original executable.
    /// </summary>
    public static async Task WriteEmbeddedAsync(
        string clientExecutablePath,
        ClientServiceBundle bundle,
        CancellationToken ct = default)
    {
        var original = await File.ReadAllBytesAsync(clientExecutablePath, ct).ConfigureAwait(false);
        var patched = SaveEmbedded(original, bundle);

        var expected = bundle.Services?.Count ?? 0;
        var readBack = LoadEmbedded(patched);
        if (readBack == null || readBack.Services.Count != expected)
        {
            var actual = readBack == null ? "none" : readBack.Services.Count.ToString();
            throw new InvalidDataException(
                $"Embedded client services verification failed for {clientExecutablePath}: " +
                $"expected {expected} service(s), read back {actual}.");
        }

        await AtomicFile.WriteBytesAsync(clientExecutablePath, patched, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Replace or append <paramref name="incoming"/> keyed by the
    /// CONNECTION identity (Server + Service). Two entries for the same
    /// ApplicationName on two different servers are kept side by side.
    /// </summary>
    public static void Upsert(List<ClientConfig> services, ClientConfig incoming)
    {
        if (string.IsNullOrWhiteSpace(incoming.ApplicationName))
            return;

        var id = ConnectionIdentity.ConnectionId(incoming);
        var idx = services.FindIndex(s =>
            string.Equals(ConnectionIdentity.ConnectionId(s), id, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
            services[idx] = incoming;
        else
            services.Add(incoming);
    }

    public static bool SameClient(ClientConfig a, ClientConfig b)
    {
        if (string.IsNullOrWhiteSpace(a.ClientName) && string.IsNullOrWhiteSpace(b.ClientName))
            return true;
        if (string.IsNullOrWhiteSpace(a.ClientName) || string.IsNullOrWhiteSpace(b.ClientName))
            return false;
        return string.Equals(a.ClientName, b.ClientName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resolve the services this process should open:
    ///   1. The bundle embedded in the launched executable lists
    ///      additional connections when non-empty (one process, N
    ///      independent tunnels).
    ///   2. The launched executable's patch slot is ALWAYS the
    ///      definition of THAT connection (gateway, OTT, server key).
    ///      A merged bundle must not hide it, replace it with another
    ///      connection's settings, or skip its initial enrollment.
    ///   3. Otherwise the patched slot is the only connection (legacy
    ///      single-service behavior).
    ///   4. Sibling SSP.Client.* binaries with the same ClientName fill
    ///      in connections the embedded bundle/patch does not already
    ///      list.
    ///
    /// An unpatched / test dummy with no server identity is never
    /// injected next to a valid bundle (the ConnectionId spaces would
    /// not match and would create a phantom extra connection).
    /// </summary>
    /// <param name="exeDirectory">Folder holding the client executable.</param>
    /// <param name="patched">ClientConfig of the launched executable's patch slot.</param>
    /// <param name="embeddedServicesJson">
    /// The <c>client_services.json</c> text read from the embedded
    /// resource of the launched executable, or null when it has none.
    /// </param>
    public static Task<IReadOnlyList<ClientConfig>> ResolveAsync(
        string exeDirectory,
        ClientConfig patched,
        string? embeddedServicesJson,
        CancellationToken ct = default)
    {
        var services = new List<ClientConfig>();
        if (!string.IsNullOrWhiteSpace(embeddedServicesJson))
        {
            try
            {
                var bundle = FromJson(embeddedServicesJson);
                if (bundle.Services.Count > 0)
                    services.AddRange(bundle.Services);
            }
            catch (Exception)
            {
                // Fall through to patched + sibling binaries.
            }
        }

        if (services.Count == 0)
            services.Add(patched);

        var siblingAdded = false;
        if (Directory.Exists(exeDirectory))
        {
            foreach (var binary in EnumeratePatchedClientBinaries(exeDirectory))
            {
                if (!TryReadPatchedConfig(binary, out var cfg))
                    continue;
                if (!HasServerIdentity(cfg))
                    continue;
                if (!SameClient(patched, cfg))
                    continue;
                if (services.Any(s => ConnectionIdentity.SameConnection(s, cfg)))
                    continue;
                services.Add(cfg);
                siblingAdded = true;
            }
        }

        // A dummy patch slot (unpatched template / test build) must never
        // run beside real connections discovered from the same folder:
        // it carries no server identity, its ConnectionId space does not
        // match, and trying to "enroll" it would only produce a phantom
        // gateway failure for a connection that does not exist. Drop it
        // as soon as at least one real connection was found.
        if (siblingAdded && services.Count > 1 && !HasServerIdentity(patched))
            services.RemoveAll(s => !HasServerIdentity(s));

        // Last: pin the launched executable's own ConnectionIdentity so
        // Web-C1 always enrolls Web against Web's gateway/OTT even when
        // the embedded bundle still lists RDP first (or only RDP).
        ApplyLaunchedConnection(services, patched);

        return Task.FromResult<IReadOnlyList<ClientConfig>>(services);
    }

    /// <summary>
    /// Convenience overload: resolve using the bundle embedded in the
    /// bytes of the launched client executable.
    /// </summary>
    public static Task<IReadOnlyList<ClientConfig>> ResolveAsync(
        string exeDirectory,
        ClientConfig patched,
        byte[] launchedClientBinary,
        CancellationToken ct = default) =>
        ResolveAsync(exeDirectory, patched, ReadEmbeddedJson(launchedClientBinary), ct);

    /// <summary>
    /// The connections THIS process may actually run.
    ///
    /// RULE (per-connection lifecycle): when the launched executable was
    /// patched for a real connection (it embeds a server identity), the
    /// process runs EXACTLY that one connection - its startup enrollment,
    /// its Authentication Code prompt, its tunnel port. The other entries
    /// of a merged client_services.json are OTHER connections: starting
    /// exe A must never enroll connection B, never dial B's gateway
    /// (which produced SocketException noise when B's gateway was not
    /// running), never consume B's One-Time Token, and never bind B's
    /// ClientTunnelPort (which blocked B's own executable from binding
    /// it later). Each of those connections completes its own full
    /// lifecycle when ITS executable is started.
    ///
    /// Only when the launched binary has no identity of its own (raw
    /// template host) does the process fall back to hosting every
    /// resolved connection.
    /// </summary>
    public static IReadOnlyList<ClientConfig> SelectProcessConnections(
        IReadOnlyList<ClientConfig> resolvedConnections,
        ClientConfig? launched)
    {
        if (launched == null ||
            string.IsNullOrWhiteSpace(launched.ApplicationName) ||
            !HasServerIdentity(launched))
        {
            // Generic host / unpatched template: nothing to pin.
            return resolvedConnections;
        }

        // THIS executable runs THIS connection (Server + Service).
        return new[] { launched };
    }

    /// <summary>
    /// True when <paramref name="config"/> carries a real server
    /// identity (public key and/or fingerprint). An empty patch slot /
    /// test dummy does not.
    /// </summary>
    public static bool HasServerIdentity(ClientConfig? config) =>
        config != null &&
        (!string.IsNullOrWhiteSpace(config.ServerPublicKeyPem) ||
         !string.IsNullOrWhiteSpace(config.ServerFingerprint));

    /// <summary>
    /// Make <paramref name="patched"/> (the launched executable) the
    /// authoritative definition of its ConnectionIdentity: overlay it
    /// onto a matching bundle entry, or insert it, and move it to the
    /// front so its initial enrollment runs first.
    ///
    /// No-ops when the patch slot has no server identity, so a dummy
    /// launch-time config cannot become a 4th connection beside a
    /// valid 3-entry bundle.
    ///
    /// The endpoint-based fallback only matches LEGACY bundle entries
    /// that carry no server identity of their own. A bundle entry with
    /// a DIFFERENT server fingerprint is a different connection
    /// (ServerB/APP next to ServerA/APP): it is never replaced or
    /// removed, so both keep independent identity, OTT and enrollment
    /// state.
    /// </summary>
    public static void ApplyLaunchedConnection(List<ClientConfig> services, ClientConfig patched)
    {
        if (services == null || patched == null)
            return;
        if (string.IsNullOrWhiteSpace(patched.ApplicationName))
            return;
        if (!HasServerIdentity(patched))
            return;

        var idx = services.FindIndex(s => ConnectionIdentity.SameConnection(s, patched));
        if (idx < 0)
        {
            // Legacy bundle entry without a server identity describing the
            // same endpoint: the patch slot (which carries the key) defines
            // the same physical connection - replace it. Entries that DO
            // carry a server identity belong to a different Server + Service
            // connection and must survive side by side.
            idx = services.FindIndex(s =>
                !HasServerIdentity(s) &&
                string.Equals(s.ApplicationName, patched.ApplicationName, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(s.GatewayPublicIpAddress ?? string.Empty,
                    patched.GatewayPublicIpAddress ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                s.GatewayPort == patched.GatewayPort);
        }

        if (idx >= 0)
            services.RemoveAt(idx);

        services.Insert(0, patched);
    }

    /// <summary>
    /// Directory holding the identity and state of ONE connection:
    /// <c>C:\Program Files\SSP\connections\{ConnectionId}</c> (the
    /// canonical product root - see
    /// <see cref="SSP.Core.IO.ClientInstallPaths"/>).
    ///
    /// The root is canonical and machine-wide, so it no longer depends
    /// on <paramref name="exeDirectory"/>: every SSP.Client.*.exe on
    /// this machine that describes the SAME connection (Server +
    /// Service) shares exactly this one directory. The parameter is
    /// kept for signature compatibility and to document the legacy
    /// per-exe layout.
    ///
    /// This is independent of how many connections the installation
    /// currently has, so adding a second connection never moves (and
    /// therefore never invalidates) the first one's enrollment.
    /// </summary>
    public static string ConnectionDirectory(string exeDirectory, ClientConfig config) =>
        Path.Combine(ClientInstallPaths.GetConnectionsRoot(),
            ConnectionIdentity.ConnectionId(config));

    /// <summary>
    /// LEGACY layout resolution, kept so pre-existing installations can
    /// be migrated: single-service clients kept keys next to the exe and
    /// multi-service clients under runtime/{ApplicationName}/. Both are
    /// only ApplicationName-scoped and are therefore no longer used for
    /// new state - see <see cref="ConnectionDirectory"/>.
    /// </summary>
    public static string IdentityDirectory(string exeDirectory, ClientConfig config, int serviceCount)
    {
        if (serviceCount <= 1)
            return exeDirectory;

        var name = SanitizeApplicationName(config.ApplicationName);
        return Path.Combine(exeDirectory, "runtime", name);
    }

    /// <summary>
    /// Create the connection directory for <paramref name="config"/> and,
    /// when this is the connection the launched executable was provisioned
    /// for, migrate existing state into it so an already enrolled
    /// installation does not have to re-enroll (spec §18).
    ///
    /// Migration is deliberately restricted to the launched connection:
    /// an old RDP identity must never be adopted by a WEB connection, and
    /// a ServerA identity must never be adopted by ServerB.
    /// </summary>
    public static string PrepareIdentityDirectory(
        string exeDirectory,
        ClientConfig config,
        int serviceCount,
        ClientConfig? launchedConfig = null)
    {
        var dest = ConnectionDirectory(exeDirectory, config);
        Directory.CreateDirectory(dest);

        var migrate = launchedConfig != null &&
                      ConnectionIdentity.SameConnection(config, launchedConfig);
        if (!migrate)
            return dest;

        // Most specific source first: the PRE-CANONICAL per-exe
        // connection directory ({exeDirectory}/connections/{ConnectionId}/).
        // Its files already use the current names and the
        // encrypted-at-rest envelope, so moving them is a plain byte
        // copy - file names, ConnectionId structure and encryption are
        // all unchanged.
        var previousConnectionDir = Path.Combine(
            exeDirectory, ClientInstallPaths.ConnectionsDirectoryName,
            ConnectionIdentity.ConnectionId(config));
        if (MigratePreviousConnectionDirectory(previousConnectionDir, dest))
            return dest;

        // Legacy sources, most specific first:
        //   runtime/{ApplicationName}/  (legacy multi-service layout,
        //                               already scoped to THIS service)
        //   {exeDirectory}/             (legacy single-service layout)
        //
        // Exe-root keys are only migrated when they cannot belong to a
        // different service. Otherwise launching Web-C1 from a folder
        // that still has RDP's client_private_key.pem would adopt RDP's
        // identity, skip Web enrollment, and never ask for Web's
        // Authentication Code.
        var legacySources = new List<string>
        {
            Path.Combine(exeDirectory, "runtime", SanitizeApplicationName(config.ApplicationName)),
        };
        if (!ExeRootKeysAreAmbiguous(exeDirectory, config))
            legacySources.Add(exeDirectory);

        foreach (var source in legacySources)
        {
            if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(dest),
                    StringComparison.OrdinalIgnoreCase))
                continue;
            if (MigrateLegacyKeys(source, dest))
                break;
        }

        return dest;
    }

    /// <summary>
    /// Move the state of ONE connection from the pre-canonical per-exe
    /// connection directory (<c>{exeDirectory}/connections/
    /// {ConnectionId}/</c>) into the canonical root
    /// (<c>C:\Program Files\SSP\connections\{ConnectionId}/</c>).
    ///
    /// The files already carry the current names (.cache.dat /
    /// .index.dat / .runtime.dat) and the encrypted-at-rest envelope,
    /// so the copy is a byte-for-byte move of the files: the encryption
    /// is never re-wrapped, re-keyed or otherwise rewritten. The source
    /// is left in place (non-destructive), mirroring the legacy PEM
    /// migration.
    ///
    /// Returns true when the connection's state was moved.
    /// </summary>
    private static bool MigratePreviousConnectionDirectory(string sourceDir, string destDir)
    {
        if (string.Equals(Path.GetFullPath(sourceDir), Path.GetFullPath(destDir),
                StringComparison.OrdinalIgnoreCase))
            return false;

        if (!Directory.Exists(sourceDir))
            return false;

        // The identity is all-or-nothing: only move a COMPLETE key pair
        // so a half pair is never left behind in the canonical root.
        var havePrivate = File.Exists(Path.Combine(sourceDir, ".cache.dat"));
        var havePublic = File.Exists(Path.Combine(sourceDir, ".index.dat"));
        if (!havePrivate || !havePublic)
            return false;

        var migrated = false;
        foreach (var name in new[] { ".cache.dat", ".index.dat", ".runtime.dat" })
        {
            var source = Path.Combine(sourceDir, name);
            var target = Path.Combine(destDir, name);
            if (File.Exists(source) && !File.Exists(target))
            {
                File.Copy(source, target);
                migrated = true;
            }
        }

        return migrated;
    }

    /// <summary>
    /// True when keys sitting next to the executable cannot safely be
    /// attributed to <paramref name="config"/>: the folder already
    /// knows about a different Application (bundle, sibling binary, or
    /// another connection profile).
    /// </summary>
    internal static bool ExeRootKeysAreAmbiguous(string exeDirectory, ClientConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.ApplicationName))
            return true;

        try
        {
            foreach (var binaryPath in EnumeratePatchedClientBinaries(exeDirectory))
            {
                byte[] bytes;
                try { bytes = File.ReadAllBytes(binaryPath); }
                catch { continue; }

                // Signal 1: the bundle embedded in this client executable.
                ClientServiceBundle? bundle = null;
                try { bundle = LoadEmbedded(bytes); }
                catch { /* unreadable embedded bundle: keep checking other signals */ }

                if (bundle?.Services != null &&
                    bundle.Services.Any(s =>
                        !string.IsNullOrWhiteSpace(s.ApplicationName) &&
                        !string.Equals(s.ApplicationName, config.ApplicationName,
                            StringComparison.OrdinalIgnoreCase)))
                    return true;

                // Signal 2: this executable's own patch slot.
                if (!TryReadPatchedConfig(bytes, out var cfg))
                    continue;
                if (!string.Equals(cfg.ApplicationName, config.ApplicationName,
                        StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch { /* ignore */ }

        try
        {
            var connectionsRoot = Path.Combine(exeDirectory, "connections");
            if (Directory.Exists(connectionsRoot))
            {
                foreach (var dir in Directory.EnumerateDirectories(connectionsRoot))
                {
                    var state = ClientConnectionState.TryLoad(dir);
                    if (state != null &&
                        !string.IsNullOrWhiteSpace(state.ApplicationName) &&
                        !string.Equals(state.ApplicationName, config.ApplicationName,
                            StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
        }
        catch { /* ignore */ }

        return false;
    }

    /// <summary>
    /// Copy a legacy client key pair into the connection directory.
    /// Returns true when a complete key pair was migrated.
    /// The LEGACY layouts keep the old .pem names; the connection
    /// directory now stores the pair as .cache.dat / .index.dat, so the
    /// copy maps old source names onto the new destination names.
    ///
    /// The destination pair is protected at rest: it is written through
    /// PemStore (the same ProtectedFileStore mechanism the server-side
    /// key files use, in the client's CurrentUser scope - Phase 3 /
    /// M-2), so the legacy plaintext PEM never lands on disk inside the
    /// connection directory - the files are created directly in the
    /// encrypted envelope and are decrypted transparently by
    /// ClientRuntime on load.
    /// </summary>
    private static bool MigrateLegacyKeys(string sourceDir, string destDir)
    {
        var legacyNames = new[] { "client_private_key.pem", "client_public_key.pem" };
        var destNames   = new[] { ".cache.dat", ".index.dat" };
        if (legacyNames.Any(n => !File.Exists(Path.Combine(sourceDir, n))))
            return false;
        if (destNames.Any(n => File.Exists(Path.Combine(destDir, n))))
            return false;

        var privPem = File.ReadAllText(Path.Combine(sourceDir, legacyNames[0]));
        var pubPem  = File.ReadAllText(Path.Combine(sourceDir, legacyNames[1]));

        // Synchronous context (PrepareIdentityDirectory): the protected
        // store's async I/O is completed inline, exactly like the
        // Windows service host does for .cache.dat. CurrentUser scope
        // (Phase 3 / M-2): the migrated legacy keys belong to the
        // interactive client user and must stay unreadable to every
        // other account on the machine.
        PemStore.SavePrivateKeyAsync(
                Path.Combine(destDir, destNames[0]), privPem,
                ClientInstallPaths.ClientConnectionProtectionScope)
            .GetAwaiter().GetResult();
        PemStore.SavePublicKeyAsync(
                Path.Combine(destDir, destNames[1]), pubPem,
                ClientInstallPaths.ClientConnectionProtectionScope)
            .GetAwaiter().GetResult();

        return true;
    }

    public static string SanitizeApplicationName(string applicationName) =>
        ConnectionIdentity.Sanitize(applicationName);

    public static IEnumerable<string> EnumeratePatchedClientBinaries(string directory)
    {
        if (!Directory.Exists(directory))
            yield break;

        foreach (var file in Directory.EnumerateFiles(directory))
        {
            var name = Path.GetFileName(file);
            if (!name.StartsWith("SSP.Client", StringComparison.OrdinalIgnoreCase))
                continue;

            var ext = Path.GetExtension(file);
            if (ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".pdb", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".lock", StringComparison.OrdinalIgnoreCase))
                continue;

            if (name.Contains(".deps.", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase))
                continue;

            yield return file;
        }
    }

    public static bool TryReadPatchedConfig(string binaryPath, out ClientConfig config)
    {
        config = null!;
        try
        {
            return TryReadPatchedConfig(File.ReadAllBytes(binaryPath), out config);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Same as <see cref="TryReadPatchedConfig(string, out ClientConfig)"/>
    /// for binary bytes that were already read (so one scan of the file
    /// can serve both the patch slot and the embedded services bundle).
    /// </summary>
    public static bool TryReadPatchedConfig(byte[] binaryBytes, out ClientConfig config)
    {
        config = null!;
        try
        {
            var cfg = ClientTemplate.ReadPatchSlot(binaryBytes);
            if (string.IsNullOrWhiteSpace(cfg.ApplicationName))
                return false;
            config = cfg;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
