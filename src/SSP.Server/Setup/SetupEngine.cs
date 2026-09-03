// File: src/SSP.Server/Setup/SetupEngine.cs
//
// SETUP MODE engine. Supports two workflows:
//
//   1. NEW Application creation (first time):
//      - Generate RSA key pair
//      - Generate OTT, store hash in pending list + legacy field for compat
//      - Patch client template into ClientName subfolder
//      - Embed/merge the client_services.json bundle INSIDE the client
//        executable(s) (same ClientName under a services/ root is
//        combined so one process can open RDP+WEB+SQL). No sidecar
//        client_services.json file is written next to the EXE.
//      - Persist server keys, .cache.dat, .index.dat
//      - Optionally create Windows Service
//
//   2. ADDITIONAL CLIENT provisioning for EXISTING Application:
//      - Detect existing service directory containing .cache.dat + keys
//      - Preserve existing RSA keys, config, .index.dat, service
//      - Generate new OTT, add to pending list
//      - Patch new client into its own subfolder (ClientName)
//      - No key regeneration, no authorized users wipe, no service recreation

using System.Reflection;
using System.Security.Cryptography;
using SSP.Core.Activation;
using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Util;
using SSP.Server.Activation;

namespace SSP.Server.Setup;

public sealed class SetupEngine
{
    /// <summary>
    /// The mandatory provisioning-time licensing gate (EP0a / EP0b). Keeping
    /// this dependency non-nullable makes it impossible to construct a setup
    /// workflow that silently skips the checks which protect service and client
    /// provisioning. Production callers obtain it from
    /// <see cref="SspRuntimeLicense.TryCreateForProvisioning"/>; tests must pass
    /// an explicit test gate when licensing is outside their scope.
    /// </summary>
    private readonly ISspLicenseGate _license;

    /// <summary>
    /// Creates the engine with the explicit provisioning-time licensing gate.
    /// The gate enforces <c>max_services</c> before a new protected service is
    /// created (EP0a) and <c>max_clients</c> before an additional client is
    /// provisioned (EP0b).
    /// </summary>
    public SetupEngine(ISspLicenseGate license)
    {
        _license = license ?? throw new ArgumentNullException(nameof(license));
    }

    public SetupResult Result { get; } = new();

    /// <summary>
    /// Run setup workflow. Detects existing application and enters
    /// additional-client provisioning path if config already exists.
    /// </summary>
    public async Task RunAsync(SetupParameters parameters, CancellationToken ct = default)
    {
        // Route from existing Application state on disk, not from whether
        // optional SetupParameters fields (GatewayPublicIpAddress, ports, …)
        // happen to be populated. An additional-client request may legally
        // supply only ApplicationName + ClientName (+ optional ServiceDirectory).
        var serviceDir = ResolveServiceDirectory(parameters, out var isExisting);
        Result.ServiceDirectory = serviceDir;

        var configPath = Path.Combine(serviceDir, ".cache.dat");
        var privPath = Path.Combine(serviceDir, ".sysdata.bin");
        var pubPath = Path.Combine(serviceDir, ".runtime.dat");
        var authPath = Path.Combine(serviceDir, ".index.dat");

        if (isExisting)
        {
            await RunAdditionalClientAsync(parameters, serviceDir, configPath, privPath, pubPath, authPath, ct);
        }
        else
        {
            await RunNewApplicationAsync(parameters, serviceDir, configPath, privPath, pubPath, authPath, ct);
        }
    }

    /// <summary>
    /// Deterministically resolve the Application directory.
    /// If any candidate already contains a valid Application
    /// (.cache.dat + server key pair), that directory wins so we
    /// never create a second services/{ApplicationName} tree or a new RSA pair.
    /// </summary>
    internal static string ResolveServiceDirectory(SetupParameters parameters, out bool isExisting)
    {
        string? existing = null;
        foreach (var candidate in EnumerateCandidateServiceDirectories(parameters))
        {
            if (IsExistingApplicationDirectory(candidate))
            {
                existing = candidate;
                break;
            }
        }

        if (existing != null)
        {
            isExisting = true;
            return existing;
        }

        isExisting = false;
        var serviceDir = ResolvePreferredNewServiceDirectory(parameters);
        return serviceDir;
    }

    /// <summary>
    /// True when the directory already hosts a complete Application:
    /// .cache.dat plus both RSA key files.
    /// </summary>
    internal static bool IsExistingApplicationDirectory(string serviceDir)
    {
        if (string.IsNullOrWhiteSpace(serviceDir))
            return false;
        if (!Directory.Exists(serviceDir))
            return false;

        var configPath = Path.Combine(serviceDir, ".cache.dat");
        var privPath = Path.Combine(serviceDir, ".sysdata.bin");
        var pubPath = Path.Combine(serviceDir, ".runtime.dat");
        return File.Exists(configPath) && File.Exists(privPath) && File.Exists(pubPath);
    }

    private static IEnumerable<string> EnumerateCandidateServiceDirectories(SetupParameters parameters)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        IEnumerable<string> Yield(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                yield break;
            string full;
            try { full = Path.GetFullPath(path); }
            catch { yield break; }
            if (seen.Add(full))
                yield return full;
        }

        var appName = parameters.ApplicationName?.Trim();
        var explicitDir = string.IsNullOrWhiteSpace(parameters.ServiceDirectory)
            ? null
            : parameters.ServiceDirectory.Trim();

        // 1. Caller-supplied ServiceDirectory (tests / batch / existing path)
        foreach (var p in Yield(explicitDir))
            yield return p;

        if (!string.IsNullOrWhiteSpace(explicitDir) && !string.IsNullOrWhiteSpace(appName))
        {
            // 2. ServiceDirectory may be a parent (e.g. "services") rather than services/RDP
            foreach (var p in Yield(Path.Combine(explicitDir, appName)))
                yield return p;
            foreach (var p in Yield(Path.Combine(explicitDir, "services", appName)))
                yield return p;
        }

        // 3. Canonical production layout: {Program Files}/SSP/services/{ApplicationName}
        //    Only when the caller did not pin an explicit ServiceDirectory,
        //    so a leftover services/RDP next to the executable cannot hijack
        //    a test/temp dir.
        if (explicitDir == null && !string.IsNullOrWhiteSpace(appName))
        {
            foreach (var p in Yield(Path.Combine(GetCanonicalServicesRoot(), appName)))
                yield return p;
        }
    }

    private static string ResolvePreferredNewServiceDirectory(SetupParameters parameters)
    {
        if (!string.IsNullOrWhiteSpace(parameters.ServiceDirectory))
            return Path.GetFullPath(parameters.ServiceDirectory.Trim());

        var appName = string.IsNullOrWhiteSpace(parameters.ApplicationName)
            ? "Application"
            : parameters.ApplicationName.Trim();
        return Path.GetFullPath(Path.Combine(GetCanonicalServicesRoot(), appName));
    }

    /// <summary>
    /// Root of the canonical <c>services/</c> production layout. All SSP
    /// data lives under the machine's Program Files folder - resolved
    /// through the standard .NET/Windows mechanism (e.g.
    /// <c>C:\Program Files\SSP\services\{ApplicationName}</c>), never
    /// hard-coded - independent of where SSP.Server.exe was launched from;
    /// the executable itself stays in its deploy location. On platforms
    /// without a Program Files folder (non-Windows test hosts) the previous
    /// working-directory-based <c>services/</c> root is kept.
    /// </summary>
    internal static string GetCanonicalServicesRoot()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            return Path.Combine(Directory.GetCurrentDirectory(), "services");
        return Path.Combine(programFiles, "SSP", "services");
    }

    /// <summary>
    /// First-time application creation.
    /// </summary>
    private async Task RunNewApplicationAsync(
        SetupParameters parameters,
        string serviceDir,
        string configPath,
        string privPath,
        string pubPath,
        string authPath,
        CancellationToken ct)
    {
        ValidateNewApplicationParameters(parameters);
        ValidateNoSiblingPortCollisions(serviceDir, parameters);

        // EP0a - creating a protected service is the primary commercial act, so
        // it is gated on max_services and on the feature set covering the
        // protected protocol being created. InvalidOperationException is this
        // engine's established denial convention: SETUP MODE catches it, prints
        // "[setup] Failed:" and exits 1 without creating any artifact.
        //
        // Usage is measured BEFORE the grant: every complete application
        // directory that already exists (this one does not exist yet).
        AuthorizeNewProtectedService(parameters.ApplicationName);

        Result.GatewayPort = parameters.GatewayPort;
        Result.ClientTunnelPort = parameters.ClientTunnelPort;

        var clientName = string.IsNullOrWhiteSpace(parameters.ClientName)
            ? "Client01"
            : parameters.ClientName!.Trim();
        ValidateClientName(clientName);

        Directory.CreateDirectory(serviceDir);

        // 2. RSA key pair
        using var rsa = RsaCrypto.GenerateKeyPair();
        var privPem = RsaCrypto.ExportPrivateKeyPem(rsa);
        var pubPem = RsaCrypto.ExportPublicKeyPem(rsa);
        await PemStore.SavePrivateKeyAsync(privPath, privPem, ct);
        await PemStore.SavePublicKeyAsync(pubPath, pubPem, ct);
        Result.ServerPrivateKeyPath = privPath;
        Result.ServerPublicKeyPath = pubPath;

        // 3. OTT
        var ott = TokenGenerator.GenerateOneTimeToken();
        var ottHash = TokenGenerator.HashOneTimeToken(ott);

        // 4-6. Client template -> copy -> patch -> validate -> rename into client subfolder
        var clientConfig = new ClientConfig
        {
            ApplicationName = parameters.ApplicationName,
            ServerPublicKeyPem = pubPem,
            // Server identity of THIS connection. Stamped at provisioning
            // time so the client can scope its state by Server + Service
            // without re-deriving it from the PEM on every start.
            ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(pubPem),
            GatewayPublicIpAddress = parameters.GatewayPublicIpAddress,
            GatewayPort = parameters.GatewayPort,
            LocalApplicationPort = parameters.LocalApplicationPort,
            ClientTunnelPort = parameters.ClientTunnelPort,
            OneTimeToken = ott,
            ClientName = clientName,
        };

        var clientDir = Path.Combine(serviceDir, clientName);
        if (Directory.Exists(clientDir) && Directory.EnumerateFileSystemEntries(clientDir).Any())
        {
            // First-time but client dir exists with content -> duplicate
            throw new InvalidOperationException($"Client '{clientName}' already exists at {clientDir}.");
        }
        Directory.CreateDirectory(clientDir);

        var clientFileName = $"SSP.Client.{parameters.ApplicationName}.{clientName}.exe";
        var clientPath = Path.Combine(clientDir, clientFileName);

        // Also guard against duplicate at root for backward compat tests that might still check root?
        // We no longer create at root by default; only in client subfolder.

        await BuildPatchedClientAsync(clientPath, clientConfig, ct);
        Result.ClientExecutablePath = clientPath;
        await PersistClientServiceBundleAsync(serviceDir, clientDir, clientName, clientConfig, ct)
            .ConfigureAwait(false);
        TryCopyClientToInteractiveUserDesktop(clientPath);

        // 7. Persist config + authorized users
        var pending = new PendingOneTimeToken
        {
            ClientName = clientName,
            OneTimeTokenHash = ottHash,
            CreatedAtUtc = DateTime.UtcNow.ToString("o"),
        };

        var cfg = new ServiceConfig
        {
            ApplicationName = parameters.ApplicationName,
            GatewayPublicIpAddress = parameters.GatewayPublicIpAddress,
            GatewayPort = parameters.GatewayPort,
            LocalApplicationPort = parameters.LocalApplicationPort,
            ClientTunnelPort = parameters.ClientTunnelPort,
            ActiveOneTimeTokenHash = ottHash, // legacy for backward compat
            PendingOneTimeTokens = new List<PendingOneTimeToken> { pending },
            CreatedAtUtc = DateTime.UtcNow.ToString("o"),
            WindowsServiceName = $"SSP {parameters.ApplicationName} {parameters.GatewayPort}",
        };
        await ServiceConfigStore.SaveAsync(configPath, cfg, ct);
        Result.ServerConfigPath = configPath;

        await AuthorisedUsersStore.SaveAsync(authPath, new AuthorisedUsersFile(), ct);
        Result.AuthorisedUsersPath = authPath;

        Result.OneTimeToken = ott;
        Result.OneTimeTokenHash = ottHash;
        Result.WindowsServiceName = cfg.WindowsServiceName;
        Result.ClientName = clientName;

        // 8. Windows Service
        if (OperatingSystem.IsWindows() && parameters.InstallWindowsService)
        {
            Result.Success = await WindowsServiceInstaller.CreateStartAndVerifyAsync(
                cfg, serviceDir, ct).ConfigureAwait(false);
            if (!Result.Success)
            {
                Console.Error.WriteLine(
                    "[setup] Windows Service did not reach RUNNING with the gateway " +
                    "listening. Setup is NOT considered complete (spec §4 / §5).");
            }
        }
        else
        {
            Result.Success = true;
        }
    }

    /// <summary>
    /// Additional client provisioning for existing application.
    /// Preserves server keys, config, authorized users, service.
    /// </summary>
    private async Task RunAdditionalClientAsync(
        SetupParameters parameters,
        string serviceDir,
        string configPath,
        string privPath,
        string pubPath,
        string authPath,
        CancellationToken ct)
    {
        // Load existing config
        var existingConfig = await ServiceConfigStore.LoadAsync(configPath, ct);
        if (!string.Equals(existingConfig.ApplicationName, parameters.ApplicationName, StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(parameters.ApplicationName))
        {
            // If caller supplied different name but dir matches existing, warn but use existing
            // For strictness, we keep existing's name.
        }

        var clientName = parameters.ClientName?.Trim();
        if (string.IsNullOrWhiteSpace(clientName))
        {
            throw new ArgumentException("ClientName is required when provisioning an additional client for an existing Application.");
        }
        ValidateClientName(clientName!);

        // Duplicate check - filesystem
        var clientDir = Path.Combine(serviceDir, clientName!);
        if (Directory.Exists(clientDir))
        {
            throw new InvalidOperationException($"Client '{clientName}' already exists at {clientDir}. Choose a different Client Name.");
        }

        // Duplicate check - pending list
        existingConfig.PendingOneTimeTokens ??= new List<PendingOneTimeToken>();
        if (existingConfig.PendingOneTimeTokens.Any(p =>
            string.Equals(p.ClientName, clientName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Client '{clientName}' already has a pending OTT. Enrollment must complete or remove pending entry first.");
        }

        // Duplicate check - authorized users label
        if (File.Exists(authPath))
        {
            var existingUsers = await AuthorisedUsersStore.LoadAsync(authPath, ct);
            if (existingUsers.Users.Any(u =>
                string.Equals(u.Label, clientName, StringComparison.OrdinalIgnoreCase)))
            {
                // If already authorized with same label, treat as duplicate to avoid confusion,
                // but allow if administrator explicitly wants to re-provision same label after enrollment?
                // For safety, reject if directory exists already covers filesystem; label duplicate is warning.
                // We will reject to prevent accidental overwrite of identity concept.
                throw new InvalidOperationException($"Client '{clientName}' already exists as an authorized client (label match). Choose a different Client Name.");
            }
        }

        // EP0b - provisioning an additional client is where the per-customer
        // client count is enforced BEFORE a One-Time Token is minted, so a
        // licensee at max_clients cannot hand out an enrollable credential. The
        // authoritative runtime enforcement remains EP2 (enrollment), which
        // counts .index.dat under the enrollment locks; this pre-check gives the
        // operator the refusal at provisioning time instead of after a client
        // executable has been built.
        await AuthorizeAdditionalClientAsync(authPath, ct).ConfigureAwait(false);

        // Load existing public key
        var pubPem = await PemStore.LoadPublicKeyAsync(pubPath, ct);

        // Generate new OTT
        var ott = TokenGenerator.GenerateOneTimeToken();
        var ottHash = TokenGenerator.HashOneTimeToken(ott);

        // Build client config reusing existing application config
        var clientConfig = new ClientConfig
        {
            ApplicationName = existingConfig.ApplicationName,
            ServerPublicKeyPem = pubPem,
            // Server identity of THIS connection. Stamped at provisioning
            // time so the client can scope its state by Server + Service
            // without re-deriving it from the PEM on every start.
            ServerFingerprint = RsaCrypto.ComputePublicKeyFingerprintFromPem(pubPem),
            GatewayPublicIpAddress = existingConfig.GatewayPublicIpAddress,
            GatewayPort = existingConfig.GatewayPort,
            LocalApplicationPort = existingConfig.LocalApplicationPort,
            ClientTunnelPort = existingConfig.ClientTunnelPort,
            OneTimeToken = ott,
            ClientName = clientName!,
        };

        Directory.CreateDirectory(clientDir);
        var clientFileName = $"SSP.Client.{existingConfig.ApplicationName}.{clientName}.exe";
        var clientPath = Path.Combine(clientDir, clientFileName);

        await BuildPatchedClientAsync(clientPath, clientConfig, ct);
        await PersistClientServiceBundleAsync(serviceDir, clientDir, clientName!, clientConfig, ct)
            .ConfigureAwait(false);
        TryCopyClientToInteractiveUserDesktop(clientPath);

        // Update config: add pending. Take the same cross-process config
        // lock used by enrollment so appending Client02/Client03 cannot race
        // with the gateway consuming Client01's token. Reload under the lock
        // to preserve any changes made after the client executable was built.
        using (await ServiceConfigFileLock.AcquireAsync(serviceDir, ct).ConfigureAwait(false))
        {
            existingConfig = await ServiceConfigStore.LoadAsync(configPath, ct).ConfigureAwait(false);
            existingConfig.PendingOneTimeTokens ??= new List<PendingOneTimeToken>();
            if (existingConfig.PendingOneTimeTokens.Any(p =>
                string.Equals(p.ClientName, clientName, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"Client '{clientName}' already has a pending OTT. Enrollment must complete or remove pending entry first.");
            }

            var pendingEntry = new PendingOneTimeToken
            {
                ClientName = clientName!,
                OneTimeTokenHash = ottHash,
                CreatedAtUtc = DateTime.UtcNow.ToString("o"),
            };
            existingConfig.PendingOneTimeTokens.Add(pendingEntry);

            // For backward compat, if ActiveOneTimeTokenHash is null and this is the only pending,
            // we could optionally keep legacy field null (new behavior). Keep legacy as null for additional clients.
            // But if legacy field still holds old hash that was already consumed (null), leave null.

            await ServiceConfigStore.SaveAsync(configPath, existingConfig, ct).ConfigureAwait(false);
        }

        Result.ServiceDirectory = serviceDir;
        Result.ServerPrivateKeyPath = privPath;
        Result.ServerPublicKeyPath = pubPath;
        Result.ServerConfigPath = configPath;
        Result.AuthorisedUsersPath = authPath;
        Result.ClientExecutablePath = clientPath;
        Result.OneTimeToken = ott;
        Result.OneTimeTokenHash = ottHash;
        Result.WindowsServiceName = existingConfig.WindowsServiceName;
        Result.ClientName = clientName!;
        Result.GatewayPort = existingConfig.GatewayPort;
        Result.ClientTunnelPort = existingConfig.ClientTunnelPort;
        Result.Success = true;
        Result.IsAdditionalClient = true;
    }

    /// <summary>
    /// EP0a - refuse to create a new protected service unless the license covers
    /// it. Checks (a) that the protected protocol being created is in the
    /// licensed feature set and (b) that <c>max_services</c> is not already
    /// exhausted by the services that exist.
    ///
    /// Denial uses this engine's established <see cref="InvalidOperationException"/>
    /// convention, which SETUP MODE turns into "[setup] Failed:" + exit 1.
    /// </summary>
    private void AuthorizeNewProtectedService(string? applicationName)
    {
        // The feature identity comes from the single SSP mapping mechanism
        // (SspLicensing.Features). An application outside SSP's protected
        // protocol vocabulary carries no feature identity: it is not
        // feature-gated, but the license-state and limit gates below still
        // apply, and at runtime EP1/EP3 gate it like any other application.
        var feature = SspLicensing.Features.ResolveForApplication(applicationName);
        if (feature is not null)
        {
            var featureDecision = _license.CanUseFeature(feature);
            if (!featureDecision.IsAllowed)
            {
                throw new InvalidOperationException(
                    $"SSP licensing denies creating protected service '{applicationName}': feature " +
                    $"'{feature}' is not part of the licensed feature set (reason {featureDecision.ReasonCode}).");
            }
        }

        // Usage BEFORE the grant: every complete application directory that
        // already exists. The directory being created does not exist yet, so it
        // is not counted (and must not be excluded either).
        var existingServices = SspProtectedServiceInventory.CountProtectedServices();
        var serviceDecision = _license.CanStartProtectedService(existingServices);
        if (!serviceDecision.IsAllowed)
        {
            throw new InvalidOperationException(
                $"SSP licensing denies creating another protected service: {existingServices} protected " +
                $"service instance(s) already exist (reason {serviceDecision.ReasonCode}).");
        }
    }

    /// <summary>
    /// EP0b - refuse to provision an additional client once <c>max_clients</c>
    /// is reached. The count is the number of clients already authorized for
    /// this application (<c>.index.dat</c>), measured before the grant.
    /// </summary>
    private async Task AuthorizeAdditionalClientAsync(string authPath, CancellationToken ct)
    {
        long authorisedClients = 0;
        if (File.Exists(authPath))
        {
            var users = await AuthorisedUsersStore.LoadAsync(authPath, ct).ConfigureAwait(false);
            authorisedClients = users.Users.Count;
        }

        var decision = _license.CanEnrollClient(authorisedClients);
        if (!decision.IsAllowed)
        {
            throw new InvalidOperationException(
                $"SSP licensing denies provisioning another client: {authorisedClients} client(s) are " +
                $"already authorized for this application (reason {decision.ReasonCode}).");
        }
    }

    private static void ValidateNewApplicationParameters(SetupParameters p)
    {
        if (string.IsNullOrWhiteSpace(p.ApplicationName))
            throw new ArgumentException("ApplicationName is required.");
        if (string.IsNullOrWhiteSpace(p.GatewayPublicIpAddress))
            throw new ArgumentException("GatewayPublicIpAddress is required.");
        if (p.GatewayPort < 1 || p.GatewayPort > 65535)
            throw new ArgumentException("GatewayPort out of range.");
        if (p.LocalApplicationPort < 1 || p.LocalApplicationPort > 65535)
            throw new ArgumentException("LocalApplicationPort out of range.");
        if (p.ClientTunnelPort < 1 || p.ClientTunnelPort > 65535)
            throw new ArgumentException("ClientTunnelPort out of range.");
        if (!string.IsNullOrWhiteSpace(p.ClientName))
            ValidateClientName(p.ClientName!);
    }

    private static void ValidateClientName(string clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
            throw new ArgumentException("ClientName is required.");

        // No path separators, no invalid file name chars, length check
        if (clientName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException($"ClientName '{clientName}' contains invalid characters.");

        if (clientName.Contains('/') || clientName.Contains('\\'))
            throw new ArgumentException($"ClientName '{clientName}' must not contain path separators.");

        if (clientName.Length > 64)
            throw new ArgumentException("ClientName too long (max 64).");

        // Simple alphanumeric + dash/underscore
        // Allow MSRD style but enforce no spaces? Requirement examples use Client01.
        // We will allow letters, digits, dash, underscore.
        foreach (var c in clientName)
        {
            if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_' ))
                throw new ArgumentException($"ClientName '{clientName}' must be alphanumeric with dash/underscore only.");
        }
    }

    /// <summary>
    /// Reject a NEW Application whose ports would collide with a sibling
    /// Application under the same <c>services/</c> root.
    ///
    /// Every SSP connection is an independent Server + Service, and its
    /// lifecycle depends on exclusive use of two ports:
    ///   - GatewayPort on the SERVER: two services sharing it means the
    ///     second gateway can never bind, so its clients see a gateway
    ///     that is permanently unreachable while the first service
    ///     looks healthy.
    ///   - ClientTunnelPort on the CLIENT machine: two connections of
    ///     the SAME client sharing it means the second executable can
    ///     never bind its local tunnel listener.
    ///
    /// Failing setup loudly here (naming both services and both ports)
    /// is far cheaper than diagnosing a "second connection never
    /// completes enrollment" field report. Standalone service
    /// directories (no <c>services/</c> root) have no siblings to
    /// compare against and are untouched.
    /// </summary>
    internal static void ValidateNoSiblingPortCollisions(string serviceDir, SetupParameters parameters)
    {
        DirectoryInfo? parent;
        try { parent = Directory.GetParent(Path.GetFullPath(serviceDir)); }
        catch { return; }
        if (parent == null ||
            !parent.Name.Equals("services", StringComparison.OrdinalIgnoreCase))
            return;

        string fullServiceDir;
        try { fullServiceDir = Path.GetFullPath(serviceDir); }
        catch { return; }

        var appName = string.IsNullOrWhiteSpace(parameters.ApplicationName)
            ? string.Empty
            : parameters.ApplicationName.Trim();
        var clientName = string.IsNullOrWhiteSpace(parameters.ClientName)
            ? "Client01"
            : parameters.ClientName!.Trim();

        IEnumerable<string> siblings;
        try { siblings = Directory.EnumerateDirectories(parent.FullName); }
        catch { return; }

        foreach (var sibling in siblings)
        {
            string fullSibling;
            try { fullSibling = Path.GetFullPath(sibling); }
            catch { continue; }
            if (string.Equals(fullSibling, fullServiceDir, StringComparison.OrdinalIgnoreCase))
                continue;

            var siblingConfigPath = Path.Combine(sibling, ".cache.dat");
            if (!File.Exists(siblingConfigPath))
                continue;

            ServiceConfig siblingConfig;
            try
            {
                siblingConfig = ServiceConfigStore.LoadAsync(siblingConfigPath).GetAwaiter().GetResult();
            }
            catch
            {
                continue; // unreadable sibling config: not ours to judge
            }

            if (string.IsNullOrWhiteSpace(siblingConfig.ApplicationName))
                continue;

            // Same Application in another directory is a provisioning-layout
            // question, not a port collision between different connections.
            if (appName.Length > 0 &&
                string.Equals(siblingConfig.ApplicationName, appName, StringComparison.OrdinalIgnoreCase))
                continue;

            if (siblingConfig.GatewayPort == parameters.GatewayPort)
            {
                throw new ArgumentException(
                    $"GatewayPort {parameters.GatewayPort} is already used by service " +
                    $"'{siblingConfig.ApplicationName}' in {fullSibling}. Each SSP service " +
                    "needs its own gateway port; two gateways can never share one port.");
            }

            if (siblingConfig.ClientTunnelPort == parameters.ClientTunnelPort &&
                Directory.Exists(Path.Combine(sibling, clientName)))
            {
                throw new ArgumentException(
                    $"ClientTunnelPort {parameters.ClientTunnelPort} is already used by service " +
                    $"'{siblingConfig.ApplicationName}' for client '{clientName}'. Two connections " +
                    "of one client installation cannot share a local tunnel port; choose a " +
                    "different ClientTunnelPort for this service.");
            }
        }
    }

    /// <summary>
    /// Extract embedded client template, copy it, patch the copy with
    /// the supplied ClientConfig, validate, write to targetPath.
    ///
    /// The executable also gets its embedded client_services.json
    /// resource seeded with this single connection, so a client built by
    /// this method alone is already self-describing. The merged bundle
    /// of a whole client installation is written by
    /// <see cref="PersistClientServiceBundleAsync"/>.
    /// </summary>
    public static async Task BuildPatchedClientAsync(string targetPath, ClientConfig cfg, CancellationToken ct = default)
    {
        var asm = Assembly.GetExecutingAssembly();
        var resourceName = EmbeddedResourceNames.ClientTemplate;

        byte[] templateBytes;
        await using (var ms = new MemoryStream())
        {
            await using var rs = asm.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException(
                    $"Embedded client template resource '{resourceName}' not found. " +
                    "Rebuild SSP.Server so the build target embeds SSP.Client.");
            await rs.CopyToAsync(ms, ct);
            templateBytes = ms.ToArray();
        }

        if (ClientTemplate.FindPatchSlotRange(templateBytes) == null)
            throw new InvalidDataException(
                "Embedded client template does not contain a patch slot. " +
                "Rebuild SSP.Client with the patch slot string baked in.");

        if (ClientTemplate.FindServicesSlotRange(templateBytes) == null)
            throw new InvalidDataException(
                "Embedded client template does not contain a client_services slot. " +
                "Rebuild SSP.Client with the client_services marker baked in.");

        var patchedBytes = ClientTemplate.PatchCopy(templateBytes, cfg);
        ClientTemplate.ValidatePatch(patchedBytes, cfg);

        // Embed this connection's client_services.json inside the same
        // executable: the client ships as a single EXE, with no sidecar.
        var seeded = ClientTemplate.PatchServicesSlot(
            patchedBytes,
            new ClientServiceBundle { Services = new List<ClientConfig> { cfg } }.ToJson());
        if (seeded.Length != patchedBytes.Length)
            throw new InvalidDataException(
                "Embedding client_services.json changed the client binary length.");

        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
        await AtomicFile.WriteBytesAsync(targetPath, seeded, ct);

        if (!OperatingSystem.IsWindows())
        {
            try { File.SetUnixFileMode(targetPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
            catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Embed the <c>client_services.json</c> bundle into every client
    /// executable of <paramref name="clientDirectory"/> so one process
    /// can open independent tunnels for several Applications. No sidecar
    /// file is created. Does not change per-service server directories
    /// or OTTs.
    /// </summary>
    public static async Task WriteClientServiceBundleAsync(
        string clientDirectory,
        IEnumerable<ClientConfig> services,
        CancellationToken ct = default)
    {
        var bundle = new ClientServiceBundle { Services = services.ToList() };

        foreach (var binary in ClientServiceBundle.EnumeratePatchedClientBinaries(clientDirectory))
            await ClientServiceBundle.WriteEmbeddedAsync(binary, bundle, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Create or update the embedded <c>client_services.json</c> of the
    /// patched client executables. When this Application lives under a
    /// canonical <c>services/</c> root, same-ClientName folders of
    /// sibling Applications are merged so one client process opens every
    /// provisioned service. Multi-client folders (Client02 vs Client01)
    /// stay isolated.
    /// </summary>
    internal static async Task PersistClientServiceBundleAsync(
        string serviceDir,
        string clientDir,
        string clientName,
        ClientConfig current,
        CancellationToken ct = default)
    {
        var services = new List<ClientConfig>();
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetFullPath(clientDir),
        };

        // Siblings first so existing RDP/WEB order is preserved and the
        // Application being provisioned is appended (or replaced in place).
        foreach (var siblingClientDir in EnumerateSiblingClientDirectories(serviceDir, clientName))
        {
            destinations.Add(siblingClientDir);
            AbsorbClientDirectory(siblingClientDir, clientName, services);
        }

        AbsorbClientDirectory(clientDir, clientName, services);
        ClientServiceBundle.Upsert(services, current);

        foreach (var dest in destinations)
        {
            Directory.CreateDirectory(dest);
            await WriteClientServiceBundleAsync(dest, services, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Sibling Application directories only when the parent folder is
    /// named <c>services</c> (interactive --setup / default layout).
    /// Arbitrary temp parents are not scanned so parallel tests and
    /// unrelated trees cannot leak ClientConfigs.
    /// </summary>
    internal static IEnumerable<string> EnumerateSiblingClientDirectories(string serviceDir, string clientName)
    {
        DirectoryInfo? parent;
        try { parent = Directory.GetParent(Path.GetFullPath(serviceDir)); }
        catch { yield break; }

        if (parent == null ||
            !parent.Name.Equals("services", StringComparison.OrdinalIgnoreCase))
            yield break;

        IEnumerable<string> siblings;
        try { siblings = Directory.EnumerateDirectories(parent.FullName); }
        catch { yield break; }

        foreach (var sibling in siblings)
        {
            if (!IsExistingApplicationDirectory(sibling))
                continue;

            var dir = Path.Combine(sibling, clientName);
            if (!Directory.Exists(dir))
                continue;

            yield return Path.GetFullPath(dir);
        }
    }

    /// <summary>
    /// Collect the connections a client directory already knows about,
    /// reading them from the client executables themselves: first the
    /// <c>client_services.json</c> embedded in each executable, then its
    /// patch slot. Nothing is read from (or written to) a sidecar file.
    /// </summary>
    private static void AbsorbClientDirectory(
        string clientDir,
        string clientName,
        List<ClientConfig> services)
    {
        if (!Directory.Exists(clientDir))
            return;

        foreach (var binary in ClientServiceBundle.EnumeratePatchedClientBinaries(clientDir))
        {
            byte[] bytes;
            try { bytes = File.ReadAllBytes(binary); }
            catch { continue; }

            ClientServiceBundle? embedded = null;
            try { embedded = ClientServiceBundle.LoadEmbedded(bytes); }
            catch
            {
                // Unreadable embedded bundle: still try the patch slot.
            }

            if (embedded != null)
            {
                foreach (var s in embedded.Services)
                {
                    if (BelongsToClient(s, clientName))
                        ClientServiceBundle.Upsert(services, s);
                }
            }

            if (!ClientServiceBundle.TryReadPatchedConfig(bytes, out var cfg))
                continue;
            if (!BelongsToClient(cfg, clientName))
                continue;
            ClientServiceBundle.Upsert(services, cfg);
        }
    }

    private static bool BelongsToClient(ClientConfig cfg, string clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
            return true;
        if (string.IsNullOrWhiteSpace(cfg.ClientName))
            return true;
        return string.Equals(cfg.ClientName, clientName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Best-effort copy of the generated Client EXE onto the Desktop of
    /// the interactive user who launched SSP.Server.exe. The original
    /// file is never moved. Failures are logged and never fail setup.
    /// </summary>
    internal static void TryCopyClientToInteractiveUserDesktop(string clientPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(clientPath) || !File.Exists(clientPath))
                return;

            var desktop = Environment.GetFolderPath(
                Environment.SpecialFolder.DesktopDirectory,
                Environment.SpecialFolderOption.DoNotVerify);
            if (string.IsNullOrWhiteSpace(desktop))
                desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (string.IsNullOrWhiteSpace(desktop))
            {
                Console.Error.WriteLine(
                    "[setup] Could not resolve the interactive user's Desktop; " +
                    "skipping Client EXE copy.");
                return;
            }

            Directory.CreateDirectory(desktop);
            var dest = Path.Combine(desktop, Path.GetFileName(clientPath));
            File.Copy(clientPath, dest, overwrite: true);
            Console.WriteLine($"[setup] Copied Client EXE to Desktop: {dest}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[setup] Failed to copy Client EXE to Desktop (setup continues): {ex.Message}");
        }
    }
}

/// <summary>Input parameters for SETUP MODE.</summary>
public sealed class SetupParameters
{
    public string ApplicationName { get; set; } = string.Empty;
    public string GatewayPublicIpAddress { get; set; } = string.Empty;
    public int GatewayPort { get; set; }
    public int LocalApplicationPort { get; set; }
    public int ClientTunnelPort { get; set; }
    public string? ServiceDirectory { get; set; }

    /// <summary>
    /// Friendly client name, e.g. Client01, Client02. Required for additional client provisioning,
    /// optional for first-time setup (defaults to Client01).
    /// </summary>
    public string? ClientName { get; set; }

    /// <summary>
    /// On Windows, install and start the real SCM service as part of setup.
    /// Defaults to true for production. False for tests hosting gateway in-process.
    /// </summary>
    public bool InstallWindowsService { get; set; } = true;
}

/// <summary>Output of a SETUP MODE run, including final success state.</summary>
public sealed class SetupResult
{
    public bool Success { get; set; }
    public string ServiceDirectory { get; set; } = string.Empty;

    // The ports are part of the setup output contract: callers use them to
    // address the gateway and the client-side tunnel that were provisioned.
    public int GatewayPort { get; set; }
    public int ClientTunnelPort { get; set; }
    public string ServerPrivateKeyPath { get; set; } = string.Empty;
    public string ServerPublicKeyPath { get; set; } = string.Empty;
    public string ServerConfigPath { get; set; } = string.Empty;
    public string AuthorisedUsersPath { get; set; } = string.Empty;
    public string ClientExecutablePath { get; set; } = string.Empty;
    public string OneTimeToken { get; set; } = string.Empty;
    public string OneTimeTokenHash { get; set; } = string.Empty;
    public string? WindowsServiceName { get; set; }
    public string? ClientName { get; set; }
    public bool IsAdditionalClient { get; set; }
}
