// File: tests/SSP.Tests/Helpers/LicensedTestEnvironment.cs
//
// Builds a REAL SSP licensing runtime for integration tests: an ephemeral
// Licensing Authority key, a genuinely signed ssp-license artifact on disk, and
// the production adapters (SspLicensePaths, SspLicenseStateStore,
// SspSecurityEventSink, LocalLicenseFileProvider) composed through
// SspActivationService.Compose - the same graph SspActivationService.Create
// wires in production, with only the trust anchor and the clock supplied by the
// test.
//
// This is what lets the runtime tests in tests/SSP.Tests/Activation/Runtime
// assert real SSP behaviour (a real ServerGateway, a real ServerProtocol, a real
// client handshake) rather than a mock's opinion about it.
//
// The ephemeral authority key exists only inside this test helper and is
// disposed with it. It is never written to disk: the artifact on disk is the
// public, signed license file, exactly as in production.

using System.Security.Cryptography;
using SSP.Activation;
using SSP.Core.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Helpers;

/// <summary>Controllable clock so expiry / not-before / revalidation can be tested deterministically.</summary>
public sealed class TestClock : IClock
{
    public TestClock(DateTimeOffset utcNow) => UtcNow = utcNow;

    public DateTimeOffset UtcNow { get; set; }

    public void Advance(TimeSpan by) => UtcNow = UtcNow.Add(by);
}

/// <summary>What the issued license should say.</summary>
public sealed class LicensedTestOptions
{
    public static readonly DateTimeOffset DefaultNow = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Application name of the protected service (drives feature resolution).</summary>
    public string ApplicationName { get; set; } = "RDP";

    /// <summary>Features in the license payload. Defaults to every feature SSP knows.</summary>
    public string[]? Features { get; set; }

    /// <summary>Limits in the license payload. Absent limits are unconstrained.</summary>
    public Dictionary<string, long?> Limits { get; set; } = new();

    public DateTimeOffset? Now { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? IssuedAt { get; set; }
    public Guid? ProductId { get; set; }
    public string? InstallationId { get; set; }
    public string? OrganizationOrPersonName { get; set; }
    public string? ComputerName { get; set; }
    public LicenseStatus Status { get; set; } = LicenseStatus.Active;
    public long SequenceNumber { get; set; } = 1;

    /// <summary>Issue a version-2 (certified) artifact instead of the legacy root-signed one.</summary>
    public bool Certified { get; set; }

    /// <summary>The certified license requires activation (carries an OTT + code hash).</summary>
    public bool ActivationRequired { get; set; }

    /// <summary>
    /// The activation code to sign into the certification. When null and
    /// <see cref="ActivationRequired"/> is true, a random code is generated and exposed via
    /// <see cref="LicensedTestEnvironment.IssuedActivationCode"/>.
    /// </summary>
    public string? ActivationCode { get; set; }

    /// <summary>
    /// When true the artifact is signed by an UNRELATED authority key, so it
    /// fails signature verification against the compiled anchor (the "tampered
    /// license" / "wrong authority" scenario).
    /// </summary>
    public bool SignWithForeignAuthority { get; set; }

    /// <summary>When true no license file is written at all (the "missing license" scenario).</summary>
    public bool OmitLicenseFile { get; set; }

    /// <summary>When true the artifact JSON is corrupted after signing (the "malformed artifact" scenario).</summary>
    public bool CorruptArtifact { get; set; }

    /// <summary>Use the production DPAPI/AES-GCM state store instead of an in-memory one.</summary>
    public bool UseDurableStateStore { get; set; } = true;

    /// <summary>Installation identity reported by the provider (null = floating license).</summary>
    public string? HostInstallationId { get; set; }

    /// <summary>
    /// Policy override. Defaults to the production fail-closed
    /// <see cref="DefaultLicensePolicy"/>; tests use a throwing policy to prove a
    /// policy failure can never fail open.
    /// </summary>
    public ILicensePolicy? Policy { get; set; }

    /// <summary>State store override (e.g. a store whose Load throws).</summary>
    public ILicenseStateStore? StateStore { get; set; }
}

/// <summary>
/// A complete, real licensing runtime plus the on-disk license artifact it reads.
/// </summary>
public sealed class LicensedTestEnvironment : IDisposable
{
    private readonly RSA _authority;
    private readonly RSA? _foreignAuthority;
    private bool _disposed;

    private LicensedTestEnvironment(
        string licenseDirectory,
        SspLicensePaths paths,
        RSA authority,
        RSA? foreignAuthority,
        TestClock clock,
        InMemorySecurityEventSink events,
        ILicenseStateStore stateStore,
        SspActivationService activation,
        SspRuntimeLicense gate,
        LicensedTestOptions options)
    {
        LicenseDirectory = licenseDirectory;
        Paths = paths;
        _authority = authority;
        _foreignAuthority = foreignAuthority;
        Clock = clock;
        Events = events;
        StateStore = stateStore;
        Activation = activation;
        Gate = gate;
        Options = options;
    }

    public string LicenseDirectory { get; }
    public SspLicensePaths Paths { get; }
    public TestClock Clock { get; }
    public InMemorySecurityEventSink Events { get; }

    /// <summary>The wired anti-rollback state store (the production DPAPI/AES-GCM adapter by default).</summary>
    public ILicenseStateStore StateStore { get; }

    public SspActivationService Activation { get; }
    public SspRuntimeLicense Gate { get; }
    public LicensedTestOptions Options { get; }
    public string LicenseFilePath => Paths.LicenseFilePath;
    public string StateStorePath => Paths.StateStorePath;

    /// <summary>The activation code the environment signed into the license (when activation-required).</summary>
    public string? IssuedActivationCode { get; private set; }

    /// <summary>The activation OTT the environment signed into the license (when activation-required).</summary>
    public string? IssuedActivationOtt { get; private set; }

    /// <summary>The license payload this environment issues by default.</summary>
    public LicensePayload DefaultPayload => BuildPayload(Options);

    /// <summary>
    /// Creates the environment: temp licensing directory, ephemeral authority,
    /// signed artifact on disk, composed activation runtime and production gate.
    /// The license is NOT loaded automatically - call <see cref="Load"/> so a
    /// test can control exactly when validation happens.
    /// </summary>
    public static LicensedTestEnvironment Create(LicensedTestOptions? options = null)
    {
        var opts = options ?? new LicensedTestOptions();
        var now = opts.Now ?? LicensedTestOptions.DefaultNow;

        var dir = Path.Combine(
            Path.GetTempPath(),
            "ssp-licensed-env-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        var paths = SspLicensePaths.Resolve(dir);
        var authority = RSA.Create(2048);
        var foreign = opts.SignWithForeignAuthority ? RSA.Create(2048) : null;
        var clock = new TestClock(now);
        var events = new InMemorySecurityEventSink();
        ILicenseStateStore stateStore = opts.StateStore
            ?? (opts.UseDurableStateStore
                ? new SspLicenseStateStore(paths.StateStorePath)
                : new InMemoryLicenseStateStore());

        var activation = SspActivationService.Compose(
            paths,
            LicenseTrustAnchor.FromPublicKey(authority),
            new StaticInstallationIdentityProvider(opts.HostInstallationId),
            events,
            stateStore,
            new LocalLicenseFileProvider(paths.LicenseFilePath),
            clock,
            opts.Policy);

        var gate = new SspRuntimeLicense(
            activation,
            SspLicensing.Features.ResolveForApplication(opts.ApplicationName),
            ownsActivation: true);

        var env = new LicensedTestEnvironment(
            dir, paths, authority, foreign, clock, events, stateStore, activation, gate, opts);

        if (!opts.OmitLicenseFile)
        {
            // Exercise the artifact failure modes the options describe.  The
            // production runtime must receive the artifact that the scenario
            // asks for; silently signing every initial artifact with the trusted
            // test authority made the tampered/foreign-authority tests exercise
            // a valid license instead of the fail-closed path.
            if (opts.SignWithForeignAuthority)
            {
                env.WriteLicenseSignedByForeignAuthority(env.DefaultPayload);
            }
            else if (opts.CorruptArtifact)
            {
                env.WriteCorruptedLicense(env.DefaultPayload);
            }
            else if (opts.Certified)
            {
                env.WriteCertifiedLicense(env.DefaultPayload, opts.ActivationRequired, opts.ActivationCode);
            }
            else
            {
                env.WriteLicense(env.DefaultPayload);
            }
        }

        return env;
    }

    /// <summary>
    /// Composes a SECOND production gate over the SAME license artifact, state
    /// store and trust anchor - exactly what a second protected service process
    /// on the same host does. Used by the connection-isolation tests to prove
    /// that licensing decisions and usage counters belong to one service, while
    /// the artifact they are measured against is shared.
    /// The caller owns the returned gate and must dispose it.
    /// </summary>
    public SspRuntimeLicense CreateAdditionalServiceGate(string applicationName)
    {
        var activation = SspActivationService.Compose(
            Paths,
            LicenseTrustAnchor.FromPublicKey(_authority),
            new StaticInstallationIdentityProvider(Options.HostInstallationId),
            Events,
            StateStore,
            new LocalLicenseFileProvider(Paths.LicenseFilePath),
            Clock);

        return new SspRuntimeLicense(
            activation,
            SspLicensing.Features.ResolveForApplication(applicationName),
            ownsActivation: true);
    }

    /// <summary>Reads and validates the artifact through the wired provider.</summary>
    public LicenseValidationResult Load() => Activation.Load();

    /// <summary>
    /// Revalidates through the wired provider. Provider-backed revalidation
    /// re-reads the artifact, so installed renewals are observed without a
    /// process restart.
    /// </summary>
    public LicenseValidationResult Revalidate() => Activation.Revalidate();

    /// <summary>Re-reads the artifact from disk through the production gate.</summary>
    public LicenseValidationResult Reload() => Gate.Reload();

    public LicenseState State => Activation.CurrentState;

    /// <summary>Builds a payload from the options (no signing, no I/O).</summary>
    public static LicensePayload BuildPayload(LicensedTestOptions opts)
    {
        var now = opts.Now ?? LicensedTestOptions.DefaultNow;
        var features = opts.Features ?? new[]
        {
            SspLicensing.Features.RemoteDesktopProtocol,
            SspLicensing.Features.SecureShell,
            SspLicensing.Features.Web,
            SspLicensing.Features.Sql,
        };

        return new LicensePayload
        {
            LicenseId = Guid.NewGuid(),
            ProductId = opts.ProductId ?? SspLicensing.ProductId,
            ProductName = SspLicensing.ProductName,
            CustomerId = Guid.NewGuid(),
            CustomerName = "Integration Test Customer",
            OrganizationOrPersonName = opts.OrganizationOrPersonName,
            ComputerName = opts.ComputerName,
            Edition = "Enterprise",
            LicenseVersion = "1.0",
            IssuedAt = opts.IssuedAt ?? now.AddDays(-30),
            NotBefore = opts.NotBefore ?? now.AddDays(-1),
            ExpiresAt = opts.ExpiresAt ?? now.AddDays(365),
            InstallationId = opts.InstallationId,
            FeatureSet = new LicenseFeatureSet(features),
            Limits = new LicenseLimits(opts.Limits.Select(kv => new KeyValuePair<string, long?>(kv.Key, kv.Value))),
            Status = opts.Status,
            SequenceNumber = opts.SequenceNumber,
        };
    }

    /// <summary>Issues and writes an artifact signed by THIS environment's authority.</summary>
    public void WriteLicense(LicensePayload payload) => WriteSigned(payload, _authority, corrupt: false);

    /// <summary>
    /// Issues and writes a version-2 certified artifact: the environment authority certifies
    /// a fresh leaf key, and the leaf key signs the payload. When
    /// <paramref name="activationRequired"/> is true, the certification also carries an OTT
    /// and the SHA-256 of <paramref name="activationCode"/> (or of a freshly generated code,
    /// exposed via <see cref="IssuedActivationCode"/>).
    /// </summary>
    public void WriteCertifiedLicense(LicensePayload payload, bool activationRequired, string? activationCode)
    {
        using var leaf = RSA.Create(2048);

        string? ott = null;
        string? codeHash = null;
        if (activationRequired)
        {
            ott = LicenseActivation.GenerateActivationOtt();
            var code = activationCode ?? LicenseActivation.GenerateActivationCode();
            codeHash = LicenseActivation.ComputeActivationCodeHash(code);
            IssuedActivationCode = code;
            IssuedActivationOtt = ott;
        }

        var certification = new LicenseKeyCertification
        {
            LicenseId = payload.LicenseId,
            ProductId = payload.ProductId,
            CustomerId = payload.CustomerId,
            NotBefore = payload.IssuedAt,
            ExpiresAt = payload.ExpiresAt,
            PublicKeySpkiDer = leaf.ExportSubjectPublicKeyInfo(),
            ActivationOtt = ott,
            ActivationCodeHash = codeHash
        };

        var artifact = LicenseCertificationIssuer.EncodeCertifiedLicenseArtifact(payload, certification, _authority, leaf);
        Directory.CreateDirectory(LicenseDirectory);
        File.WriteAllText(LicenseFilePath, artifact);
    }

    /// <summary>Writes an artifact signed by an unrelated key (signature must not verify).</summary>
    public void WriteLicenseSignedByForeignAuthority(LicensePayload payload)
    {
        var foreign = _foreignAuthority ?? throw new InvalidOperationException(
            "This environment was not created with SignWithForeignAuthority.");
        WriteSigned(payload, foreign, corrupt: false);
    }

    /// <summary>Writes a signed artifact whose JSON is then corrupted (malformed / invalid signature).</summary>
    public void WriteCorruptedLicense(LicensePayload payload) => WriteSigned(payload, _authority, corrupt: true);

    /// <summary>Writes raw artifact bytes, for tests that need a specific malformed envelope.</summary>
    public void WriteRawArtifact(string artifactJson) => File.WriteAllText(LicenseFilePath, artifactJson);

    /// <summary>Deletes the license file (deletion must never recover a lockdown).</summary>
    public void DeleteLicense()
    {
        if (File.Exists(LicenseFilePath))
        {
            File.Delete(LicenseFilePath);
        }
    }

    /// <summary>
    /// Issues a renewed/superseding license with a higher sequence number and
    /// writes it over the current one - the only way a lockdown is cleared.
    /// </summary>
    public LicenseValidationResult InstallRenewal(
        string[]? features = null,
        Dictionary<string, long?>? limits = null,
        DateTimeOffset? expiresAt = null)
    {
        // The reference schema requires issuedAt <= notBefore.  A renewal is
        // issued before its validity window opens, so both are anchored to the
        // same pre-window instant rather than issuedAt being "now".
        var notBefore = Clock.UtcNow.AddDays(-1);
        var renewal = new LicensedTestOptions
        {
            ApplicationName = Options.ApplicationName,
            Now = Clock.UtcNow,
            Features = features ?? Options.Features,
            Limits = limits ?? Options.Limits,
            ExpiresAt = expiresAt ?? Clock.UtcNow.AddDays(365),
            NotBefore = notBefore,
            IssuedAt = notBefore,
            ProductId = Options.ProductId,
            InstallationId = Options.InstallationId,
            Status = LicenseStatus.Active,
            SequenceNumber = Options.SequenceNumber + 1000,
        };

        WriteLicense(BuildPayload(renewal));
        return Reload();
    }

    private void WriteSigned(LicensePayload payload, RSA signingKey, bool corrupt)
    {
        var artifact = LicenseIssuer.EncodeLicenseArtifact(payload, signingKey);
        if (corrupt)
        {
            // Flip a character inside the base64url payload segment so the
            // canonical bytes no longer match the signature (or the envelope no
            // longer decodes). Both outcomes must fail closed.
            artifact = CorruptPayloadSegment(artifact);
        }

        Directory.CreateDirectory(LicenseDirectory);
        File.WriteAllText(LicenseFilePath, artifact);
    }

    private static string CorruptPayloadSegment(string artifact)
    {
        const string marker = "\"payload\":\"";
        var start = artifact.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return artifact + "\u0000";
        }

        var index = start + marker.Length + 4;
        if (index >= artifact.Length)
        {
            return artifact + "\u0000";
        }

        var replacement = artifact[index] == 'A' ? 'B' : 'A';
        return string.Concat(
            artifact.AsSpan(0, index),
            replacement.ToString(),
            artifact.AsSpan(index + 1));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try { Gate.Dispose(); } catch { /* best effort */ }
        try { _authority.Dispose(); } catch { /* best effort */ }
        try { _foreignAuthority?.Dispose(); } catch { /* best effort */ }
        try { Directory.Delete(LicenseDirectory, recursive: true); } catch { /* best effort */ }
    }
}
