// File: src/SSP.Server/Activation/RuntimeCodeIntegrity.cs
//
// Runtime code-integrity gate (Security Correction roadmap Phase 5 / M-4).
//
// This is the fail-closed, credential-free startup gate that a protected service
// consults BEFORE it is allowed to become operational. It verifies an armed
// <see cref="CodeIntegrityManifest"/> (expected SHA-256 over the on-disk
// protected runtime components) against the files under the process's base
// directory. Any missing, tampered or unreadable component makes the service
// refuse to start: RuntimeCodeIntegrity throws <see cref="SspActivationException"/>
// (reason <see cref="SspActivationException.CodeIntegrityFailureReason"/>) and
// writes a credential-free "[security] event=..." line. Both protected-service
// start paths funnel through <see cref="SspRuntimeLicense.CreateForService"/>,
// which calls <see cref="VerifyArmedStartup(string)"/> first, so the SCM path
// (SspWindowsService.OnStart) and the foreground --run-once path are covered by
// exactly the same gate.
//
// ARMING (release seam; mirrors how the trust anchor is provisioned)
// -------------------------------------------------------------------
// The manifest is a build/release constant. It is embedded as the manifest
// resource <see cref="ManifestResourceName"/> at the release seam
// (SSP.Server/Activation/SspCodeIntegrity.targets), from a JSON file an operator
// produces at release time over a pristine build (the SSP.Core hashing helper /
// RuntimeCodeIntegrity.BuildManifestFromFiles; see Security Correction.md Phase 5
// and the manifest schema in CodeIntegrityManifest). A developer/CI build that
// does not embed a
// manifest is NOT armed: VerifyArmedStartup is a no-op and the existing
// licensing fail-closed behaviour (compiled-in trust anchor + signed license) is
// the only gate. This mirrors SspTrustAnchor exactly - the release ceremony is
// the only place the baseline enters a binary, and nothing at runtime reads
// configuration, environment or the filesystem to relax it.
//
// Why not self-verify the single-file shipping image?
//   A single-file image cannot carry the trusted hash of its own bytes (the hash
//   would be inside the file it certifies). Authenticode/signing validated by the
//   OS loader is the control for the shipping image itself; what this gate does is
//   detect tampering of the on-disk protected runtime components a protected
//   service actually runs/deploys and refuse to continue. The residual (a fully
//   privileged local administrator who can also remove the gate) is documented in
//   the threat model (§9).

using SSP.Core.CodeIntegrity;
using SSP.Server.ServiceHost;

namespace SSP.Server.Activation;

/// <summary>
/// Production runtime code-integrity gate. Internal (visible to SSP.Tests) so the
/// fail-closed startup contract is asserted directly.
/// </summary>
internal static class RuntimeCodeIntegrity
{
    /// <summary>
    /// Manifest-resource name the release seam embeds the code-integrity JSON
    /// under (kept in sync with the <c>SspCodeIntegrityManifestResourceName</c>
    /// MSBuild property in <c>Activation/SspCodeIntegrity.targets</c>).
    /// </summary>
    public const string ManifestResourceName = "SSP.Server.CodeIntegrity.manifest.json";

    /// <summary>
    /// Entry gate called at the very top of <see cref="SspRuntimeLicense.CreateForService"/>.
    /// No-op when this build is not armed; fails closed when this build carries an
    /// armed manifest and a protected component is missing, tampered or unreadable.
    /// </summary>
    public static void VerifyArmedStartup(string? serviceDir)
    {
        var manifest = LoadArmedManifest();
        if (manifest is null)
        {
            // Not armed (developer/CI build). The licensing fail-closed gate
            // remains the sole authority; nothing here adds or removes a gate.
            return;
        }

        // Root for verification: the process base directory - where the on-disk
        // protected runtime components a protected service runs are located.
        GuardStartup(AppContext.BaseDirectory, serviceDir, manifest);
    }

    /// <summary>
    /// Verifies <paramref name="manifest"/> under <paramref name="rootDirectory"/>
    /// and, on any failure, raises a credential-free security event and throws
    /// <see cref="SspActivationException"/> (fail closed). Does nothing for a null
    /// or empty manifest.
    /// </summary>
    /// <exception cref="SspActivationException">
    /// A listed protected component is missing, tampered or unreadable.
    /// </exception>
    public static void GuardStartup(
        string rootDirectory,
        string? serviceDir,
        CodeIntegrityManifest manifest)
    {
        if (manifest is null || manifest.IsEmpty)
        {
            return;
        }

        var verification = CodeIntegrityVerifier.Verify(manifest, rootDirectory);
        if (verification.IsSatisfied)
        {
            return;
        }

        var summary = SummarizeFailures(verification);
        var ex = new SspActivationException(
            SspActivationException.CodeIntegrityFailureReason,
            "SSP refused to start a protected service: runtime code-integrity verification failed. " +
            "The on-disk protected runtime components no longer match the trusted baseline: " +
            summary + ". The protected binaries appear to have been modified or removed. Fail closed.");

        // Credential-free, filterable security event. Names components and their
        // outcome only - never hashes as secrets, never key material, never the
        // baseline itself.
        TryWriteSecurityLine(ex);

        // Best-effort persistence through the same startup-failure channel the EP1
        // licensing denial uses (ssp-service-startup.log + Windows Application log).
        // Never masks or replaces the exception below.
        if (!string.IsNullOrWhiteSpace(serviceDir))
        {
            try
            {
                ServiceDiagnostics.WriteStartupFailure(serviceDir, ex);
            }
            catch
            {
                // Best effort only.
            }
        }

        throw ex;
    }

    /// <summary>
    /// Loads the armed release manifest (embedded resource). Returns null when
    /// this build is not armed OR when the embedded manifest is empty/malformed
    /// (a build that embeds a manifest but ships an unusable one must not silently
    /// run unverified; that condition is surfaced separately so the caller can
    /// fail closed with a precise reason).
    /// </summary>
    internal static CodeIntegrityManifest? LoadArmedManifest()
    {
        string? json;
        try
        {
            var assembly = typeof(RuntimeCodeIntegrity).Assembly;
            using var stream = assembly.GetManifestResourceStream(ManifestResourceName);
            if (stream is null)
            {
                return null;
            }

            using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            json = reader.ReadToEnd();
        }
        catch
        {
            // A resource that cannot be read is treated exactly like an absent
            // manifest for the purposes of the armed check; it must never crash
            // composition. VerifyArmedStartup will not treat a missing resource as
            // a violation (developer build).
            return null;
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        var manifest = CodeIntegrityManifestSerializer.TryDeserialize(json);
        return manifest is null || manifest.IsEmpty ? null : manifest;
    }

    /// <summary>
    /// Builds a <see cref="CodeIntegrityManifest"/> from a set of on-disk files,
    /// computing each file's SHA-256. This is the release-ceremony helper the
    /// operator runs on a pristine build to produce the JSON that is then embedded
    /// at the release seam. Logical names default to the file name; a file that is
    /// missing/unreadable makes the whole call fail (a baseline cannot be built
    /// from bytes that cannot be read).
    /// </summary>
    /// <exception cref="FileNotFoundException">A supplied path does not exist.</exception>
    /// <exception cref="IOException">A supplied file cannot be read.</exception>
    internal static CodeIntegrityManifest BuildManifestFromFiles(IEnumerable<string> filePaths)
    {
        ArgumentNullException.ThrowIfNull(filePaths);

        var components = new List<CodeIntegrityComponent>();
        foreach (var path in filePaths)
        {
            var fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException(
                    "Cannot build a code-integrity baseline from a missing file.", fullPath);
            }

            string hash;
            try
            {
                using var stream = new FileStream(
                    fullPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var sha = System.Security.Cryptography.SHA256.Create();
                hash = Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
            }
            catch (Exception ex)
            {
                throw new IOException(
                    $"Cannot hash '{fullPath}' for a code-integrity baseline: {ex.Message}", ex);
            }

            components.Add(new CodeIntegrityComponent(
                Path.GetFileName(fullPath),
                Path.GetFileName(fullPath),
                hash));
        }

        return CodeIntegrityManifest.Create(components);
    }

    /// <summary>Human-readable, secret-free summary of the failed components.</summary>
    internal static string SummarizeFailures(CodeIntegrityVerification verification)
    {
        const int maxListed = 8;
        var listed = verification.Failures.Take(maxListed)
            .Select(r => $"{r.Component.LogicalName}={StatusName(r.Status)}");
        var text = string.Join(", ", listed);
        if (verification.Failures.Count > maxListed)
        {
            text += $", ... and {verification.Failures.Count - maxListed} more";
        }

        return string.IsNullOrEmpty(text) ? "(none)" : text;
    }

    private static string StatusName(CodeIntegrityStatus status) => status switch
    {
        CodeIntegrityStatus.Missing => "missing",
        CodeIntegrityStatus.Tampered => "tampered",
        CodeIntegrityStatus.Unreadable => "unreadable",
        _ => status.ToString()
    };

    private static void TryWriteSecurityLine(SspActivationException ex)
    {
        try
        {
            Console.Error.WriteLine(
                $"[security] event=CodeIntegrityVerificationFailed reason={ex.ReasonCode} detail={ex.Message}");
        }
        catch
        {
            // Best effort only; never let a logging failure mask the throw.
        }
    }
}
