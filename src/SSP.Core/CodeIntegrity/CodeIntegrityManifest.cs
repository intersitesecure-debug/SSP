// File: src/SSP.Core/CodeIntegrity/CodeIntegrityManifest.cs
//
// Runtime code-integrity protection (Security Correction roadmap Phase 5 / M-4).
//
// This file defines the *manifest* model: an ordered, immutable list of
// protected components, each with an expected SHA-256 over its file bytes.
// A protected service refuses to start unless every listed component on disk
// matches the expected hash (fail closed). The manifest itself is the
// release-time data the runtime verifies against; it is embedded into the
// shipping SSP.Server/SSP.ServiceHost images at the release seam (mirroring
// how the Licensing Authority public key is provisioned by the key ceremony),
// never supplied by configuration, environment or the filesystem at runtime.
//
// Design notes (why this protects what it can, and what it cannot):
//   * A process cannot cryptographically certify its OWN single-file image: the
//     expected value would have to live inside the very file being verified.
//     The manifest therefore names the on-disk protected runtime components a
//     protected service actually runs and deploys (the SSP runtime assemblies,
//     and the standalone service-host/client images where they exist as files
//     next to the verified process). Tampering with any listed component is
//     detected before a protected service is allowed to start.
//   * Full tamper-resistance of the shipping image against a fully privileged
//     local administrator is a property of signed binaries validated by the OS
//     loader, not of in-process self-verification; that residual is documented
//     in the threat model (§9). What this subsystem delivers is deterministic
//     detection + fail-closed refusal + a credential-free security event.
//   * Nothing here is network-dependent and nothing weakens the RSA-PSS trust
//     chain; the signed license artifact remains the root of trust.

using System.Text;
using System.Text.Json;

namespace SSP.Core.CodeIntegrity;

/// <summary>
/// The verification outcome for a single protected component.
/// </summary>
public enum CodeIntegrityStatus
{
    /// <summary>The component was present and its bytes matched the expected hash.</summary>
    Ok,

    /// <summary>The component file was not found at the expected location.</summary>
    Missing,

    /// <summary>The component file was present but its bytes did not match the expected hash.</summary>
    Tampered,

    /// <summary>
    /// The component file could not be opened or hashed (permissions, sharing, I/O). A protected
    /// service treats this as a failure to prove integrity and fails closed.
    /// </summary>
    Unreadable
}

/// <summary>
/// One protected component: its logical name (for diagnostics/events), the file
/// name it is expected at (resolved relative to the verification root), and the
/// lowercase-hex SHA-256 of the pristine bytes.
/// </summary>
public sealed record CodeIntegrityComponent(
    string LogicalName,
    string FileName,
    string ExpectedSha256Hex);

/// <summary>
/// An immutable set of protected components to verify before a protected
/// operation may start. Empty manifests are meaningless and are treated as
/// unsatisfied by <see cref="CodeIntegrityVerifier"/>.
/// </summary>
public sealed class CodeIntegrityManifest
{
    private readonly IReadOnlyList<CodeIntegrityComponent> _components;

    private CodeIntegrityManifest(IReadOnlyList<CodeIntegrityComponent> components)
    {
        _components = components;
    }

    /// <summary>Creates an immutable manifest from the supplied components.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="components"/> is null.</exception>
    public static CodeIntegrityManifest Create(IEnumerable<CodeIntegrityComponent> components)
    {
        ArgumentNullException.ThrowIfNull(components);
        return new CodeIntegrityManifest(components.ToArray());
    }

    /// <summary>The ordered list of protected components.</summary>
    public IReadOnlyList<CodeIntegrityComponent> Components => _components;

    /// <summary>True when no protected component is listed.</summary>
    public bool IsEmpty => _components.Count == 0;

    /// <summary>The number of protected components in this manifest.</summary>
    public int ComponentCount => _components.Count;
}

/// <summary>
/// The verification result for a single protected component.
/// </summary>
public sealed record CodeIntegrityComponentResult(
    CodeIntegrityComponent Component,
    CodeIntegrityStatus Status,
    string? ActualSha256Hex = null,
    string? Diagnostic = null);

/// <summary>
/// The aggregate result of verifying a manifest. Fail closed by construction:
/// <see cref="IsSatisfied"/> is true ONLY when the manifest is non-empty and
/// every single component verified <see cref="CodeIntegrityStatus.Ok"/>.
/// </summary>
public sealed record CodeIntegrityVerification
{
    /// <summary>Per-component outcomes, in manifest order.</summary>
    public required IReadOnlyList<CodeIntegrityComponentResult> Results { get; init; }

    /// <summary>
    /// True only when the manifest is non-empty and every component verified Ok.
    /// A single missing, tampered or unreadable component makes this false.
    /// </summary>
    public bool IsSatisfied =>
        Results.Count > 0 && Results.All(r => r.Status == CodeIntegrityStatus.Ok);

    /// <summary>Components that did not verify Ok (missing/tampered/unreadable).</summary>
    public IReadOnlyList<CodeIntegrityComponentResult> Failures =>
        Results.Where(r => r.Status != CodeIntegrityStatus.Ok).ToArray();
}

/// <summary>
/// Deterministic, lossless JSON (de)serialization of <see cref="CodeIntegrityManifest"/>.
/// The JSON shape is a stable release contract:
/// <c>{"components":[{"logicalName":"...","fileName":"...","sha256":"..."}]}</c>.
/// Implemented on <see cref="Utf8JsonWriter"/>/<see cref="JsonDocument"/> so it does
/// not depend on a serializer instantiating helper DTOs.
/// </summary>
public static class CodeIntegrityManifestSerializer
{
    private const string ComponentsProperty = "components";
    private const string LogicalNameProperty = "logicalName";
    private const string FileNameProperty = "fileName";
    private const string Sha256Property = "sha256";

    /// <summary>Serializes a manifest to its canonical JSON form.</summary>
    public static string Serialize(CodeIntegrityManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartArray(ComponentsProperty);
            foreach (var component in manifest.Components)
            {
                writer.WriteStartObject();
                writer.WriteString(LogicalNameProperty, component.LogicalName);
                writer.WriteString(FileNameProperty, component.FileName);
                writer.WriteString(Sha256Property, component.ExpectedSha256Hex);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Parses the canonical JSON form of a manifest. Returns null when the text is
    /// not a well-formed manifest (malformed JSON, wrong shape, missing fields).
    /// An empty component list is valid JSON but yields an empty manifest; the
    /// startup guard treats an empty/absent manifest as not armed and the
    /// verifier treats it as unsatisfied.
    /// </summary>
    public static CodeIntegrityManifest? TryDeserialize(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (!root.TryGetProperty(ComponentsProperty, out var componentsElement) ||
                componentsElement.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var entries = new List<CodeIntegrityComponent>();
            foreach (var item in componentsElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object ||
                    !item.TryGetProperty(LogicalNameProperty, out var logicalName) ||
                    !item.TryGetProperty(FileNameProperty, out var fileName) ||
                    !item.TryGetProperty(Sha256Property, out var sha256) ||
                    logicalName.ValueKind != JsonValueKind.String ||
                    fileName.ValueKind != JsonValueKind.String ||
                    sha256.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                var logical = logicalName.GetString();
                var file = fileName.GetString();
                var hex = sha256.GetString();
                if (string.IsNullOrWhiteSpace(logical) ||
                    string.IsNullOrWhiteSpace(file) ||
                    string.IsNullOrWhiteSpace(hex))
                {
                    return null;
                }

                entries.Add(new CodeIntegrityComponent(
                    logical,
                    file,
                    hex.Trim().ToLowerInvariant()));
            }

            return CodeIntegrityManifest.Create(entries);
        }
    }
}
