// File: src/SSP.Server/Activation/SspTrustAnchor.cs
//
// SSP-native trust-anchor composition. The Licensing Authority public key is
// the single root of trust for activation. It is a BUILD/RELEASE constant of
// the SSP shipping builds - it is provisioned into the assembly at build time
// by the release key ceremony and is never loaded from user-editable
// configuration, environment variables or the filesystem at runtime - so no
// configuration change on a customer machine can ever install a usable
// verification key. The private signing key never exists in this repository
// or in any shipped SSP binary.
//
// ---------------------------------------------------------------------------
// HOW THE PUBLIC KEY GETS IN (the release key ceremony seam)
// ---------------------------------------------------------------------------
// The anchor is provisioned at build time, by MSBuild, from a PEM file that
// lives OUTSIDE this repository (see src/SSP.Server/Activation/SspTrustAnchor.targets
// and TRUST_ANCHOR_KEY_CEREMONY.md):
//
//     dotnet publish src/SSP.Server/SSP.Server.csproj -c Release \
//         -p:SspRequireTrustAnchor=true \
//         -p:SspAuthorityPublicKeyPemFile=<path to authority-public.pem> \
//         -p:SspAuthorityPublicKeySha256=<expected SPKI SHA-256>
//
// MSBuild embeds that PEM as the manifest resource named by
// <see cref="AuthorityPublicKeyResourceName"/> inside SSP.Server.dll and records
// the expected SHA-256 of its SubjectPublicKeyInfo as assembly metadata. Both
// therefore travel inside the compiled, Authenticode-signable binary exactly
// like SSP's other embedded release material (the client and service-host
// images) - they are not files an operator can drop next to the executable and
// not values an environment variable can supply.
//
// WHY A MANIFEST RESOURCE RATHER THAN A SOURCE-CODE STRING LITERAL
//   * the key ceremony must never require an edit-and-commit of key material
//     into git (the blueprint's requirement: "the public key is set at the
//     release key ceremony", the private key never enters the repository);
//   * a resource is embedded verbatim - no escaping, no re-formatting, no risk
//     of a corrupted literal - and is byte-verifiable in the shipped binary;
//   * it is still *compiled in*: the resource is part of the assembly image, so
//     the runtime rule "the anchor cannot come from config/env/disk" holds.
//
// Fail-closed contract (unchanged and strengthened):
//   * no anchor provisioned            -> Create() throws, IsCompiledIn false;
//   * anchor present but malformed     -> Create() throws (never a partial anchor);
//   * anchor present but < 2048 bits   -> Create() throws;
//   * anchor present but does not match the fingerprint recorded at the
//     ceremony (assembly metadata pin) -> Create() throws.
// In every case the callers (SspActivationService.Create, SspRuntimeLicense)
// refuse to produce a licensing runtime, so no protected operation can be
// authorized.

using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using SSP.Activation;

namespace SSP.Server.Activation;

/// <summary>
/// Secret-free description of the trust anchor provisioned into this build.
/// Produced by <see cref="SspTrustAnchor.Inspect"/>; safe to print.
/// </summary>
/// <param name="IsProvisioned">A trust anchor was provisioned into this build.</param>
/// <param name="IsUsable">The provisioned anchor imports, meets the key-size floor and matches the pin.</param>
/// <param name="Source">Where the anchor came from (ceremony file name, or "(not provisioned)").</param>
/// <param name="KeySizeBits">Imported key size, 0 when the anchor is missing or unusable.</param>
/// <param name="PublicKeySha256">Lowercase hex SHA-256 of the anchored SubjectPublicKeyInfo, null when unusable.</param>
/// <param name="PinnedPublicKeySha256">The fingerprint recorded at the ceremony, when one was pinned.</param>
/// <param name="Error">Secret-free diagnosis when <paramref name="IsUsable"/> is false.</param>
public sealed record SspTrustAnchorInfo(
    bool IsProvisioned,
    bool IsUsable,
    string Source,
    int KeySizeBits,
    string? PublicKeySha256,
    string? PinnedPublicKeySha256,
    string? Error)
{
    /// <summary>True when the anchored key meets the ceremony's recommended strength.</summary>
    public bool MeetsRecommendedKeySize => KeySizeBits >= SspTrustAnchor.RecommendedKeySizeBits;

    /// <summary>Operator-facing, secret-free single-block report.</summary>
    public string Describe()
    {
        var builder = new StringBuilder();
        builder.AppendLine("SSP Licensing Authority trust anchor");
        builder.AppendLine($"  Provisioned        : {(IsProvisioned ? "yes" : "no")}");
        builder.AppendLine($"  Usable             : {(IsUsable ? "yes" : "no")}");
        builder.AppendLine($"  Source             : {Source}");
        if (IsUsable)
        {
            builder.AppendLine($"  Key size           : {KeySizeBits} bits" +
                (MeetsRecommendedKeySize
                    ? string.Empty
                    : $" (BELOW the recommended {SspTrustAnchor.RecommendedKeySizeBits})"));
            builder.AppendLine($"  SPKI SHA-256       : {PublicKeySha256}");
            builder.AppendLine($"  Pinned fingerprint : {PinnedPublicKeySha256 ?? "(none recorded)"}");
        }
        else
        {
            builder.AppendLine($"  Diagnosis          : {Error}");
        }

        return builder.ToString();
    }
}

/// <summary>
/// Owns the release-provisioned SSP Licensing Authority public key and builds
/// the <see cref="LicenseTrustAnchor"/> used by the activation runtime.
/// </summary>
public static class SspTrustAnchor
{
    /// <summary>
    /// Manifest-resource name the release build embeds the authority public key
    /// PEM under (see <c>Activation/SspTrustAnchor.targets</c>). Kept in sync with
    /// the <c>SspAuthorityPublicKeyResourceName</c> MSBuild property.
    /// </summary>
    public const string AuthorityPublicKeyResourceName = "SSP.Server.Activation.AuthorityPublicKey.pem";

    /// <summary>
    /// Assembly-metadata key carrying the SHA-256 (lowercase hex, over the DER
    /// SubjectPublicKeyInfo) of the key that was embedded at the ceremony. When
    /// present it is enforced at runtime: an anchor that does not match the
    /// fingerprint recorded at the ceremony is refused.
    /// </summary>
    public const string PublicKeyFingerprintMetadataKey = "SspAuthorityPublicKeySha256";

    /// <summary>Assembly-metadata key naming the ceremony file the key came from (diagnostics only).</summary>
    public const string PublicKeySourceMetadataKey = "SspAuthorityPublicKeySource";

    /// <summary>Minimum RSA key size accepted for the trusted anchor (library floor).</summary>
    public const int MinimumKeySizeBits = LicenseTrustAnchor.MinimumKeySizeBits;

    /// <summary>Key size the SSP key ceremony mandates for the production authority key.</summary>
    public const int RecommendedKeySizeBits = 3072;

    /// <summary>Reported <see cref="SspTrustAnchorInfo.Source"/> when no anchor is provisioned.</summary>
    public const string NotProvisionedSource = "(not provisioned)";

    private static readonly Lazy<string> LazyPem = new(LoadEmbeddedPem, isThreadSafe: true);
    private static readonly Lazy<string?> LazyPin = new(
        () => NormalizeFingerprint(ReadAssemblyMetadata(PublicKeyFingerprintMetadataKey)), isThreadSafe: true);
    private static readonly Lazy<string> LazySource = new(
        () =>
        {
            var recorded = ReadAssemblyMetadata(PublicKeySourceMetadataKey);
            if (!string.IsNullOrWhiteSpace(recorded))
            {
                return recorded!.Trim();
            }

            return string.IsNullOrWhiteSpace(LazyPem.Value)
                ? NotProvisionedSource
                : $"embedded resource {AuthorityPublicKeyResourceName}";
        },
        isThreadSafe: true);

    /// <summary>
    /// The SSP Licensing Authority RSA public key in PEM ("PUBLIC KEY") format,
    /// as provisioned into this build; the empty string when this build carries
    /// no anchor. Public key material only - the authority private key never
    /// exists in this repository or in any shipped binary.
    /// </summary>
    public static string AuthorityPublicKeyPem => LazyPem.Value;

    /// <summary>
    /// The SPKI SHA-256 fingerprint recorded at the release key ceremony
    /// (lowercase hex), or null when no fingerprint was pinned into the build.
    /// </summary>
    public static string? PinnedAuthorityPublicKeySha256 => LazyPin.Value;

    /// <summary>Where this build's anchor came from (ceremony file name); diagnostics only.</summary>
    public static string ProvisionedSource => LazySource.Value;

    /// <summary>
    /// True when this build has an actual trust anchor provisioned in. Builds
    /// without one return false and all production composition entry points
    /// fail closed rather than pretending to be licensed.
    /// </summary>
    public static bool IsCompiledIn => !string.IsNullOrWhiteSpace(AuthorityPublicKeyPem);

    /// <summary>
    /// Creates the production trust anchor from the release-provisioned public
    /// key. This is the ONLY way a shipped SSP binary obtains its root of trust.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// No trust anchor is provisioned into this build, or the provisioned anchor
    /// is malformed, too weak, or does not match the pinned ceremony
    /// fingerprint. Fail closed in every case.
    /// </exception>
    public static LicenseTrustAnchor Create()
    {
        if (!IsCompiledIn)
        {
            throw new InvalidOperationException(
                "SSP activation trust anchor is not compiled into this build. " +
                "Provision the SSP Licensing Authority public key at the release key " +
                "ceremony (-p:SspAuthorityPublicKeyPemFile=<authority-public.pem>) and " +
                "rebuild before shipping a production-protecting build.");
        }

        return ImportAuthorityPublicKey(
            AuthorityPublicKeyPem,
            ProvisionedSource,
            PinnedAuthorityPublicKeySha256);
    }

    /// <summary>
    /// Imports and validates an SSP Licensing Authority public key PEM under the
    /// exact rules the production anchor must satisfy: a single "PUBLIC KEY"
    /// block, no private key material, a parsable SubjectPublicKeyInfo, at least
    /// <see cref="MinimumKeySizeBits"/> bits and - when
    /// <paramref name="expectedSha256"/> is supplied - a matching SPKI
    /// fingerprint.
    /// </summary>
    /// <remarks>
    /// This is the shared validation used by <see cref="Create"/> for the
    /// release-provisioned key. It is NOT a runtime injection seam: production
    /// composition (<see cref="SspActivationService.Create"/>) only ever calls
    /// <see cref="Create"/>, which reads the compiled-in resource and nothing
    /// else. Exposing the validation makes the ceremony rules testable and lets
    /// the authority tooling verify a candidate key before a release build.
    /// </remarks>
    /// <param name="pem">Candidate authority public key PEM.</param>
    /// <param name="source">Secret-free description of where the PEM came from (used in diagnostics).</param>
    /// <param name="expectedSha256">Optional pinned SPKI SHA-256 (hex; ":"/whitespace/"sha256:" tolerated).</param>
    /// <exception cref="InvalidOperationException">The candidate key is unusable as an SSP trust anchor.</exception>
    public static LicenseTrustAnchor ImportAuthorityPublicKey(
        string? pem,
        string source = "(caller supplied)",
        string? expectedSha256 = null)
    {
        var describedSource = string.IsNullOrWhiteSpace(source) ? "(unspecified)" : source.Trim();

        if (string.IsNullOrWhiteSpace(pem))
        {
            throw new InvalidOperationException(
                $"SSP activation trust anchor from {describedSource} is empty. Fail closed.");
        }

        // Defense in depth: the authority PRIVATE key must never be embedded in,
        // or handed to, a relying party. LicenseTrustAnchor.FromPem would already
        // reject a private-key block by label, but a file that carries one is a
        // ceremony failure that must be named explicitly rather than reported as
        // a generic parse error.
        if (pem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"SSP activation trust anchor from {describedSource} contains PRIVATE KEY material. " +
                "The Licensing Authority private key must never be embedded in, or distributed with, " +
                "an SSP binary. Fail closed.");
        }

        LicenseTrustAnchor anchor;
        try
        {
            anchor = LicenseTrustAnchor.FromPem(pem);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"SSP activation trust anchor from {describedSource} is not a usable Licensing Authority " +
                $"public key ({ex.GetType().Name}: {ex.Message}). Fail closed.",
                ex);
        }

        try
        {
            // LicenseTrustAnchor enforces the 2048-bit floor at import; re-assert
            // it here so this method's contract does not silently depend on the
            // vendored library keeping that check.
            if (anchor.KeySizeBits < MinimumKeySizeBits)
            {
                throw new InvalidOperationException(
                    $"SSP activation trust anchor from {describedSource} is {anchor.KeySizeBits} bits; " +
                    $"at least {MinimumKeySizeBits} bits are required. Fail closed.");
            }

            var fingerprint = ComputeFingerprint(anchor);
            var pin = NormalizeFingerprint(expectedSha256);
            if (pin is not null && !string.Equals(pin, fingerprint, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"SSP activation trust anchor from {describedSource} does not match the fingerprint " +
                    $"recorded at the key ceremony (expected sha256:{pin}, found sha256:{fingerprint}). " +
                    "Fail closed.");
            }

            return anchor;
        }
        catch
        {
            anchor.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Secret-free inspection of this build's anchor. Never throws: used by the
    /// operator CLI and by the composition guards, both of which must be able to
    /// report "unusable" without crashing.
    /// </summary>
    public static SspTrustAnchorInfo Inspect()
    {
        var provisioned = IsCompiledIn;
        if (!provisioned)
        {
            return new SspTrustAnchorInfo(
                IsProvisioned: false,
                IsUsable: false,
                Source: NotProvisionedSource,
                KeySizeBits: 0,
                PublicKeySha256: null,
                PinnedPublicKeySha256: PinnedAuthorityPublicKeySha256,
                Error: "No Licensing Authority trust anchor is provisioned into this build " +
                       "(no embedded authority public key). No license can validate and no " +
                       "protected SSP service can start.");
        }

        try
        {
            using var anchor = Create();
            return new SspTrustAnchorInfo(
                IsProvisioned: true,
                IsUsable: true,
                Source: ProvisionedSource,
                KeySizeBits: anchor.KeySizeBits,
                PublicKeySha256: ComputeFingerprint(anchor),
                PinnedPublicKeySha256: PinnedAuthorityPublicKeySha256,
                Error: null);
        }
        catch (Exception ex)
        {
            return new SspTrustAnchorInfo(
                IsProvisioned: true,
                IsUsable: false,
                Source: ProvisionedSource,
                KeySizeBits: 0,
                PublicKeySha256: null,
                PinnedPublicKeySha256: PinnedAuthorityPublicKeySha256,
                Error: ex.Message);
        }
    }

    /// <summary>Lowercase-hex SHA-256 over the anchored DER SubjectPublicKeyInfo.</summary>
    public static string ComputeFingerprint(LicenseTrustAnchor anchor)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        return ComputeFingerprint(anchor.ExportSpkiDer());
    }

    /// <summary>Lowercase-hex SHA-256 over a DER SubjectPublicKeyInfo.</summary>
    public static string ComputeFingerprint(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(subjectPublicKeyInfo, digest);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>
    /// Normalizes a fingerprint for comparison: trims, drops an optional
    /// "sha256:" prefix, removes ":" separators and whitespace, lowercases.
    /// Returns null for null/blank input.
    /// </summary>
    public static string? NormalizeFingerprint(string? fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            return null;
        }

        var value = fingerprint.Trim();
        if (value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            value = value["sha256:".Length..];
        }

        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (char.IsAsciiHexDigit(ch))
            {
                builder.Append(char.ToLowerInvariant(ch));
            }
            else if (ch is ':' or '-' or ' ' or '\t' or '\r' or '\n')
            {
                continue;
            }
            else
            {
                // Anything else makes the pin unusable as a fingerprint; keep the
                // character so the comparison fails loudly instead of silently
                // matching a sanitized prefix.
                builder.Append(ch);
            }
        }

        var normalized = builder.ToString();
        return normalized.Length == 0 ? null : normalized;
    }

    private static string LoadEmbeddedPem()
    {
        try
        {
            var assembly = typeof(SspTrustAnchor).Assembly;
            using var stream = assembly.GetManifestResourceStream(AuthorityPublicKeyResourceName);
            if (stream is null)
            {
                return string.Empty;
            }

            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return reader.ReadToEnd();
        }
        catch
        {
            // A resource that cannot be read is treated exactly like an absent
            // anchor: fail closed, never guess a key.
            return string.Empty;
        }
    }

    private static string? ReadAssemblyMetadata(string key)
    {
        try
        {
            foreach (var attribute in typeof(SspTrustAnchor).Assembly
                         .GetCustomAttributes<AssemblyMetadataAttribute>())
            {
                if (string.Equals(attribute.Key, key, StringComparison.Ordinal))
                {
                    return attribute.Value;
                }
            }
        }
        catch
        {
            // Metadata is diagnostics/pin material only; an unreadable attribute
            // must not crash the composition guards.
        }

        return null;
    }
}
