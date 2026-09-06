// File: src/SSP.Core/CodeIntegrity/CodeIntegrityVerifier.cs
//
// Streaming SHA-256 verifier for <see cref="CodeIntegrityManifest"/>.
//
// Semantics are fail-closed and deterministic:
//   * a listed component that is absent        => Missing;
//   * a listed component that cannot be read   => Unreadable (never a throw);
//   * a listed component whose bytes differ    => Tampered;
//   * the aggregate is satisfied ONLY when the manifest is non-empty and every
//     component is Ok.
//
// A single IOException/UnreadableFile is deliberately NOT an exception: on the
// startup path, an unverifiable protected component must refuse the protected
// service, not crash the verifier and accidentally let the caller continue.

using System.Security.Cryptography;

namespace SSP.Core.CodeIntegrity;

/// <summary>
/// Verifies an on-disk set of protected components against a
/// <see cref="CodeIntegrityManifest"/> of expected SHA-256 hashes.
/// </summary>
public static class CodeIntegrityVerifier
{
    /// <summary>
    /// Verifies every component of <paramref name="manifest"/> under
    /// <paramref name="rootDirectory"/>. Never throws for a missing/unreadable/
    /// tampered file; those become component outcomes. Throws only for a null
    /// argument.
    /// </summary>
    /// <param name="manifest">The expected-hash manifest (never null).</param>
    /// <param name="rootDirectory">
    /// Directory each component's <see cref="CodeIntegrityComponent.FileName"/> is
    /// resolved against. A component that would escape the root (e.g. via "..")
    /// is reported as <see cref="CodeIntegrityStatus.Unreadable"/> so a malformed
    /// manifest can never read arbitrary files.
    /// </param>
    public static CodeIntegrityVerification Verify(CodeIntegrityManifest manifest, string rootDirectory)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(rootDirectory);

        var results = new List<CodeIntegrityComponentResult>(manifest.ComponentCount);
        foreach (var component in manifest.Components)
        {
            results.Add(VerifyComponent(component, rootDirectory));
        }

        return new CodeIntegrityVerification { Results = results };
    }

    private static CodeIntegrityComponentResult VerifyComponent(
        CodeIntegrityComponent component,
        string rootDirectory)
    {
        var fullPath = ResolveWithinRoot(rootDirectory, component.FileName);
        if (fullPath is null || !File.Exists(fullPath))
        {
            return new CodeIntegrityComponentResult(
                component,
                CodeIntegrityStatus.Missing,
                Diagnostic: "file not found under the verification root");
        }

        string actualSha256;
        try
        {
            actualSha256 = HashFileSha256(fullPath);
        }
        catch (Exception ex)
        {
            // Unreadable is a FAILED integrity outcome, never an exception. The
            // protected service must not start when a protected component cannot
            // be proven intact.
            return new CodeIntegrityComponentResult(
                component,
                CodeIntegrityStatus.Unreadable,
                Diagnostic: ex.GetType().Name);
        }

        var expected = NormalizeHex(component.ExpectedSha256Hex);
        var ok = string.Equals(expected, actualSha256, StringComparison.Ordinal);
        return new CodeIntegrityComponentResult(
            component,
            ok ? CodeIntegrityStatus.Ok : CodeIntegrityStatus.Tampered,
            ActualSha256Hex: actualSha256,
            Diagnostic: ok ? null : "content does not match the expected hash");
    }

    /// <summary>Streaming SHA-256 over a file's bytes (lowercase hex).</summary>
    private static string HashFileSha256(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    /// <summary>
    /// Combines root + fileName and ensures the result stays inside the root.
    /// Returns null when the file name escapes the root.
    /// </summary>
    private static string? ResolveWithinRoot(string rootDirectory, string fileName)
    {
        string root;
        try
        {
            root = Path.GetFullPath(rootDirectory);
        }
        catch
        {
            return null;
        }

        string combined;
        try
        {
            combined = Path.GetFullPath(Path.Combine(root, fileName));
        }
        catch
        {
            return null;
        }

        var rootWithSep = root.EndsWith(Path.DirectorySeparatorChar) || root.EndsWith(Path.AltDirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;

        if (!combined.StartsWith(rootWithSep, StringComparison.Ordinal) &&
            !string.Equals(combined, root, StringComparison.Ordinal))
        {
            return null;
        }

        return combined;
    }

    private static string NormalizeHex(string hex) => hex.Trim().ToLowerInvariant();
}
