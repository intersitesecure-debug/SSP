// File: src/SSP.Core/IO/StateWitnessPaths.cs
//
// Canonical location of the REDUNDANT anti-rollback witness files (Security
// Correction roadmap Phase 4 / M-3).
//
// A single durable state file can be deleted or rolled back to an older copy
// by a local administrator with filesystem access. The witness is a second,
// independently stored copy of the monotonic security state (installation
// binding, write epoch, highest accepted value). Because it lives OUTSIDE the
// directory it protects — one directory level above, in a hidden per-purpose
// tree — the cheap attacks no longer work:
//
//   * deleting only the protected state file leaves the witness intact, so
//     the floor can be recovered (deletion no longer means "fresh install");
//   * restoring an older copy of only the protected state file is detected
//     because the witnessed epoch is higher than the file's (rollback);
//   * restoring the whole protected DIRECTORY from a backup also misses the
//     witness, which lives in a sibling directory.
//
// Restoring the witness as well — i.e. reconstructing the entire machine or
// product-root state from a backup — remains possible for a local
// administrator; that coordinated-rollback residual is documented in the
// threat model and is outside what offline, software-only protection can
// eliminate.
//
// Layout (witness of the state in <dir>, for purpose P):
//
//   {parent of <dir>}/.ssp-state-witness/P/{sha256(normalized <dir>)[0..31]}/.witness.dat
//
// The witness FILE NAME is a fixed constant so ProtectedFileStore encrypts
// every witness at rest (the directory-hash segment makes the file name
// itself dynamic). The path-key hash isolates witnesses of different
// directories (and therefore different tests / redirects) from each other,
// and is case-insensitive-normalized on Windows so two spellings of one
// directory share one witness.

using System.Security.Cryptography;
using System.Text;

namespace SSP.Core.IO;

/// <summary>
/// Canonical paths of the redundant anti-rollback witness files.
/// </summary>
public static class SspStateWitnessPaths
{
    /// <summary>Hidden directory (in the PARENT of each protected directory) holding witness trees.</summary>
    public const string WitnessRootDirectoryName = ".ssp-state-witness";

    /// <summary>
    /// Fixed file name of every witness file. Registered in
    /// <see cref="ProtectedFileStore"/> so witnesses are encrypted at rest;
    /// only witness files may use this name.
    /// </summary>
    public const string WitnessFileName = ".witness.dat";

    /// <summary>Purpose segment for the license anti-rollback state witness (see SspLicenseStateStore).</summary>
    public const string LicenseStatePurpose = "license";

    /// <summary>Purpose segment for the enrollment anti-rollback state witness (see ServerProtocol).</summary>
    public const string EnrollmentPurpose = "enrollment";

    /// <summary>Length (hex characters) of the directory-key hash used in witness paths.</summary>
    private const int DirectoryKeyHexLength = 32;

    /// <summary>
    /// Resolves the witness file path for the anti-rollback state stored in
    /// <paramref name="protectedDirectory"/>. The witness deliberately lives
    /// OUTSIDE that directory (one level above it), so deleting, rolling back
    /// or restoring the protected directory itself cannot take the witness
    /// with it.
    /// </summary>
    /// <param name="protectedDirectory">
    /// Directory whose state the witness protects (e.g. the licensing
    /// directory for the license-state witness, a service directory for the
    /// enrollment witness). Any spelling of the same directory resolves to
    /// the same witness path.
    /// </param>
    /// <param name="purpose">Purpose segment (<see cref="LicenseStatePurpose"/> or <see cref="EnrollmentPurpose"/>).</param>
    public static string GetWitnessPath(string protectedDirectory, string purpose)
    {
        if (string.IsNullOrWhiteSpace(protectedDirectory))
        {
            throw new ArgumentException("Protected directory must not be null or empty.", nameof(protectedDirectory));
        }

        if (string.IsNullOrWhiteSpace(purpose))
        {
            throw new ArgumentException("Purpose must not be null or empty.", nameof(purpose));
        }

        var canonical = Path.GetFullPath(protectedDirectory);
        canonical = Path.TrimEndingDirectorySeparator(canonical);

        // The witness lives in the PARENT of the protected directory. A
        // protected directory at the filesystem root (degenerate, never used
        // by SSP layouts) has no parent; fall back to the directory itself so
        // GetWitnessPath always returns a usable path.
        var witnessRootParent = Path.GetDirectoryName(canonical);
        if (string.IsNullOrEmpty(witnessRootParent))
        {
            witnessRootParent = canonical;
        }

        return Path.Combine(
            witnessRootParent,
            WitnessRootDirectoryName,
            purpose,
            ComputeDirectoryKey(canonical),
            WitnessFileName);
    }

    /// <summary>
    /// Stable identity of a protected directory for witness pathing. The path
    /// is case-normalized on Windows (where two casings name one directory)
    /// and hashed with SHA-256; only directories, never file content, are
    /// hashed here.
    /// </summary>
    private static string ComputeDirectoryKey(string canonicalDirectory)
    {
        var normalized = OperatingSystem.IsWindows()
            ? canonicalDirectory.ToUpperInvariant()
            : canonicalDirectory;

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(hash).ToLowerInvariant()[..DirectoryKeyHexLength];
    }
}
