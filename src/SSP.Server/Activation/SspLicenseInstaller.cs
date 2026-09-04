using SSP.Activation;
using SSP.Core.IO;

namespace SSP.Server.Activation;

/// <summary>
/// Validates a license artifact and atomically installs it at the canonical
/// licensing location. Validation is deliberately performed against the wired
/// activation service before the target file is touched.
/// </summary>
public static class SspLicenseInstaller
{
    public static async Task<LicenseValidationResult> InstallAsync(
        SspActivationService activation,
        string sourcePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activation);
        if (string.IsNullOrWhiteSpace(sourcePath))
            throw new ArgumentException("License artifact path is required.", nameof(sourcePath));

        var source = Path.GetFullPath(sourcePath);
        if (!File.Exists(source))
            throw new FileNotFoundException("License artifact was not found.", source);

        var info = new FileInfo(source);
        if (info.Length > LicenseArtifactCodec.MaxArtifactCharacters)
            throw new InvalidDataException("License artifact exceeds the maximum supported size.");

        var artifact = await File.ReadAllTextAsync(source, cancellationToken).ConfigureAwait(false);

        // LoadLicense runs the complete existing validation pipeline, including
        // signature, product, installation, validity window, revocation and
        // anti-rollback checks. Do not write anything unless it passes.
        var result = activation.Manager.LoadLicense(artifact);
        if (!result.IsValid)
            return result;

        // AtomicFile writes a sibling temporary file and replaces the target,
        // so a crash cannot leave a truncated installed artifact.
        await AtomicFile.WriteTextAsync(
            activation.Paths.LicenseFilePath,
            artifact,
            cancellationToken).ConfigureAwait(false);

        return result;
    }
}
