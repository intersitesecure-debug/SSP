namespace SSP.Activation;

/// <summary>
/// Reads a license artifact from a local file. The file is transport only: it is never a
/// security boundary, and its content is always fully validated (signature, product,
/// installation, time window, revocation) before anything is authorized.
/// </summary>
public sealed class LocalLicenseFileProvider : ILicenseProvider
{
    private readonly string _filePath;

    public LocalLicenseFileProvider(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("File path must not be null or empty.", nameof(filePath));
        }

        _filePath = filePath;
    }

    public string FilePath => _filePath;

    public LicenseFetchResult FetchLicense()
    {
        if (!File.Exists(_filePath))
        {
            return LicenseFetchResult.Empty($"License file not found: {_filePath}");
        }

        try
        {
            var info = new FileInfo(_filePath);
            if (info.Length > LicenseArtifactCodec.MaxArtifactCharacters)
            {
                return LicenseFetchResult.Error(
                    $"License file exceeds the maximum size of {LicenseArtifactCodec.MaxArtifactCharacters} characters.");
            }

            var content = File.ReadAllText(_filePath);
            return LicenseFetchResult.FromArtifact(content);
        }
        catch (Exception ex)
        {
            // Transport errors fail closed: no artifact, no authorization.
            return LicenseFetchResult.Error($"License file could not be read: {ex.GetType().Name}");
        }
    }
}
