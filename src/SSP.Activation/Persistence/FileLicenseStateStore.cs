using System.Text.Json;

namespace SSP.Activation;

/// <summary>
/// Durable, file-backed <see cref="ILicenseStateStore"/> for anti-rollback. Writes are
/// atomic (write to a temp file, then move it into place) and reads fail closed: a corrupt
/// or unreadable state file is reported as an error by <see cref="Load"/> so that validation
/// fails closed, never silently resetting the anti-rollback floor.
///
/// This is a repository-local persistence implementation using only the BCL. For stronger
/// tamper-resistance SSP.Core should supply a DPAPI/TPM-protected or ACL-guarded store (see
/// docs/ARCHITECTURE.md §10). The store is never a security boundary: it can only restrict
/// authorization (reject older sequences), never grant it.
/// </summary>
public sealed class FileLicenseStateStore : ILicenseStateStore
{
    private readonly string _path;
    private readonly object _gate = new();

    public FileLicenseStateStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("State store path must not be null or empty.", nameof(path));
        }

        _path = path;
    }

    /// <summary>The path of the underlying state file.</summary>
    public string Path => _path;

    public LicenseStateRecord? Load()
    {
        lock (_gate)
        {
            if (!File.Exists(_path))
            {
                // Fresh installation: no anti-rollback floor has been established.
                return null;
            }

            try
            {
                var json = File.ReadAllText(_path);
                if (string.IsNullOrWhiteSpace(json))
                {
                    throw new InvalidDataException("State store file is empty.");
                }

                var record = JsonSerializer.Deserialize<LicenseStateRecord>(json);
                if (record is null)
                {
                    throw new InvalidDataException("State store file could not be deserialized.");
                }

                return record;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or InvalidDataException)
            {
                // Fail closed: a corrupt or unreadable state store must never silently reset
                // the anti-rollback floor (which could re-enable an older license).
                throw new InvalidDataException($"License state store could not be read: {ex.GetType().Name}", ex);
            }
        }
    }

    public void Save(LicenseStateRecord record)
    {
        if (record is null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        lock (_gate)
        {
            var directory = System.IO.Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(record);
            var temp = _path + ".tmp";
            File.WriteAllText(temp, json);
            File.Move(temp, _path, overwrite: true);
        }
    }
}
