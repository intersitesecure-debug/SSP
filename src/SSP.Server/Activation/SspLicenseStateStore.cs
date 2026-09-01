// File: src/SSP.Server/Activation/SspLicenseStateStore.cs
//
// SSP-native durable anti-rollback state store. It persists the
// LicenseStateRecord (highest accepted sequence number and diagnostics)
// through SSP.Core.ProtectedFileStore, so the file is written in the SSP-EAR1
// encrypted-at-rest envelope: DPAPI LocalMachine on Windows (the recorded
// floor cannot be decrypted by a copied licensing folder on another machine)
// and the repo's existing non-Windows AES-GCM fallback for cross-platform
// tests. Reads fail closed: DPAPI, I/O, authorization or JSON failures throw,
// which the licensing validator maps to state_store_unavailable.

using System.Security.Cryptography;
using System.Text.Json;
using SSP.Activation;
using SSP.Core.IO;

namespace SSP.Server.Activation;

/// <summary>
/// Durable, tamper-resistant (DPAPI-backed) anti-rollback floor for
/// <see cref="SSP.Activation.LicenseManager"/>. The store is never a security
/// boundary: it can only restrict authorization, never grant it.
/// </summary>
public sealed class SspLicenseStateStore : ILicenseStateStore
{
    /// <summary>Canonical name of the encrypted state file.</summary>
    public const string DefaultFileName = ".license-state.dat";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };

    private readonly string _path;
    private readonly object _gate = new();

    public SspLicenseStateStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("State store path must not be null or empty.", nameof(path));
        }

        _path = path;
    }

    /// <summary>The path of the underlying encrypted state file.</summary>
    public string Path => _path;

    /// <inheritdoc />
    /// <remarks>
    /// A missing file means no anti-rollback floor has been established yet.
    /// Any present-but-corrupt/unreadable file throws so the validator fails
    /// closed rather than silently resetting the floor.
    /// </remarks>
    public LicenseStateRecord? Load()
    {
        lock (_gate)
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            try
            {
                var read = ProtectedFileStore.ReadTextAsync(_path).GetAwaiter().GetResult();
                if (string.IsNullOrWhiteSpace(read.Text))
                {
                    throw new InvalidDataException("License state store file is empty.");
                }

                var record = JsonSerializer.Deserialize<LicenseStateRecord>(read.Text, SerializerOptions);
                if (record is null)
                {
                    throw new InvalidDataException("License state store file could not be deserialized.");
                }

                // A legacy plaintext state file is upgraded to the encrypted
                // envelope once it has been read successfully. Best effort:
                // a failed migration must not make an otherwise-readable state
                // unavailable (the next Save will re-write it encrypted).
                if (read.WasPlaintextProtectedFile)
                {
                    try
                    {
                        ProtectedFileStore.MigratePlaintextAsync(_path, read).GetAwaiter().GetResult();
                    }
                    catch
                    {
                        // Best effort only; keep the validated state available.
                    }
                }

                return record;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException
                                       or InvalidDataException or CryptographicException
                                       or PlatformNotSupportedException)
            {
                // Fail closed: a corrupt or unreadable state store must never
                // silently reset the anti-rollback floor.
                throw new InvalidDataException(
                    $"License state store could not be read: {ex.GetType().Name}", ex);
            }
        }
    }

    /// <inheritdoc />
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

            var json = JsonSerializer.Serialize(record, SerializerOptions);
            ProtectedFileStore.WriteTextAsync(_path, json).GetAwaiter().GetResult();
        }
    }
}
