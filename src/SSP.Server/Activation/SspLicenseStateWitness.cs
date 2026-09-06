// File: src/SSP.Server/Activation/SspLicenseStateWitness.cs
//
// Redundant durable copy of the monotonic license-state values (Security
// Correction roadmap Phase 4 / M-3), stored OUTSIDE the licensing directory
// (see SspStateWitnessPaths). The witness holds exactly the fields that must
// never regress:
//
//   * the installation binding of the state,
//   * the monotonic write epoch,
//   * the highest accepted license sequence number (the anti-rollback floor),
//   * the last accepted and activated license ids (restriction-relevant:
//     ActivatedLicenseId gates activation-required licenses).
//
// Like the primary state record, the witness can only RESTRICT authorization
// — it never grants anything. A missing witness is never a violation (the
// primary state file is authoritative while it is intact and consistent); a
// present-but-unreadable, plaintext or foreign-bound witness is an integrity
// violation and fails closed.

using System.Security.Cryptography;
using System.Text.Json;
using SSP.Core.IO;

namespace SSP.Server.Activation;

/// <summary>
/// The subset of <see cref="SSP.Activation.LicenseStateRecord"/> that is
/// redundantly witnessed outside the licensing directory.
/// </summary>
public sealed record LicenseStateWitness
{
    /// <summary>Installation binding of the witnessed state (null before Phase 4 / on unbound hosts).</summary>
    public string? InstallationId { get; init; }

    /// <summary>Highest state-write epoch ever durably recorded for this installation.</summary>
    public long StateEpoch { get; init; }

    /// <summary>Highest accepted license sequence number ever durably recorded (the anti-rollback floor).</summary>
    public long HighestAcceptedSequenceNumber { get; init; }

    /// <summary>License id most recently accepted (diagnostics).</summary>
    public Guid? LastAcceptedLicenseId { get; init; }

    /// <summary>License id whose activation was accepted (restriction-relevant state).</summary>
    public Guid? ActivatedLicenseId { get; init; }
}

/// <summary>
/// File-backed load/save of <see cref="LicenseStateWitness"/> through the
/// encrypted-at-rest envelope (<see cref="ProtectedFileStore"/>). Reads fail
/// closed: an absent file yields null (no witness established yet); a
/// present-but-corrupt, undecryptable or PLAINTEXT witness throws
/// <see cref="InvalidDataException"/> — a legitimate witness is always
/// envelope-encrypted, so plaintext material in the witness slot is tampering.
/// </summary>
public static class SspLicenseStateWitnessStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };

    /// <summary>
    /// Loads the witness at <paramref name="path"/>. Null when no witness
    /// file exists. Throws <see cref="InvalidDataException"/> for any
    /// present-but-unusable witness (integrity violation, fail closed).
    /// </summary>
    public static LicenseStateWitness? Load(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var read = ProtectedFileStore.ReadTextAsync(path).GetAwaiter().GetResult();

            // A legitimate witness is always written through the encrypted
            // envelope. Plaintext (or foreign non-envelope) bytes in the
            // witness slot are hand-crafted material: fail closed.
            if (!read.WasEncrypted)
            {
                throw new InvalidDataException(
                    "License state witness is not in the SSP encrypted-at-rest envelope.");
            }

            if (string.IsNullOrWhiteSpace(read.Text))
            {
                throw new InvalidDataException("License state witness file is empty.");
            }

            var witness = JsonSerializer.Deserialize<LicenseStateWitness>(read.Text, SerializerOptions);
            if (witness is null)
            {
                throw new InvalidDataException("License state witness could not be deserialized.");
            }

            return witness;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException
                                   or InvalidDataException or CryptographicException
                                   or PlatformNotSupportedException)
        {
            throw new InvalidDataException(
                $"License state witness could not be read: {ex.GetType().Name}", ex);
        }
    }

    /// <summary>
    /// Atomically writes the witness at <paramref name="path"/> in the
    /// encrypted-at-rest envelope. Throws on failure — callers decide whether
    /// a witness write is best effort (the licensing store: yes, a lagging
    /// witness is the safe direction) or critical.
    /// </summary>
    public static void Save(string path, LicenseStateWitness witness)
    {
        if (witness is null)
        {
            throw new ArgumentNullException(nameof(witness));
        }

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(witness, SerializerOptions);
        ProtectedFileStore.WriteTextAsync(path, json).GetAwaiter().GetResult();
    }
}
