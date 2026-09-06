// File: src/SSP.Server/Runtime/EnrollmentStateWitness.cs
//
// Redundant durable copy of the ENROLLMENT anti-rollback state (Security
// Correction roadmap Phase 4 / M-3, applying the same witness pattern as the
// license-state witness to the Phase 1/2 enrollment protections).
//
// The Phase 1/2 controls (failed Authentication Code counter, progressive
// cooldown, three-attempt OTT revocation, single-use OTT consumption) are
// persisted ONLY in the service directory's .cache.dat. A local administrator
// who restores an older copy of that file resets the guess budget, erases the
// cooldown, resurrects a revoked OTT, or revives a consumed OTT — exactly the
// rollback class the roadmap deferred to Phase 4.
//
// This witness stores, per hashed OTT (the credential-free key the Phase 1
// design already uses), the monotonic security state:
//
//   * FailedAttempts        — the highest failure count ever durably recorded,
//   * RetryNotBeforeUtc     — the latest cooldown instant ever recorded,
//   * Revoked               — sticky: the OTT hash was permanently revoked,
//   * Consumed             — sticky: the OTT hash was consumed by a completed
//                             enrollment.
//
// The witness lives OUTSIDE the service directory (one level above it, in the
// .ssp-state-witness/enrollment tree — see SspStateWitnessPaths), so
// restoring the service directory from a backup cannot take the witness with
// it. It is encrypted at rest (the fixed .witness.dat name is registered in
// ProtectedFileStore) and can only RESTRICT enrollment: it clamps counters
// and cooldowns upward, and makes revoked/consumed OTTs unrevivable. It never
// authorizes anything by itself.
//
// Ordering contract: .cache.dat is always written FIRST and the witness
// SECOND. A crash between the two leaves a lagging witness (the safe
// direction: the witness under-reports, never over-reports). The reverse
// order would let a crash resurrect state the config no longer has.

using System.Security.Cryptography;
using System.Text.Json;
using SSP.Core.Crypto;
using SSP.Core.IO;

namespace SSP.Server.Runtime;

/// <summary>
/// Per-hashed-OTT monotonic enrollment state held in the witness.
/// </summary>
public sealed class EnrollmentOttWitnessEntry
{
    /// <summary>Highest failed Authentication Code count ever durably recorded for this OTT.</summary>
    public int FailedAttempts { get; set; }

    /// <summary>Latest cooldown instant (ISO-8601 UTC) ever durably recorded for this OTT.</summary>
    public string? RetryNotBeforeUtc { get; set; }

    /// <summary>Sticky: the OTT hash was permanently revoked (Phase 1 three-attempt lockout).</summary>
    public bool Revoked { get; set; }

    /// <summary>Sticky: the OTT hash was consumed by a fully completed enrollment.</summary>
    public bool Consumed { get; set; }
}

/// <summary>
/// Root object of the enrollment-state witness file. Entries are keyed by the
/// SHA-256 hex hash of the OTT (the same credential-free identifier
/// <see cref="Models.ServiceConfig"/> stores); no OTT plaintext, code, key or
/// fingerprint ever enters this file.
/// </summary>
public sealed class EnrollmentStateWitnessFile
{
    public int Version { get; set; } = 1;

    public Dictionary<string, EnrollmentOttWitnessEntry> Entries { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Finds the witness entry for <paramref name="oneTimeTokenHash"/> using
    /// constant-time comparison, mirroring the .cache.dat matching style (the
    /// witness is an anti-rollback record, not an authentication oracle; the
    /// constant-time discipline is hygiene and consistency with Phase 1/2).
    /// </summary>
    public EnrollmentOttWitnessEntry? Find(string oneTimeTokenHash)
    {
        foreach (var (hash, entry) in Entries)
        {
            if (TokenGenerator.ConstantTimeEquals(oneTimeTokenHash, hash))
            {
                return entry;
            }
        }

        return null;
    }

    /// <summary>
    /// Returns (creating if absent) the witness entry for
    /// <paramref name="oneTimeTokenHash"/>.
    /// </summary>
    public EnrollmentOttWitnessEntry GetOrAdd(string oneTimeTokenHash)
    {
        var existing = Find(oneTimeTokenHash);
        if (existing is not null)
        {
            return existing;
        }

        var created = new EnrollmentOttWitnessEntry();
        Entries[oneTimeTokenHash] = created;
        return created;
    }
}

/// <summary>
/// Load/save of the enrollment-state witness for one service directory.
/// Reads fail closed: an absent file yields null (no witness established
/// yet); a present-but-corrupt, undecryptable or PLAINTEXT witness throws
/// <see cref="InvalidDataException"/> — a legitimate witness is always
/// envelope-encrypted, so plaintext material in the witness slot is
/// tampering, and enrollment for the service must be refused until the state
/// is repaired.
/// </summary>
public static class EnrollmentStateWitnessStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };

    /// <summary>Witness path for the enrollment state of <paramref name="serviceDir"/>.</summary>
    public static string GetWitnessPath(string serviceDir) =>
        SspStateWitnessPaths.GetWitnessPath(serviceDir, SspStateWitnessPaths.EnrollmentPurpose);

    /// <summary>
    /// Loads the enrollment witness of <paramref name="serviceDir"/>. Null
    /// when no witness file exists. Throws <see
    /// cref="InvalidDataException"/> for any present-but-unusable witness.
    /// </summary>
    public static async Task<EnrollmentStateWitnessFile?> LoadAsync(
        string serviceDir,
        CancellationToken ct = default)
    {
        var path = GetWitnessPath(serviceDir);
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var read = await ProtectedFileStore.ReadTextAsync(path, ct).ConfigureAwait(false);

            // A legitimate witness is always written through the encrypted
            // envelope; plaintext bytes in the witness slot are hand-crafted
            // material and fail closed.
            if (!read.WasEncrypted)
            {
                throw new InvalidDataException(
                    "Enrollment state witness is not in the SSP encrypted-at-rest envelope.");
            }

            if (string.IsNullOrWhiteSpace(read.Text))
            {
                throw new InvalidDataException("Enrollment state witness file is empty.");
            }

            var witness = JsonSerializer.Deserialize<EnrollmentStateWitnessFile>(read.Text, SerializerOptions);
            if (witness is null)
            {
                throw new InvalidDataException("Enrollment state witness could not be deserialized.");
            }

            witness.Entries ??= new Dictionary<string, EnrollmentOttWitnessEntry>(StringComparer.Ordinal);
            return witness;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException
                                   or InvalidDataException or CryptographicException
                                   or PlatformNotSupportedException)
        {
            throw new InvalidDataException(
                $"Enrollment state witness could not be read: {ex.GetType().Name}", ex);
        }
    }

    /// <summary>
    /// Atomically writes the enrollment witness of <paramref name="serviceDir"/>
    /// in the encrypted-at-rest envelope. Throws on failure — the caller
    /// decides whether the write is best effort (the protocol paths: yes, a
    /// lagging witness is the safe direction) or critical.
    /// </summary>
    public static async Task SaveAsync(
        string serviceDir,
        EnrollmentStateWitnessFile witness,
        CancellationToken ct = default)
    {
        if (witness is null)
        {
            throw new ArgumentNullException(nameof(witness));
        }

        var path = GetWitnessPath(serviceDir);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(witness, SerializerOptions);
        await ProtectedFileStore.WriteTextAsync(path, json, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The later of two ISO-8601 cooldown instants, fail-closed on unparsable
    /// values (an unparsable timestamp is returned verbatim so
    /// <see cref="AuthenticationCodeAbusePolicy.IsRetryAllowed"/> refuses the
    /// retry, exactly as it does for the config timestamp).
    /// </summary>
    public static string? LaterRetryNotBefore(string? first, string? second)
    {
        if (string.IsNullOrWhiteSpace(second))
        {
            return first;
        }

        if (!DateTimeOffset.TryParse(second, out var secondInstant))
        {
            return second;
        }

        if (string.IsNullOrWhiteSpace(first))
        {
            return second;
        }

        if (!DateTimeOffset.TryParse(first, out var firstInstant))
        {
            return first;
        }

        return secondInstant > firstInstant ? second : first;
    }
}
