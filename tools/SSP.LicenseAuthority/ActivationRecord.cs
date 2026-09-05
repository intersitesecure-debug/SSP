// File: tools/SSP.LicenseAuthority/ActivationRecord.cs
//
// Authority-side activation record. When the authority issues an
// activation-required license it generates the activation OTT and the 10-digit
// code, and records them OUTSIDE the repository (next to the authority private
// key) so the offline `activate` command can later validate a presented OTT and
// return the code. The code is stored in plaintext ONLY here, authority-side;
// it is never written into the license artifact (which carries only its SHA-256,
// signed into the key certification).
//
// The record is authority secret material: it must never enter the SSP
// repository, a build machine, CI secrets, or any shipped/customer artifact.

using System.Globalization;
using System.Text.Json;
using SSP.Activation;

namespace SSP.LicenseAuthority;

/// <summary>Authority-side activation record for one license.</summary>
internal sealed class ActivationRecord
{
    public Guid LicenseId { get; init; }

    public string ActivationOtt { get; init; } = string.Empty;

    /// <summary>The 10-digit activation code (plaintext, authority-side only).</summary>
    public string ActivationCode { get; init; } = string.Empty;

    /// <summary>True after the OTT has been successfully validated and consumed.</summary>
    public bool Consumed { get; init; }

    /// <summary>UTC time the OTT was consumed (diagnostics).</summary>
    public DateTimeOffset? ConsumedAtUtc { get; init; }

    public ActivationRecord MarkConsumed(DateTimeOffset consumedAtUtc) => new()
    {
        LicenseId = LicenseId,
        ActivationOtt = ActivationOtt,
        ActivationCode = ActivationCode,
        Consumed = true,
        ConsumedAtUtc = consumedAtUtc.ToUniversalTime()
    };
}

/// <summary>Loads and atomically persists the authority-side activation records.</summary>
internal static class ActivationRecordStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };

    /// <summary>Loads a single activation record file (one license per file). Fails closed on any error.</summary>
    public static ActivationRecord Load(string path)
    {
        var json = AuthorityKeyMaterial.ReadTextFile(path, "activation record");

        ActivationRecord? record;
        try
        {
            record = JsonSerializer.Deserialize<ActivationRecord>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new AuthorityToolException($"Activation record '{Path.GetFullPath(path)}' is not valid JSON: {ex.Message}", ex);
        }

        if (record is null)
        {
            throw new AuthorityToolException($"Activation record '{Path.GetFullPath(path)}' is empty.");
        }

        if (record.LicenseId == Guid.Empty ||
            string.IsNullOrWhiteSpace(record.ActivationOtt) ||
            !LicenseActivation.IsValidActivationCode(record.ActivationCode))
        {
            throw new AuthorityToolException(
                $"Activation record '{Path.GetFullPath(path)}' is incomplete: it must contain a licenseId, an activation OTT and a 10-digit activation code.");
        }

        return record;
    }

    /// <summary>Serializes and atomically writes an activation record. Refuses to overwrite unless <paramref name="overwrite"/> is set.</summary>
    public static void Save(string path, ActivationRecord record, bool overwrite)
    {
        var json = JsonSerializer.Serialize(record, SerializerOptions);
        AuthorityKeyMaterial.WriteTextFile(path, json, overwrite);
    }

    public static string FormatTime(DateTimeOffset value)
        => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
}
