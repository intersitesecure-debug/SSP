// File: tools/SSP.LicenseAuthority/AuthorityKeyMaterial.cs
//
// Authority-side RSA key handling. The private key is caller-owned, never
// retained, never logged and never written anywhere except the explicit
// destination the operator passed to `keygen`. Production key generation
// is RSA-3072; loading rejects anything the relying-party library would
// refuse as a trust anchor (non-RSA, undersized, private material in a
// public-key file).

using System.Security.Cryptography;
using System.Text;
using SSP.Activation;

namespace SSP.LicenseAuthority;

/// <summary>Operational failure of the authority tool (missing file, bad key, refused overwrite).</summary>
internal sealed class AuthorityToolException : Exception
{
    public AuthorityToolException(string message) : base(message) { }

    public AuthorityToolException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Load / generate / export / fingerprint Licensing Authority RSA keys.
/// Fingerprint algorithm is identical to
/// <c>SSP.Server.Activation.SspTrustAnchor.ComputeFingerprint</c>: SHA-256
/// over the DER SubjectPublicKeyInfo, lowercase hex.
/// </summary>
internal static class AuthorityKeyMaterial
{
    /// <summary>RSA size the SSP key ceremony mandates for the production authority key.</summary>
    public const int ProductionKeySizeBits = 3072;

    /// <summary>Library / tool floor: the same 2048-bit floor <see cref="LicenseTrustAnchor"/> enforces.</summary>
    public const int MinimumKeySizeBits = LicenseTrustAnchor.MinimumKeySizeBits;

    /// <summary>Generate a new RSA-3072 authority key pair. Caller owns and must dispose the result.</summary>
    public static RSA GenerateProductionKeyPair()
    {
        var rsa = RSA.Create(ProductionKeySizeBits);
        try
        {
            AssertAuthorityRsa(rsa, requirePrivate: true, source: "newly generated key");
            if (rsa.KeySize != ProductionKeySizeBits)
            {
                throw new AuthorityToolException(
                    $"Key generation produced a {rsa.KeySize}-bit key; SSP requires RSA-{ProductionKeySizeBits}.");
            }

            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>Load an RSA private key from a PEM file. Rejects public-only material, non-RSA keys and undersized keys.</summary>
    public static RSA LoadPrivateKey(string path)
    {
        var pem = ReadPemFile(path, "private key");
        if (!ContainsPrivateKeyLabel(pem))
        {
            throw new AuthorityToolException(
                $"File '{path}' is not a private key PEM (expected a 'PRIVATE KEY' or 'RSA PRIVATE KEY' block).");
        }

        var rsa = RSA.Create();
        try
        {
            try
            {
                rsa.ImportFromPem(pem);
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
            {
                throw new AuthorityToolException(
                    $"File '{path}' is not a usable RSA private key ({ex.GetType().Name}).", ex);
            }

            try
            {
                _ = rsa.ExportParameters(includePrivateParameters: true);
            }
            catch (CryptographicException ex)
            {
                throw new AuthorityToolException(
                    $"File '{path}' does not contain RSA private key parameters. " +
                    "The Licensing Authority private key is required for this command.", ex);
            }

            AssertAuthorityRsa(rsa, requirePrivate: true, source: path);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Load an RSA public key from a PEM file. Rejects private-key material
    /// explicitly (a private key must never be treated as a public export)
    /// and applies the same floor as <see cref="LicenseTrustAnchor"/>.
    /// </summary>
    public static RSA LoadPublicKey(string path)
    {
        var pem = ReadPemFile(path, "public key");
        if (ContainsPrivateKeyLabel(pem))
        {
            throw new AuthorityToolException(
                $"File '{path}' contains PRIVATE KEY material. " +
                "Pass a 'PUBLIC KEY' PEM (SubjectPublicKeyInfo) to public-key commands. " +
                "The Licensing Authority private key must never be published or embedded.");
        }

        // Reuse the relying-party import so the tool and SSP.Server accept
        // exactly the same public-key shapes (PUBLIC KEY label, no trailing
        // DER, RSA, >= 2048 bits).
        LicenseTrustAnchor anchor;
        try
        {
            anchor = LicenseTrustAnchor.FromPem(pem);
        }
        catch (Exception ex)
        {
            throw new AuthorityToolException(
                $"File '{path}' is not a usable Licensing Authority public key ({ex.GetType().Name}: {ex.Message}).",
                ex);
        }

        try
        {
            var rsa = RSA.Create();
            try
            {
                rsa.ImportSubjectPublicKeyInfo(anchor.ExportSpkiDer(), out _);
                AssertAuthorityRsa(rsa, requirePrivate: false, source: path);
                return rsa;
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }
        finally
        {
            anchor.Dispose();
        }
    }

    /// <summary>PKCS#8 PEM (`BEGIN PRIVATE KEY`).</summary>
    public static string ExportPrivateKeyPem(RSA rsa)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>SPKI PEM (`BEGIN PUBLIC KEY`) — the only form SSP embeds as a trust anchor.</summary>
    public static string ExportPublicKeyPem(RSA rsa)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>Lowercase-hex SHA-256 over the DER SubjectPublicKeyInfo.</summary>
    public static string ComputeSpkiSha256Hex(RSA rsa)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        return ComputeSpkiSha256Hex(rsa.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Lowercase-hex SHA-256 over a DER SubjectPublicKeyInfo.</summary>
    public static string ComputeSpkiSha256Hex(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(subjectPublicKeyInfo, digest);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>
    /// Normalizes a fingerprint for comparison: trims, drops an optional
    /// "sha256:" prefix, removes ":" / "-" separators and whitespace, lowercases.
    /// Returns null for null/blank input. Matches
    /// <c>SspTrustAnchor.NormalizeFingerprint</c>.
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
                builder.Append(ch);
            }
        }

        var normalized = builder.ToString();
        return normalized.Length == 0 ? null : normalized;
    }

    /// <summary>Write a private-key PEM with restrictive permissions. Refuses to overwrite unless <paramref name="overwrite"/> is set.</summary>
    public static void WritePrivateKeyFile(string path, string pem, bool overwrite)
    {
        if (string.IsNullOrWhiteSpace(pem) || !ContainsPrivateKeyLabel(pem))
        {
            throw new AuthorityToolException("Refusing to write a private-key file that does not contain PRIVATE KEY material.");
        }

        WriteFileAtomic(path, pem, overwrite);
        RestrictPrivateKeyPermissions(path);
    }

    /// <summary>Write a public-key PEM. Refuses to write private-key material to a public-key destination.</summary>
    public static void WritePublicKeyFile(string path, string pem, bool overwrite)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            throw new AuthorityToolException("Refusing to write an empty public-key file.");
        }

        if (ContainsPrivateKeyLabel(pem))
        {
            throw new AuthorityToolException(
                "Refusing to write PRIVATE KEY material to a public-key destination. " +
                "The Licensing Authority private key must never be published.");
        }

        WriteFileAtomic(path, pem, overwrite);
    }

    /// <summary>Write an issued license artifact (signed JSON). Refuses to overwrite unless <paramref name="overwrite"/> is set.</summary>
    public static void WriteArtifactFile(string path, string artifactJson, bool overwrite)
        => WriteFileAtomic(path, artifactJson, overwrite);

    public static void AssertAuthorityRsa(RSA rsa, bool requirePrivate, string source)
    {
        ArgumentNullException.ThrowIfNull(rsa);

        if (rsa.KeySize < MinimumKeySizeBits)
        {
            throw new AuthorityToolException(
                $"RSA key from {source} is {rsa.KeySize} bits; at least {MinimumKeySizeBits} bits are required " +
                $"(production ceremony key is RSA-{ProductionKeySizeBits}).");
        }

        if (requirePrivate)
        {
            try
            {
                _ = rsa.ExportParameters(includePrivateParameters: true);
            }
            catch (CryptographicException ex)
            {
                throw new AuthorityToolException(
                    $"RSA key from {source} does not include private parameters.", ex);
            }
        }
    }

    public static bool IsBelowRecommendedSize(RSA rsa) => rsa.KeySize < ProductionKeySizeBits;

    private static string ReadPemFile(string path, string what)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new AuthorityToolException($"A {what} path is required.");
        }

        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
        {
            throw new AuthorityToolException($"{what} file was not found: {full}");
        }

        string text;
        try
        {
            text = File.ReadAllText(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new AuthorityToolException($"Could not read {what} file '{full}': {ex.GetType().Name}.", ex);
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            throw new AuthorityToolException($"{what} file '{full}' is empty.");
        }

        return text;
    }

    private static bool ContainsPrivateKeyLabel(string pem)
        => pem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase);

    private static void WriteFileAtomic(string path, string content, bool overwrite)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new AuthorityToolException("An output path is required.");
        }

        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        if (File.Exists(full) && !overwrite)
        {
            throw new AuthorityToolException(
                $"Refusing to overwrite existing file '{full}'. Pass --force to replace it.");
        }

        var tmp = full + ".tmp";
        try
        {
            File.WriteAllText(tmp, content);
            if (File.Exists(full))
            {
                File.Replace(tmp, full, destinationBackupFileName: null);
            }
            else
            {
                File.Move(tmp, full);
            }
        }
        catch
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best effort */ }
            throw;
        }
    }

    private static void RestrictPrivateKeyPermissions(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // Best effort: the file is already written. The operator's umask /
            // directory ACL is the remaining control.
        }
    }
}
