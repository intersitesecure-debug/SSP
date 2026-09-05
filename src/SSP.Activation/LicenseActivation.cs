using System.Globalization;
using System.Security.Cryptography;

namespace SSP.Activation;

/// <summary>
/// Authority-side helpers for the license activation flow. These functions are the
/// Licensing Authority's own generation logic and are not part of what a relying party
/// (SSP.Server) needs: the server never generates its own activation code — it can only
/// hash the code the operator types in and compare it with the hash the authority signed
/// into the license-key certification.
///
/// The activation flow:
///   1. The authority issues a license whose key certification carries an activation
///      one-time token (<see cref="GenerateActivationOtt"/>) and the SHA-256 of a
///      human-friendly activation code (<see cref="GenerateActivationCode"/>).
///   2. The customer installs the license and starts SSP.Server, which presents the OTT
///      (signed into the certification, so it cannot be forged by the customer) in its
///      activation request to the authority.
///   3. The authority validates the OTT (single use, not consumed before activation) and
///      returns the activation code to the customer.
///   4. The customer types the activation code; SSP.Server hashes it and compares with the
///      signed <c>ActivationCodeHash</c>. A match marks the license activated.
/// </summary>
public static class LicenseActivation
{
    /// <summary>Number of decimal digits in an activation code.</summary>
    public const int ActivationCodeLength = 10;

    /// <summary>Random entropy (bytes) per one-time token.</summary>
    private const int OttRandomBytes = 32;

    /// <summary>
    /// Generates a license activation one-time token. Random 256-bit, encoded as base64url
    /// (unpadded, 43 characters). Generated and retained only by the Licensing Authority;
    /// the authority binds the token to the license by signing it into the key
    /// certification and by recording it server-side so a request can be matched to a
    /// pending license. It is single use and must never be consumed before successful
    /// activation.
    /// </summary>
    public static string GenerateActivationOtt()
    {
        var bytes = RandomNumberGenerator.GetBytes(OttRandomBytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Generates a human-friendly, uniformly random 10-digit activation code. The only
    /// value that is ever persisted or signed is <see cref="ComputeActivationCodeHash"/> of
    /// the code, so knowledge of the license artifact and certification does not reveal the
    /// code.
    /// </summary>
    public static string GenerateActivationCode()
    {
        var code = new char[ActivationCodeLength];
        for (var i = 0; i < code.Length; i++)
        {
            // Digit 0-9 via rejection sampling over the random byte so no decimal bias.
            byte sample;
            do
            {
                sample = RandomNumberGenerator.GetBytes(1)[0];
            }
            while (sample >= 250); // 250 is the largest multiple of 10 within [0,255]

            code[i] = (char)('0' + (sample % 10));
        }

        return new string(code);
    }

    /// <summary>
    /// True when <paramref name="code"/> is exactly <see cref="ActivationCodeLength"/> ASCII
    /// decimal digits (surrounding spaces are tolerated, mirroring what an operator might
    /// paste). Used by the authority to validate codes it records and by the activation
    /// comparison path.
    /// </summary>
    public static bool IsValidActivationCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        var normalized = code.Replace(" ", string.Empty, StringComparison.Ordinal);
        return normalized.Length == ActivationCodeLength && normalized.All(char.IsAsciiDigit);
    }

    /// <summary>
    /// Computes the lowercase-hex SHA-256 of an activation code after removing any
    /// whitespace the operator may have typed. This is the representation signed into
    /// <see cref="LicenseKeyCertification.ActivationCodeHash"/>.
    /// </summary>
    public static string ComputeActivationCodeHash(string activationCode)
    {
        if (!IsValidActivationCode(activationCode))
        {
            throw new ArgumentException(
                $"Activation code must be exactly {ActivationCodeLength} decimal digits.",
                nameof(activationCode));
        }

        var normalized = activationCode.Replace(" ", string.Empty, StringComparison.Ordinal);
        var hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(normalized));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Constant-time comparison of an operator-supplied activation code against the
    /// certification's signed <see cref="LicenseKeyCertification.ActivationCodeHash"/>.
    /// Returns true only when both are present and match. A license with a null activation
    /// code hash never matches an entered code (and vice versa).
    /// </summary>
    public static bool ActivationCodeMatches(string? signedActivationCodeHash, string? enteredActivationCode)
    {
        if (string.IsNullOrEmpty(signedActivationCodeHash))
        {
            return false;
        }

        string? enteredHash;
        try
        {
            enteredHash = enteredActivationCode is null
                ? null
                : ComputeActivationCodeHash(enteredActivationCode);
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (enteredHash is null)
        {
            return false;
        }

        var expected = FromHex(signedActivationCodeHash);
        var actual = FromHex(enteredHash);
        if (expected.Length != 32 || actual.Length != 32)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>
    /// Constant-time comparison of an authority-recorded OTT against a presented OTT. Both
    /// are base64url strings; comparison is over the raw ASCII bytes and fails (and returns
    /// false) for null/empty or different-length input. Used by the authority when it
    /// validates an activation request.
    /// </summary>
    public static bool OttMatches(string? expectedOtt, string? presentedOtt)
    {
        if (string.IsNullOrEmpty(expectedOtt) || string.IsNullOrEmpty(presentedOtt))
        {
            return false;
        }

        var expected = System.Text.Encoding.ASCII.GetBytes(expectedOtt);
        var actual = System.Text.Encoding.ASCII.GetBytes(presentedOtt);
        if (expected.Length != actual.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private static byte[] FromHex(string hex)
    {
        if (hex.Length % 2 != 0 || !hex.All(IsHexDigit))
        {
            return Array.Empty<byte>();
        }

        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return bytes;
    }

    private static bool IsHexDigit(char c) =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
