namespace SSP.Activation;

/// <summary>
/// Strict base64url (RFC 4648 §5) codec. Encoding is unpadded; decoding accepts only the
/// characters [A-Za-z0-9_-] (explicit '+', '/', '=', whitespace and other characters are
/// rejected) and enforces canonical length rules, so ambiguous encodings fail closed.
/// Used to embed exact payload and signature bytes in the artifact envelope without any
/// JSON escaping ambiguity.
/// </summary>
internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static bool TryDecode(string? text, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        foreach (var ch in text)
        {
            var valid = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            if (!valid)
            {
                return false;
            }
        }

        var remainder = text.Length % 4;
        if (remainder == 1)
        {
            return false; // length that cannot be valid base64
        }

        var padded = text.Replace('-', '+').Replace('_', '/');
        padded += remainder switch
        {
            2 => "==",
            3 => "=",
            _ => string.Empty
        };

        try
        {
            bytes = Convert.FromBase64String(padded);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
