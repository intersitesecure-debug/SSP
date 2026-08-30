// File: src/SSP.Core/Util/ClientTemplate.cs
//
// Embedded client template system.
//
// BUILD TIME
//   SSP.Client is published as a self-contained executable, then
//   embedded as an embedded resource into SSP.Server.exe. The patch
//   slot is a well-known byte sequence injected into the client binary
//   at build time so the server can locate it later.
//
// SETUP TIME
//   1. Extract the embedded client template to a temp directory.
//   2. Copy the file (template stays read-only and unchanged).
//   3. Locate the patch slot inside the copy.
//   4. Overwrite the slot placeholder with the JSON-serialized
//      ClientConfig.
//   5. Validate the patched binary (slot is readable and contains
//      a valid ClientConfig).
//   6. Rename the copy to SSP.Client.<ApplicationName>.exe.
//
// The patch slot is implemented as a 4096-byte region delimited by
// ASCII sentinels:
//
//   __SSP_CLIENT_PATCH_BEGIN__\n
//   <base64-encoded ClientConfig JSON, padded with spaces>
//   \n__SSP_CLIENT_PATCH_END__
//
// Padding with spaces (0x20) means the patched file is byte-for-byte
// the same length as the template, which keeps any PE header offsets
// valid.
//
// SERVICES SLOT (embedded client_services.json)
//   The list of connections a client installation belongs to used to be
//   written as a client_services.json file next to the executable. It is
//   now embedded INSIDE the client executable as a second manifest
//   resource, using exactly the same sentinel/padding technique:
//
//     __SSP_CLIENT_SERVICES_BEGIN__\n
//     <plain ClientServiceBundle JSON, padded with spaces>\n
//     __SSP_CLIENT_SERVICES_END__
//
//   The payload is the JSON text as-is: no encryption, no hashing, no
//   compression and no obfuscation - only fixed-length space padding,
//   which is required to keep the binary length constant. The client
//   therefore ships as a single EXE with no sidecar file.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSP.Core.IO;
using SSP.Core.Models;

namespace SSP.Core.Util;

public static class ClientTemplate
{
    /// <summary>ASCII sentinel that opens the patch slot.</summary>
    public const string PatchBeginSentinel = "__SSP_CLIENT_PATCH_BEGIN__";

    /// <summary>ASCII sentinel that closes the patch slot.</summary>
    public const string PatchEndSentinel   = "__SSP_CLIENT_PATCH_END__";

    /// <summary>Total slot body size (excluding sentinels and newlines).</summary>
    public const int SlotBodySize = 4096;

    /// <summary>
    /// Build the patch slot payload (sentinels + padded body) as a UTF-8
    /// byte array. The body is the base64 encoding of the JSON ClientConfig,
    /// right-padded with spaces to exactly SlotBodySize bytes.
    /// </summary>
    public static byte[] BuildPatchSlot(ClientConfig cfg)
    {
        var json = JsonSerializer.Serialize(cfg, JsonOptions.Default);
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        var b64 = Convert.ToBase64String(jsonBytes);

        var sb = new StringBuilder();
        sb.Append(PatchBeginSentinel).Append('\n');
        sb.Append(b64);
        // Pad the remainder with spaces so the total body size is constant.
        var padding = SlotBodySize - b64.Length;
        if (padding < 0)
            throw new InvalidOperationException(
                $"ClientConfig too large for patch slot: {b64.Length} > {SlotBodySize}.");
        sb.Append(' ', padding);
        sb.Append('\n').Append(PatchEndSentinel);

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>
    /// Locate the patch slot in a client binary and return its byte
    /// range as a (bodyStart, bodyEnd) tuple. Returns null if the slot
    /// is not present.
    /// </summary>
    public static (int BodyStart, int BodyEnd)? FindPatchSlotRange(byte[] binary)
    {
        var beginBytes = Encoding.ASCII.GetBytes(PatchBeginSentinel);
        var endBytes   = Encoding.ASCII.GetBytes(PatchEndSentinel);

        var begin = IndexOf(binary, beginBytes);
        if (begin < 0) return null;
        var bodyStart = begin + beginBytes.Length;
        if (bodyStart < binary.Length && binary[bodyStart] == (byte)'\r') bodyStart++;
        if (bodyStart < binary.Length && binary[bodyStart] == (byte)'\n') bodyStart++;

        var end = IndexOf(binary, endBytes, bodyStart);
        if (end < 0) return null;
        var bodyEnd = end;
        if (bodyEnd > bodyStart && binary[bodyEnd - 1] == (byte)'\n') bodyEnd--;
        if (bodyEnd > bodyStart && binary[bodyEnd - 1] == (byte)'\r') bodyEnd--;

        return (bodyStart, bodyEnd);
    }

    /// <summary>
    /// Locate the patch slot in a client binary and return its byte
    /// range. Returns null if the slot is not present. Kept for API
    /// compatibility with callers that prefer Range.
    /// </summary>
    public static Range? FindPatchSlot(byte[] binary)
    {
        var range = FindPatchSlotRange(binary);
        if (range == null) return null;
        return new Range(range.Value.BodyStart, range.Value.BodyEnd);
    }

    /// <summary>
    /// Inject (or overwrite) the patch slot inside a copy of the client
    /// binary. The slot must already exist in the template; if it does
    /// not, an exception is thrown.
    /// </summary>
    public static byte[] PatchCopy(byte[] templateBytes, ClientConfig cfg)
    {
        var slotRange = FindPatchSlotRange(templateBytes)
                   ?? throw new InvalidDataException(
                       "Client template does not contain a patch slot. " +
                       "Rebuild SSP.Client with the patch slot marker.");

        var slotBytes = BuildPatchSlot(cfg);

        // The total slot size (sentinels + body + newlines) is fixed
        // and the patch payload is exactly the same length, so we just
        // overwrite the bytes in place. Compute the slot start (where
        // the begin sentinel starts) by walking back from the body start.
        var beginBytes = Encoding.ASCII.GetBytes(PatchBeginSentinel);
        var begin = IndexOf(templateBytes, beginBytes);
        if (begin < 0)
            throw new InvalidDataException("Begin sentinel disappeared between calls.");

        if (begin + slotBytes.Length > templateBytes.Length)
            throw new InvalidDataException("Patch slot would overrun the end of the binary.");

        var copy = new byte[templateBytes.Length];
        Buffer.BlockCopy(templateBytes, 0, copy, 0, templateBytes.Length);
        Buffer.BlockCopy(slotBytes, 0, copy, begin, slotBytes.Length);
        return copy;
    }

    /// <summary>
    /// Read the ClientConfig out of a patched client binary. Used by
    /// the SETUP MODE validator and by the client itself at startup.
    /// </summary>
    public static ClientConfig ReadPatchSlot(byte[] binary)
    {
        var range = FindPatchSlotRange(binary)
                   ?? throw new InvalidDataException("Patch slot not found in client binary.");

        var bodyStart = range.BodyStart;
        var bodyEnd = range.BodyEnd;
        var bodyLength = bodyEnd - bodyStart;
        if (bodyLength <= 0)
            throw new InvalidDataException("Empty patch slot body.");

        var bodyBytes = new byte[bodyLength];
        Buffer.BlockCopy(binary, bodyStart, bodyBytes, 0, bodyLength);

        // Strip trailing spaces used as padding.
        var end = bodyBytes.Length;
        while (end > 0 && bodyBytes[end - 1] == ' ') end--;
        var b64 = Encoding.ASCII.GetString(bodyBytes, 0, end);

        var jsonBytes = Convert.FromBase64String(b64);
        return JsonSerializer.Deserialize<ClientConfig>(jsonBytes, JsonOptions.Default)
               ?? throw new InvalidDataException("Failed to deserialize ClientConfig from patch slot.");
    }

    /// <summary>
    /// Validate that the patched binary contains a ClientConfig that
    /// matches every required field. Used by the SETUP MODE validator
    /// step.
    /// </summary>
    public static void ValidatePatch(byte[] binary, ClientConfig expected)
    {
        var actual = ReadPatchSlot(binary);

        if (actual.ApplicationName        != expected.ApplicationName        ||
            actual.GatewayPublicIpAddress != expected.GatewayPublicIpAddress ||
            actual.GatewayPort            != expected.GatewayPort            ||
            actual.LocalApplicationPort   != expected.LocalApplicationPort   ||
            actual.ClientTunnelPort       != expected.ClientTunnelPort       ||
            actual.OneTimeToken           != expected.OneTimeToken           ||
            actual.ServerFingerprint      != expected.ServerFingerprint      ||
            actual.ServerPublicKeyPem     != expected.ServerPublicKeyPem)
        {
            throw new InvalidDataException(
                "Patch validation failed: the patched ClientConfig does not match " +
                "the values that were supposed to be written.");
        }

        // If expected ClientName is set, it must also match.
        if (!string.IsNullOrEmpty(expected.ClientName) &&
            actual.ClientName != expected.ClientName)
        {
            throw new InvalidDataException(
                "Patch validation failed: ClientName mismatch.");
        }
    }

    // ────────────────────────────────────────────────────────────────
    // EMBEDDED client_services.json ("services slot")
    // ────────────────────────────────────────────────────────────────

    /// <summary>ASCII sentinel that opens the embedded services slot.</summary>
    public const string ServicesBeginSentinel = "__SSP_CLIENT_SERVICES_BEGIN__";

    /// <summary>ASCII sentinel that closes the embedded services slot.</summary>
    public const string ServicesEndSentinel = "__SSP_CLIENT_SERVICES_END__";

    /// <summary>
    /// Total services-slot body size (excluding sentinels and newlines).
    /// Sized for a merged bundle of many connections; the payload is the
    /// plain JSON text, so ~1.1 KB per connection is the rule of thumb.
    /// </summary>
    public const int ServicesSlotBodySize = 131072;

    /// <summary>
    /// Build the services slot payload (sentinels + fixed-size body) as a
    /// UTF-8 byte array. The body holds the <c>client_services.json</c>
    /// text verbatim - no encryption, hashing, compression or
    /// obfuscation - right-padded with spaces to exactly
    /// <see cref="ServicesSlotBodySize"/> bytes so the binary length is
    /// unchanged by the patch.
    /// </summary>
    public static byte[] BuildServicesSlot(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json ?? string.Empty);
        if (payload.Length > ServicesSlotBodySize)
            throw new InvalidOperationException(
                $"client_services.json payload too large for the embedded client slot: " +
                $"{payload.Length} > {ServicesSlotBodySize} bytes.");

        var beginBytes = Encoding.ASCII.GetBytes(ServicesBeginSentinel);
        var endBytes = Encoding.ASCII.GetBytes(ServicesEndSentinel);

        var slot = new byte[beginBytes.Length + 1 + ServicesSlotBodySize + 1 + endBytes.Length];
        var offset = 0;
        Buffer.BlockCopy(beginBytes, 0, slot, offset, beginBytes.Length);
        offset += beginBytes.Length;
        slot[offset++] = (byte)'\n';
        Array.Fill(slot, (byte)' ', offset, ServicesSlotBodySize);
        Buffer.BlockCopy(payload, 0, slot, offset, payload.Length);
        offset += ServicesSlotBodySize;
        slot[offset++] = (byte)'\n';
        Buffer.BlockCopy(endBytes, 0, slot, offset, endBytes.Length);
        return slot;
    }

    /// <summary>
    /// Locate the services slot in a client binary and return its body
    /// byte range. Returns null when the slot is not present. Works on a
    /// whole binary as well as on the raw manifest resource bytes.
    /// </summary>
    public static (int BodyStart, int BodyEnd)? FindServicesSlotRange(byte[] binary)
    {
        var beginBytes = Encoding.ASCII.GetBytes(ServicesBeginSentinel);
        var endBytes = Encoding.ASCII.GetBytes(ServicesEndSentinel);

        var begin = IndexOf(binary, beginBytes);
        if (begin < 0) return null;
        var bodyStart = begin + beginBytes.Length;
        if (bodyStart < binary.Length && binary[bodyStart] == (byte)'\r') bodyStart++;
        if (bodyStart < binary.Length && binary[bodyStart] == (byte)'\n') bodyStart++;

        var end = IndexOf(binary, endBytes, bodyStart);
        if (end < 0) return null;
        var bodyEnd = end;
        if (bodyEnd > bodyStart && binary[bodyEnd - 1] == (byte)'\n') bodyEnd--;
        if (bodyEnd > bodyStart && binary[bodyEnd - 1] == (byte)'\r') bodyEnd--;

        return (bodyStart, bodyEnd);
    }

    /// <summary>
    /// Inject (or overwrite) the embedded client_services.json inside a
    /// copy of the client binary. The slot must already exist in the
    /// template; the returned array has exactly the same length as the
    /// input, and the patch slot is left untouched.
    /// </summary>
    public static byte[] PatchServicesSlot(byte[] binary, string json)
    {
        var range = FindServicesSlotRange(binary)
                 ?? throw new InvalidDataException(
                     "Client binary does not contain a services slot. " +
                     "Rebuild SSP.Client with the client_services marker.");

        var beginBytes = Encoding.ASCII.GetBytes(ServicesBeginSentinel);
        var begin = IndexOf(binary, beginBytes);
        if (begin < 0)
            throw new InvalidDataException("Services slot begin sentinel disappeared between calls.");

        var slotBytes = BuildServicesSlot(json);
        if (begin + slotBytes.Length > binary.Length)
            throw new InvalidDataException("Services slot would overrun the end of the binary.");

        var copy = new byte[binary.Length];
        Buffer.BlockCopy(binary, 0, copy, 0, binary.Length);
        Buffer.BlockCopy(slotBytes, 0, copy, begin, slotBytes.Length);
        return copy;
    }

    /// <summary>
    /// Read the embedded client_services.json text out of a patched
    /// client binary (or out of the raw manifest resource bytes).
    /// Returns null when the slot is missing or still holds the empty
    /// template, so an unpatched client simply has no bundle.
    /// </summary>
    public static string? ReadServicesSlot(byte[] binary)
    {
        var range = FindServicesSlotRange(binary);
        if (range == null) return null;

        var bodyLength = range.Value.BodyEnd - range.Value.BodyStart;
        if (bodyLength <= 0) return null;

        var bodyBytes = new byte[bodyLength];
        Buffer.BlockCopy(binary, range.Value.BodyStart, bodyBytes, 0, bodyLength);

        // Strip trailing spaces and newlines used as padding.
        var end = bodyBytes.Length;
        while (end > 0 && (bodyBytes[end - 1] == (byte)' ' || bodyBytes[end - 1] == (byte)'\r' || bodyBytes[end - 1] == (byte)'\n' || bodyBytes[end - 1] == (byte)'\t')) end--;
        if (end == 0) return null; // still the empty template

        var json = Encoding.UTF8.GetString(bodyBytes, 0, end);
        return string.IsNullOrWhiteSpace(json) ? null : json;
    }

    /// <summary>Naive byte-array index-of. Sufficient for a one-shot scan.</summary>
    private static int IndexOf(byte[] haystack, byte[] needle, int start = 0)
    {
        if (needle.Length == 0) return 0;
        for (var i = start; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }
}

/// <summary>
/// Names of the embedded resources that ship inside SSP.Server.exe.
/// </summary>
public static class EmbeddedResourceNames
{
    /// <summary>
    /// The published SSP.Client binary, embedded at build time.
    /// </summary>
    public const string ClientTemplate = "SSP.Server.Embedded.SSP.Client.bin";

    /// <summary>
    /// The published SSP.ServiceHost binary - the standalone Windows
    /// Service host image. Embedded at build time (single-file,
    /// self-contained) and extracted by WindowsServiceInstaller into each
    /// newly created service directory, so services run their own host
    /// executable and never reference or copy the setup executable.
    /// </summary>
    public const string ServiceHostImage = "SSP.Server.Embedded.SSP.ServiceHost.bin";
}
