// File: src/SSP.Client/PatchSlot.cs
//
// The patch slot is a small binary blob embedded in SSP.Client as a
// manifest resource (SSP.Client.PatchSlot.bin). The SetupEngine
// patcher scans the COMPILED BINARY for the begin/end sentinels and
// overwrites the body bytes with a JSON-encoded ClientConfig.
//
// At runtime the client reads the patch slot from its own binary file
// on disk (NOT from the manifest resource) so it sees the patched
// values rather than the empty template.

using System.Reflection;
using System.Text;
using SSP.Core.Util;

namespace SSP.Client;

internal static class PatchSlot
{
    /// <summary>
    /// Touch the embedded resource so the compiler / linker keeps it
    /// in the binary. We do not actually read it at runtime - the
    /// patcher operates on the binary file on disk, not on the
    /// resource loader.
    /// </summary>
    public static readonly byte[] TemplateBytes = LoadTemplateResource();

    private static byte[] LoadTemplateResource()
    {
        var asm = Assembly.GetExecutingAssembly();
        using var rs = asm.GetManifestResourceStream("SSP.Client.PatchSlot.bin");
        if (rs == null) return Array.Empty<byte>();
        using var ms = new MemoryStream();
        rs.CopyTo(ms);
        return ms.ToArray();
    }
}
