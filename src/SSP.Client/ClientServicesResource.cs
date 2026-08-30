// File: src/SSP.Client/ClientServicesResource.cs
//
// client_services.json lives INSIDE the client executable as a manifest
// resource (SSP.Client.ClientServices.json). SetupEngine overwrites its
// fixed-size body with the plain JSON of the ClientServiceBundle at
// provisioning time, so no client_services.json file is ever written,
// extracted or required next to the EXE.
//
// The resource is the primary source at startup. The on-disk main binary
// is kept as a fallback for a framework-dependent layout, where the
// patcher rewrote the apphost while the loaded assembly came from the
// sibling SSP.Client.dll - the same reason PatchSlot reads its slot from
// the binary rather than from the resource loader.

using System.Reflection;
using SSP.Core.Util;

namespace SSP.Client;

internal static class ClientServicesResource
{
    /// <summary>Manifest resource holding the embedded bundle.</summary>
    internal const string ResourceName = "SSP.Client.ClientServices.json";

    /// <summary>
    /// The client_services.json text embedded in THIS process, or null
    /// when the executable was never provisioned with a bundle.
    /// </summary>
    internal static string? Read(byte[] mainBinaryFallback)
    {
        var fromResource = ReadManifestResource();
        if (!string.IsNullOrWhiteSpace(fromResource))
            return fromResource;

        return ClientTemplate.ReadServicesSlot(mainBinaryFallback);
    }

    private static string? ReadManifestResource()
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var rs = asm.GetManifestResourceStream(ResourceName);
            if (rs == null) return null;

            using var ms = new MemoryStream();
            rs.CopyTo(ms);
            // The resource bytes ARE the slot (sentinels + padded body),
            // so the same reader that scans a binary works here.
            return ClientTemplate.ReadServicesSlot(ms.ToArray());
        }
        catch
        {
            return null;
        }
    }
}
