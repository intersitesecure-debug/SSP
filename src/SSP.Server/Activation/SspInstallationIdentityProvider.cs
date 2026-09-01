// File: src/SSP.Server/Activation/SspInstallationIdentityProvider.cs
//
// SSP-native installation identity for activation. The licensing library
// deliberately performs no hardware/OS fingerprinting; the host supplies the
// identity. SSP binds to the Windows MachineGuid (HKLM\SOFTWARE\Microsoft\
// Cryptography\MachineGuid), hashed with SHA-256 plus a purpose tag, so the
// raw MachineGuid never appears in a readable license artifact or security
// event. On non-Windows test/development hosts the provider returns null,
// which makes installation-bound licenses fail closed (the reference
// library's documented semantics); floating test licenses still validate.

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SSP.Core.Activation;

namespace SSP.Server.Activation;

/// <summary>
/// Provides a stable, hashed installation identifier for license binding.
/// The identifier survives reboots and ordinary hardware churn; it changes on
/// OS reinstall/VM re-sysprep, which is the intended commercial binding.
/// </summary>
public sealed class SspInstallationIdentityProvider : SSP.Activation.IInstallationIdentityProvider
{
    private const string MachineGuidValueName = "MachineGuid";
    private const string CryptographyKeyPath = @"SOFTWARE\Microsoft\Cryptography";
    private const int RegQueryBufferBytes = 4096;
    private const uint RegSz = 1u;

    // HKEY_LOCAL_MACHINE. WinReg.h defines the predefined registry handles as
    // sign-extended 32-bit values: ((HKEY)(ULONG_PTR)((LONG)0x80000002)). The
    // int cast inside unchecked() reproduces exactly that: it yields
    // 0x80000002 on 32-bit and the sign-extended 0xFFFFFFFF80000002 on x64,
    // which is the canonical pseudo-handle advapi32 expects on 64-bit
    // Windows. (A plain (IntPtr)(long)0x80000002 would zero-extend on x64 to
    // 0x0000000080000002 - not a predefined key - and the constant
    // long->nint conversion also raises CS8778 for 32-bit targets.)
    private static readonly IntPtr HkeyLocalMachine = new(unchecked((int)0x80000002));
    private const uint KeyQueryValue = 0x0001;

    private readonly object _gate = new();
    private bool _initialized;
    private string? _cached;

    /// <inheritdoc />
    public string? GetInstallationId()
    {
        lock (_gate)
        {
            if (!_initialized)
            {
                _cached = ReadMachineGuid();
                _initialized = true;
            }

            return _cached is null ? null : ComputeInstallationId(_cached);
        }
    }

    /// <summary>
    /// Computes the license binding identifier from the raw Windows
    /// MachineGuid using the stable SSP domain separation tag. Exposed
    /// internally for deterministic tests without requiring a live registry.
    /// </summary>
    internal static string ComputeInstallationId(string machineGuid)
    {
        if (string.IsNullOrWhiteSpace(machineGuid))
        {
            throw new ArgumentException("MachineGuid must not be null or empty.", nameof(machineGuid));
        }

        var material = Encoding.UTF8.GetBytes(machineGuid + SspLicensing.InstallationBindingPurposeTag);
        var hash = SHA256.HashData(material);
        CryptographicOperations.ZeroMemory(material);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? ReadMachineGuid()
    {
        if (!OperatingSystem.IsWindows())
        {
            // No registry on non-Windows hosts; identity unavailable. Bound
            // licenses then fail closed while floating licenses still work.
            return null;
        }

        try
        {
            return ReadWindowsMachineGuid();
        }
        catch
        {
            // A registry failure must never make the identity provider throw;
            // the licensing library already treats an unavailable identity as
            // a fail-closed condition for installation-bound licenses.
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadWindowsMachineGuid()
    {
        if (NativeMethods.RegOpenKeyExW(HkeyLocalMachine, CryptographyKeyPath, 0, KeyQueryValue, out var hkey) != 0)
        {
            return null;
        }

        try
        {
            var buffer = new byte[RegQueryBufferBytes];
            uint cbData = (uint)RegQueryBufferBytes;
            uint type;
            if (NativeMethods.RegQueryValueExW(hkey, MachineGuidValueName, 0, out type, buffer, ref cbData) != 0)
            {
                return null;
            }

            if ((type & RegSz) == 0)
            {
                // The value exists but is not a REG_SZ string; treat as unavailable.
                return null;
            }

            // REG_SZ data includes a UTF-16 null terminator when cbData is set.
            var bytes = (int)cbData;
            if (bytes < 2 || bytes > buffer.Length)
            {
                // Too small to hold a string, or larger than the read buffer;
                // fail closed and report identity unavailable.
                return null;
            }

            if (bytes % 2 != 0)
            {
                bytes -= 1;
            }

            var text = Encoding.Unicode.GetString(buffer, 0, bytes);
            return text.TrimEnd('\0');
        }
        finally
        {
            NativeMethods.RegCloseKey(hkey);
        }
    }

    // advapi32 registry P/Invoke. The repo deliberately does not add the
    // Microsoft.Win32.Registry NuGet dependency; these calls are used only on
    // Windows and are guarded by the OperatingSystem.IsWindows() check above.
    private static class NativeMethods
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [SupportedOSPlatform("windows")]
        internal static extern int RegOpenKeyExW(
            IntPtr hKey,
            string subKey,
            int reserved,
            uint samDesired,
            out IntPtr phkResult);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [SupportedOSPlatform("windows")]
        internal static extern int RegQueryValueExW(
            IntPtr hKey,
            string valueName,
            int reserved,
            out uint type,
            byte[] data,
            ref uint cbData);

        [DllImport("advapi32.dll", SetLastError = true)]
        [SupportedOSPlatform("windows")]
        internal static extern int RegCloseKey(IntPtr hKey);
    }
}
