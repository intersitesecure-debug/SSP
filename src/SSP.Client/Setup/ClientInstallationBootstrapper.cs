// File: src/SSP.Client/Setup/ClientInstallationBootstrapper.cs
//
// Windows launch handoff for the SSP client. A client executable
// (SSP.Client.*.exe) first started outside its canonical location
// C:\Program Files\SSP is:
//   1. copied to C:\Program Files\SSP (same file name),
//   2. represented by ONE Desktop shortcut named after the client,
//      whose target is EXACTLY the copied file in
//      C:\Program Files\SSP,
//   3. announced to the shell through the standard change-notification
//      API so the shortcut is visible immediately (no F5),
//   4. launched from its canonical copy, and the original process
//      exits.
//
// A client already running from the canonical location passes through
// untouched: no copy, no shortcut.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Text;
using SSP.Core.IO;
using SSP.Core.Models;
using SSP.Core.Util;

namespace SSP.Client.Setup;

/// <summary>
/// Installs a manually launched <c>SSP.Client.*.exe</c> into the
/// canonical Windows location and continues the client from the
/// canonical copy through its Desktop shortcut. This class deliberately
/// does not own any client runtime logic; it only hands execution to
/// the existing startup path after the location is correct.
/// </summary>
internal static class ClientInstallationBootstrapper
{
    internal const string ExecutableNamePrefix = "SSP.Client";
    private const string ExecutableExtension = ".exe";
    private const string ShortcutExtension = ".lnk";

    /// <summary>
    /// Attempts the Windows install handoff for the process whose
    /// launched on-disk binary is <paramref name="launchedExecutablePath"/>.
    /// Returns <see langword="true"/> only when the canonical copy was
    /// launched, in which case the caller must exit the original process.
    /// </summary>
    internal static bool InstallAndLaunchCanonicalIfNeeded(string launchedExecutablePath)
    {
        if (!OperatingSystem.IsWindows())
            return false;

        var canonicalDirectory = ClientInstallPaths.GetProductRoot();
        if (!RequiresInstallation(launchedExecutablePath, canonicalDirectory))
            return false;

        var fileName = Path.GetFileName(launchedExecutablePath);
        Directory.CreateDirectory(canonicalDirectory);
        var canonicalExecutablePath = Path.Combine(canonicalDirectory, fileName);

        // The source is the actual apphost process, never the working
        // directory or an assembly path. This preserves a single-file
        // published executable exactly as it was launched.
        File.Copy(launchedExecutablePath, canonicalExecutablePath, overwrite: true);

        // Move this executable's connection state from the pre-canonical
        // per-exe location to the canonical root BEFORE the canonical
        // copy starts, so an installation that was already enrolled while
        // the executable still lived elsewhere does not have to
        // re-enroll (and does not burn its one-time token again).
        MigrateConnectionState(launchedExecutablePath, canonicalDirectory);

        var desktopDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(desktopDirectory))
            throw new InvalidOperationException("The current user's Desktop directory could not be resolved.");

        Directory.CreateDirectory(desktopDirectory);
        var shortcutName = DeriveShortcutName(fileName);
        var shortcutPath = Path.Combine(desktopDirectory, shortcutName + ShortcutExtension);
        CreateOrReplaceShortcut(shortcutPath, canonicalExecutablePath, canonicalDirectory);
        NotifyDesktopContentsChanged(desktopDirectory);

        // Continue the client from the canonical copy. The copied file is
        // launched directly, so the new process sees the canonical path
        // and passes RequiresInstallation without creating a second copy
        // or shortcut.
        Process.Start(new ProcessStartInfo
        {
            FileName = canonicalExecutablePath,
            WorkingDirectory = canonicalDirectory,
            UseShellExecute = true,
        });

        return true;
    }

    /// <summary>
    /// True when the process is an SSP client executable and is not
    /// already running from the canonical installation directory
    /// (C:\Program Files\SSP).
    /// </summary>
    internal static bool RequiresInstallation(string? launchedPath, string canonicalDirectory)
    {
        if (string.IsNullOrWhiteSpace(launchedPath) ||
            string.IsNullOrWhiteSpace(canonicalDirectory))
        {
            return false;
        }

        try
        {
            if (!IsClientExecutableName(Path.GetFileName(launchedPath)))
            {
                // Framework-dependent `dotnet SSP.Client.dll` runs and
                // foreign executables must not be copied.
                return false;
            }

            var directory = Path.GetDirectoryName(Path.GetFullPath(launchedPath));
            return !PathsEqual(directory, canonicalDirectory);
        }
        catch
        {
            // If an unusual process path cannot be normalised, leave
            // startup handling untouched rather than copying an
            // uncertain file.
            return false;
        }
    }

    /// <summary>
    /// True for SSP client executables: SSP.Client.exe,
    /// SSP.Client.RDP.Client01.exe, etc.
    /// </summary>
    internal static bool IsClientExecutableName(string fileName) =>
        fileName.StartsWith(ExecutableNamePrefix, StringComparison.OrdinalIgnoreCase) &&
        fileName.EndsWith(ExecutableExtension, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Desktop shortcut name for a client executable, derived from the
    /// client's own name:
    ///   SSP.Client.RDP.Client01.exe -> "SSP Client - RDP - Client01"
    ///   SSP.Client.exe              -> "SSP Client"
    /// </summary>
    internal static string DeriveShortcutName(string fileName)
    {
        var name = Path.GetFileName(fileName);
        var withoutExtension = name;
        if (name.EndsWith(ExecutableExtension, StringComparison.OrdinalIgnoreCase))
            withoutExtension = name[..^ExecutableExtension.Length];

        var suffix = withoutExtension;
        if (withoutExtension.StartsWith(ExecutableNamePrefix, StringComparison.OrdinalIgnoreCase))
            suffix = withoutExtension[ExecutableNamePrefix.Length..].Trim('.');

        if (string.IsNullOrWhiteSpace(suffix))
            return "SSP Client";

        return "SSP Client - " + string.Join(" - ", suffix.Split('.'));
    }

    /// <summary>
    /// Move this executable's connection state from the pre-canonical
    /// per-exe location (<c>{exeDir}/connections/</c>) to the canonical
    /// root (<c>canonicalDirectory/connections/</c>).
    ///
    /// Only the connection of the LAUNCHED executable is moved: its
    /// ConnectionId comes from the patch slot embedded in the launched
    /// binary. A binary without a server identity of its own (raw
    /// template host) moves every sub-directory. The copy is
    /// byte-for-byte (the files are already encrypted at rest),
    /// non-destructive (the source stays in place) and best-effort: a
    /// failure here must never block the handoff, the canonical copy
    /// still launches - worst case the connection enrolls again.
    /// </summary>
    internal static void MigrateConnectionState(
        string launchedExecutablePath,
        string canonicalDirectory)
    {
        try
        {
            var originalDirectory = Path.GetDirectoryName(Path.GetFullPath(launchedExecutablePath));
            if (string.IsNullOrWhiteSpace(originalDirectory))
                return;
            if (PathsEqual(originalDirectory, canonicalDirectory))
                return;

            var from = Path.Combine(originalDirectory, ClientInstallPaths.ConnectionsDirectoryName);
            if (!Directory.Exists(from))
                return;

            var to = Path.Combine(canonicalDirectory, ClientInstallPaths.ConnectionsDirectoryName);
            Directory.CreateDirectory(to);

            var launchedConnectionId = TryGetLaunchedConnectionId(launchedExecutablePath);

            foreach (var sourceDir in Directory.EnumerateDirectories(from))
            {
                var name = Path.GetFileName(sourceDir);
                if (launchedConnectionId != null &&
                    !string.Equals(name, launchedConnectionId, StringComparison.OrdinalIgnoreCase))
                    continue;

                CopyConnectionFiles(sourceDir, Path.Combine(to, name));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[client-installation] Connection state migration failed: {ex.Message}");
        }
    }

    private static string? TryGetLaunchedConnectionId(string executablePath)
    {
        try
        {
            var config = ClientTemplate.ReadPatchSlot(File.ReadAllBytes(executablePath));
            return string.IsNullOrWhiteSpace(config.ApplicationName)
                ? null
                : ConnectionIdentity.ConnectionId(config);
        }
        catch
        {
            return null;
        }
    }

    private static void CopyConnectionFiles(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir))
        {
            var target = Path.Combine(destDir, Path.GetFileName(file));
            if (!File.Exists(target))
                File.Copy(file, target);
        }
    }

    private static bool PathsEqual(string? firstPath, string? secondPath)
    {
        if (string.IsNullOrWhiteSpace(firstPath) || string.IsNullOrWhiteSpace(secondPath))
            return false;

        var first = Path.GetFullPath(firstPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var second = Path.GetFullPath(secondPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Saves to a same-directory temporary link then replaces the visible
    /// link. An existing shortcut is therefore retained if creation of the
    /// replacement fails, and the Desktop never accumulates duplicate
    /// links. The shortcut target is EXACTLY <paramref name="targetPath"/>
    /// (the copied executable in C:\Program Files\SSP).
    ///
    /// Declared Windows-only because the Shell Link object it releases
    /// through <c>Marshal.FinalReleaseComObject</c> is a Windows COM API.
    /// Its single call site sits behind the <c>OperatingSystem.IsWindows()</c>
    /// gate in <see cref="InstallAndLaunchCanonicalIfNeeded"/>, exactly like
    /// <see cref="NotifyDesktopContentsChanged"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CreateOrReplaceShortcut(
        string shortcutPath,
        string targetPath,
        string workingDirectory)
    {
        var shortcutDirectory = Path.GetDirectoryName(shortcutPath)
            ?? throw new InvalidOperationException("The shortcut directory could not be resolved.");
        var temporaryPath = Path.Combine(
            shortcutDirectory,
            $".{Guid.NewGuid():N}{ShortcutExtension}");

        try
        {
            var shellLink = (IShellLinkW)new ShellLink();
            try
            {
                shellLink.SetPath(targetPath);
                shellLink.SetWorkingDirectory(workingDirectory);
                shellLink.SetDescription("SSP Client");
                ((IPersistFile)shellLink).Save(temporaryPath, fRemember: true);
            }
            finally
            {
                if (Marshal.IsComObject(shellLink))
                    Marshal.FinalReleaseComObject(shellLink);
            }

            File.Move(temporaryPath, shortcutPath, overwrite: true);
        }
        finally
        {
            // File.Move removes the temporary file on success. Best-effort
            // cleanup keeps a failed replacement from appearing as a
            // second Desktop shortcut.
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    /// <summary>
    /// Tells Explorer through the standard Shell change-notification API
    /// that the Desktop folder contents changed, so the newly created or
    /// replaced shortcut appears immediately without the user pressing
    /// F5. The shortcut is written as a temporary file and then renamed
    /// into place, which Explorer does not always pick up on its own.
    /// This only raises the documented notification; it never refreshes
    /// or restarts Explorer.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void NotifyDesktopContentsChanged(string desktopDirectory)
    {
        try
        {
            SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, desktopDirectory, IntPtr.Zero);
        }
        catch (Exception ex)
        {
            // The shortcut already exists on disk at this point. A missing
            // or failing shell32 notification must not abort the handoff;
            // the user would then only need a manual Desktop refresh.
            Console.Error.WriteLine(
                $"[client-installation] Desktop change notification failed: {ex.Message}");
        }
    }

    // shlobj_core.h: the contents of a directory changed; dwItem1 is a
    // Unicode path; flush the shell event buffer without blocking. Note
    // SHCNF_FLUSHNOWAIT is 0x3000 on current Windows SDKs because it
    // includes SHCNF_FLUSH (0x1000).
    private const int SHCNE_UPDATEDIR = 0x00001000;
    private const uint SHCNF_PATHW = 0x0005;
    private const uint SHCNF_FLUSHNOWAIT = 0x3000;

    [SupportedOSPlatform("windows")]
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern void SHChangeNotify(
        int eventId,
        uint flags,
        [MarshalAs(UnmanagedType.LPWStr)] string item1,
        IntPtr item2);

    [ComImport]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLinkW
    {
        void GetPath(
            [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder file,
            int cchMaxPath,
            IntPtr findData,
            uint flags);

        void GetIDList(out IntPtr itemIdList);
        void SetIDList(IntPtr itemIdList);

        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder description, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);

        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);

        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);

        void GetHotkey(out short hotkey);
        void SetHotkey(short hotkey);
        void GetShowCmd(out int showCommand);
        void SetShowCmd(int showCommand);

        void GetIconLocation(
            [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder iconPath,
            int cch,
            out int iconIndex);

        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string relativePath, uint reserved);
        void Resolve(IntPtr windowHandle, uint flags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string path);
    }

    [ComImport]
    [Guid("00021401-0000-0000-C000-000000000046")]
    private class ShellLink
    {
    }
}
