// File: src/SSP.Server/Setup/ServerInstallationBootstrapper.cs
//
// Windows launch handoff for SSP.Server. A server executable first started
// outside its canonical Program Files location is copied there, represented
// by one Desktop shortcut, then launched from that shortcut for SETUP MODE.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Text;

namespace SSP.Server.Setup;

/// <summary>
/// Installs a manually launched <c>SSP.Server.exe</c> into the canonical
/// Windows location and starts the canonical executable through its Desktop
/// shortcut. This class deliberately does not own any SETUP MODE logic; it
/// only hands execution to the existing mode after the location is correct.
/// </summary>
internal static class ServerInstallationBootstrapper
{
    internal const string ExecutableFileName = "SSP.Server.exe";
    internal const string ProductDirectoryName = "SSP";
    internal const string ShortcutName = "SSP Server";
    private const string ShortcutExtension = ".lnk";

    /// <summary>
    /// Attempts the Windows install handoff for the current process. Returns
    /// <see langword="true"/> only when the copied executable was launched
    /// through the Desktop shortcut, in which case the caller must exit the
    /// original process.
    /// </summary>
    internal static bool InstallAndLaunchSetupIfNeeded()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        var officialExecutablePath = GetOfficialExecutablePath();
        var currentExecutablePath = Environment.ProcessPath;
        if (!RequiresInstallation(currentExecutablePath, officialExecutablePath))
            return false;

        var installationDirectory = Path.GetDirectoryName(officialExecutablePath)
            ?? throw new InvalidOperationException("The SSP installation directory could not be resolved.");
        Directory.CreateDirectory(installationDirectory);

        // The source is the actual apphost process, never the working
        // directory or an assembly path. This preserves a single-file
        // published executable exactly as it was launched.
        File.Copy(currentExecutablePath!, officialExecutablePath, overwrite: true);

        var desktopDirectory = Environment.GetEnvironmentVariable("SSP_DESKTOP_DIR");
        if (string.IsNullOrWhiteSpace(desktopDirectory))
        {
            desktopDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        }
        if (string.IsNullOrWhiteSpace(desktopDirectory))
            throw new InvalidOperationException("The current user's Desktop directory could not be resolved.");

        Directory.CreateDirectory(desktopDirectory);
        var shortcutPath = Path.Combine(desktopDirectory, ShortcutName + ShortcutExtension);
        CreateOrReplaceShortcut(shortcutPath, officialExecutablePath, installationDirectory);
        NotifyDesktopContentsChanged(desktopDirectory);

        // Launch the .lnk itself, rather than the target path, so this is
        // precisely the shortcut just created or replaced above.
        Process.Start(new ProcessStartInfo
        {
            FileName = shortcutPath,
            UseShellExecute = true,
        });

        return true;
    }

    /// <summary>
    /// Canonical production location of the server executable. Program Files
    /// is resolved through .NET rather than repeated literal path fragments.
    /// On a standard 64-bit Windows installation this is
    /// <c>C:\Program Files\SSP\SSP.Server.exe</c>.
    /// </summary>
    internal static string GetOfficialExecutablePath()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            throw new InvalidOperationException("The Windows Program Files directory could not be resolved.");

        return Path.Combine(programFiles, ProductDirectoryName, ExecutableFileName);
    }

    /// <summary>
    /// True when the process is the server apphost and is not already running
    /// from the canonical installation path.
    /// </summary>
    internal static bool RequiresInstallation(string? processPath, string officialExecutablePath)
    {
        if (string.IsNullOrWhiteSpace(processPath) ||
            string.IsNullOrWhiteSpace(officialExecutablePath))
        {
            return false;
        }

        try
        {
            if (!string.Equals(
                    GetFileName(processPath),
                    ExecutableFileName,
                    StringComparison.OrdinalIgnoreCase))
            {
                // Framework-dependent `dotnet SSP.Server.dll` runs must not
                // copy dotnet.exe as SSP.Server.exe.
                return false;
            }

            return !PathsEqual(processPath, officialExecutablePath);
        }
        catch
        {
            // If an unusual process path cannot be normalised, leave command
            // handling untouched rather than copying an uncertain file.
            return false;
        }
    }

    private static string GetFileName(string path)
    {
        var separator = path.LastIndexOfAny(new[] { '\\', '/' });
        return separator < 0 ? path : path[(separator + 1)..];
    }

    private static bool PathsEqual(string firstPath, string secondPath)
    {
        var first = Path.GetFullPath(firstPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var second = Path.GetFullPath(secondPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Saves to a same-directory temporary link then replaces the visible
    /// link. An existing shortcut is therefore retained if creation of the
    /// replacement fails, and the Desktop never accumulates duplicate links.
    ///
    /// Declared Windows-only because the Shell Link object it releases through
    /// <c>Marshal.FinalReleaseComObject</c> is a Windows COM API. Its single
    /// call site sits behind the <c>OperatingSystem.IsWindows()</c> gate in
    /// <see cref="InstallAndLaunchSetupIfNeeded"/>, exactly like
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
            $".{ShortcutName}.{Guid.NewGuid():N}{ShortcutExtension}");

        try
        {
            var shellLink = (IShellLinkW)new ShellLink();
            try
            {
                shellLink.SetPath(targetPath);
                shellLink.SetWorkingDirectory(workingDirectory);
                shellLink.SetDescription("SSP Server setup");
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
            // cleanup keeps a failed replacement from appearing as a second
            // Desktop shortcut.
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    /// <summary>
    /// Tells Explorer through the standard Shell change-notification API that
    /// the Desktop folder contents changed, so the newly created or replaced
    /// shortcut appears without the user pressing F5. The shortcut is written
    /// as a temporary file and then renamed into place, which Explorer does
    /// not always pick up on its own. This only raises the documented
    /// notification; it never refreshes or restarts Explorer.
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
                $"[server-installation] Desktop change notification failed: {ex.Message}");
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
