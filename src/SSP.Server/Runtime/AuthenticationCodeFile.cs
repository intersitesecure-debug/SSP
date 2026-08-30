// File: src/SSP.Server/Runtime/AuthenticationCodeFile.cs
//
// Administrator readout of the enrollment Authentication Code.
//
// The code is generated per enrollment request and is compared against
// the value the client operator types. It is never sent over the
// network. This file is only a local display channel so a separate
// utility can show the current code to the server administrator.

namespace SSP.Server.Runtime;

/// <summary>
/// Writes the current 10-digit Authentication Code to
/// <c>C:\Program Files\SSP\Authcode.txt</c> (or a test override).
/// </summary>
public static class AuthenticationCodeFile
{
    /// <summary>Production directory for the administrator readout file.</summary>
    public const string DefaultDirectory = @"C:\Program Files\SSP";

    /// <summary>File name only; always combined with <see cref="ResolveDirectory"/>.</summary>
    public const string FileName = "Authcode.txt";

    /// <summary>
    /// When set, the readout file is written here instead of
    /// <see cref="DefaultDirectory"/>. Used by tests so they never
    /// touch Program Files.
    /// </summary>
    public const string DirectoryOverrideVariable = "SSP_AUTHCODE_DIR";

    public static string ResolveDirectory()
    {
        var overrideDir = Environment.GetEnvironmentVariable(DirectoryOverrideVariable);
        return string.IsNullOrWhiteSpace(overrideDir) ? DefaultDirectory : overrideDir;
    }

    public static string ResolvePath() => Path.Combine(ResolveDirectory(), FileName);

    /// <summary>
    /// Create the directory if needed and overwrite the file with the
    /// current 10-digit code plus a trailing newline.
    /// </summary>
    public static void Write(string authenticationCode)
    {
        // On non-Windows hosts there is no Program Files tree. Skip
        // unless a test (or operator) has redirected the path.
        if (!OperatingSystem.IsWindows() &&
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(DirectoryOverrideVariable)))
        {
            return;
        }

        var directory = ResolveDirectory();
        Directory.CreateDirectory(directory);
        File.WriteAllText(ResolvePath(), authenticationCode + Environment.NewLine);
    }
}
