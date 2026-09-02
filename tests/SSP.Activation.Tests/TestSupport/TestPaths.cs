namespace SSP.Activation.Tests.TestSupport;

/// <summary>Temp file helpers rooted inside the test working directory (never the OS temp dir).</summary>
internal static class TestPaths
{
    public static string CreateTempDirectory()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "test-tmp", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static string WriteFile(string directory, string fileName, string content)
    {
        var path = Path.Combine(directory, fileName);
        File.WriteAllText(path, content);
        return path;
    }

    public static void DeleteDirectory(string directory)
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
