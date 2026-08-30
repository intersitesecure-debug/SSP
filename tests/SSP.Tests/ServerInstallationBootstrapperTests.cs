// File: tests/SSP.Tests/ServerInstallationBootstrapperTests.cs
//
// Unit coverage for the path gate used before the existing SETUP MODE entry.

using SSP.Server.Setup;

namespace SSP.Tests;

public sealed class ServerInstallationBootstrapperTests
{
    private const string OfficialPath = @"C:\Program Files\SSP\SSP.Server.exe";

    [Theory]
    [InlineData(@"C:\Program Files\SSP\SSP.Server.exe", false)]
    [InlineData(@"c:\program files\ssp\ssp.server.exe", false)]
    [InlineData(@"C:\Users\Operator\Downloads\SSP.Server.exe", true)]
    [InlineData(@"D:\Deployment\SSP.Server.exe", true)]
    public void RequiresInstallation_OnlyForServerExecutableOutsideOfficialPath(
        string processPath,
        bool expected)
    {
        Assert.Equal(
            expected,
            ServerInstallationBootstrapper.RequiresInstallation(processPath, OfficialPath));
    }

    [Theory]
    [InlineData(@"C:\Users\Operator\Downloads\dotnet.exe")]
    [InlineData(@"C:\Users\Operator\Downloads\SSP.Server.dll")]
    [InlineData("")]
    public void RequiresInstallation_RejectsNonServerProcesses(string processPath)
    {
        Assert.False(ServerInstallationBootstrapper.RequiresInstallation(processPath, OfficialPath));
    }

    [Fact]
    public void Bootstrapper_UsesTheRequiredSingleShortcutAndExecutableNames()
    {
        Assert.Equal("SSP.Server.exe", ServerInstallationBootstrapper.ExecutableFileName);
        Assert.Equal("SSP Server", ServerInstallationBootstrapper.ShortcutName);
    }
}
