// File: tests/SSP.Tests/Activation/SspInstallationIdentityProviderTests.cs
//
// Tests for the SSP installation identity adapter. The raw Windows
// MachineGuid is never exposed; the provider returns only a stable SHA-256
// domain-separated hash. Non-Windows hosts report unavailable identity so
// installation-bound licenses fail closed (reference library semantics).

using SSP.Server.Activation;

namespace SSP.Tests.Activation;

public class SspInstallationIdentityProviderTests
{
    [Fact]
    public void ComputeInstallationId_IsDeterministic()
    {
        const string machineGuid = "01234567-89ab-cdef-0123-456789abcdef";

        var first = SspInstallationIdentityProvider.ComputeInstallationId(machineGuid);
        var second = SspInstallationIdentityProvider.ComputeInstallationId(machineGuid);

        Assert.Equal(first, second);
    }

    [Fact]
    public void ComputeInstallationId_IsLowercaseHexSha256()
    {
        // SHA-256 output: 64 lowercase hex characters - never the raw input.
        var id = SspInstallationIdentityProvider.ComputeInstallationId("01234567-89ab-cdef-0123-456789abcdef");

        Assert.Matches("^[0-9a-f]{64}$", id);
        Assert.DoesNotContain("01234567", id, StringComparison.Ordinal);
        Assert.DoesNotContain("MachineGuid", id, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ComputeInstallationId_ChangesWithMachineGuid()
    {
        var a = SspInstallationIdentityProvider.ComputeInstallationId("MACHINE-A");
        var b = SspInstallationIdentityProvider.ComputeInstallationId("MACHINE-B");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeInstallationId_RejectsEmptyInput()
    {
        Assert.Throws<ArgumentException>(() => SspInstallationIdentityProvider.ComputeInstallationId(""));
        Assert.Throws<ArgumentException>(() => SspInstallationIdentityProvider.ComputeInstallationId("   "));
        Assert.Throws<ArgumentException>(() => SspInstallationIdentityProvider.ComputeInstallationId(null!));
    }

    [Fact]
    public void NonWindowsHost_ReturnsNull_AndNeverThrows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var provider = new SspInstallationIdentityProvider();

        Assert.Null(provider.GetInstallationId());
        Assert.Null(provider.GetInstallationId());
    }

    [Fact]
    public void WindowsHost_ReturnsStableHashedMachineGuid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var provider = new SspInstallationIdentityProvider();

        var first = provider.GetInstallationId();
        var second = provider.GetInstallationId();

        Assert.NotNull(first);
        Assert.Matches("^[0-9a-f]{64}$", first);
        Assert.Equal(first, second);
    }
}
