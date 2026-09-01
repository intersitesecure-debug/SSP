// File: tests/SSP.Tests/Activation/SspLicensingAndTrustAnchorTests.cs
//
// Tests for the SSP product identity constants and the trust-anchor
// composition. The trust anchor is a build/deployment constant; a build with
// no anchor compiled in must fail closed (throw) rather than silently
// enforcing against an assumed key.

using SSP.Activation;
using SSP.Core.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

public class SspLicensingAndTrustAnchorTests
{
    [Fact]
    public void ProductId_IsStableNonEmptyAndMatchesContract()
    {
        Assert.NotEqual(Guid.Empty, SspLicensing.ProductId);
        Assert.Equal(SspLicensing.ProductId, SspLicensing.ProductId);
        Assert.Equal("SSP", SspLicensing.ProductName);
        Assert.False(string.IsNullOrWhiteSpace(SspLicensing.InstallationBindingPurposeTag));

        // Host vocabulary documented for SSP.Core; the limit names must stay
        // in sync with the vendored SSP.Activation.LicenseLimitNames values.
        Assert.Equal(SSP.Activation.LicenseLimitNames.MaxServices, SspLicensing.Limits.MaxServices);
        Assert.Equal(SSP.Activation.LicenseLimitNames.MaxClients, SspLicensing.Limits.MaxClients);
        Assert.Equal(SSP.Activation.LicenseLimitNames.MaxSessions, SspLicensing.Limits.MaxSessions);
        Assert.Equal(SSP.Activation.LicenseLimitNames.MaxConcurrentSessions, SspLicensing.Limits.MaxConcurrentSessions);
        Assert.Equal(SSP.Activation.LicenseLimitNames.MaxConcurrentTunnels, SspLicensing.Limits.MaxConcurrentTunnels);
        Assert.Equal("rdp", SspLicensing.Features.RemoteDesktopProtocol);
    }

    [Fact]
    public void MinimumKeySize_MatchesLibraryContract()
    {
        Assert.Equal(LicenseTrustAnchor.MinimumKeySizeBits, SspTrustAnchor.MinimumKeySizeBits);
    }

    [Fact]
    public void Create_FailsClosedWhenNoProductionAnchorIsCompiledIn()
    {
        if (!SspTrustAnchor.IsCompiledIn)
        {
            var ex = Assert.Throws<InvalidOperationException>(() => SspTrustAnchor.Create());
            Assert.Contains("trust anchor", ex.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        // Once a real authority key is compiled in, Create() must build a
        // usable anchor (still never a private key).
        using var anchor = SspTrustAnchor.Create();
        Assert.NotNull(anchor);
        Assert.True(anchor.KeySizeBits >= LicenseTrustAnchor.MinimumKeySizeBits);
    }
}
