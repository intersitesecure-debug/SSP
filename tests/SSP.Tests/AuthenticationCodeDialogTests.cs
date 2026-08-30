// File: tests/SSP.Tests/AuthenticationCodeDialogTests.cs
//
// Tests for the server-side Authentication Code presentation seam.
// The native dialog itself cannot be unit tested headlessly, so we test
// the only testable boundary: the pure display-formatting function, and
// the guarantee that the underlying 10-digit value is not mutated.

using SSP.Core.Crypto;
using SSP.Server.UI;
using Xunit;

namespace SSP.Tests;

public class AuthenticationCodeDialogTests
{
    [Theory]
    [InlineData("5831940271", "583 194 0271")]
    [InlineData("0000000000", "000 000 0000")]
    [InlineData("1234567890", "123 456 7890")]
    [InlineData("9998887777", "999 888 7777")]
    public void FormatForDisplay_GroupsTenDigits_AsThreeThreeFour(string raw, string expected)
    {
        Assert.Equal(expected, AuthenticationCodeDialog.FormatForDisplay(raw));
    }

    [Fact]
    public void FormatForDisplay_DoesNotAlterUnderlyingValue()
    {
        // The raw generated code must remain exactly 10 digits with no
        // spaces; formatting is presentation only and must never be fed
        // back into validation/hashing/comparison.
        var raw = TokenGenerator.GenerateAuthenticationCode();

        Assert.Equal(10, raw.Length);
        Assert.All(raw, c => Assert.InRange(c, '0', '9'));

        var display = AuthenticationCodeDialog.FormatForDisplay(raw);
        Assert.NotEqual(raw, display);

        // Stripping the presentation spaces must recover the exact raw
        // value (documents the no-semantics-change guarantee).
        Assert.Equal(raw, display.Replace(" ", string.Empty));
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("12345678901")]
    [InlineData("12-45-7890")]
    public void FormatForDisplay_NonCanonicalInput_ReturnedUnchanged(string input)
    {
        // Defensive: anything that is not exactly 10 ASCII digits is
        // returned verbatim rather than being partially reformatted.
        Assert.Equal(input, AuthenticationCodeDialog.FormatForDisplay(input));
    }

    [Fact]
    public void Title_IsConstant_SspAuthentication()
    {
        Assert.Equal("SSP Authentication", AuthenticationCodeDialog.Title);
    }

    [Fact]
    public async Task ShowAsync_WhenSuppressed_ReturnsWithoutThrowing()
    {
        // The test assembly sets SSP_SUPPRESS_AUTH_DIALOG in its module
        // initializer; ShowAsync must complete immediately on all
        // platforms (this is what keeps enrollment tests from blocking on
        // WTSSendMessage / MessageBox). Production service processes do
        // not set this variable.
        Assert.Equal("SSP_SUPPRESS_AUTH_DIALOG", AuthenticationCodeDialog.SuppressEnvironmentVariable);
        Assert.False(string.IsNullOrEmpty(
            Environment.GetEnvironmentVariable(AuthenticationCodeDialog.SuppressEnvironmentVariable)));
        await AuthenticationCodeDialog.ShowAsync("RDP", "5831940271");
    }
}
