using SSP.Activation;

namespace SSP.Activation.Tests.Activation;

/// <summary>Authority-side activation-material generation and constant-time verification helpers.</summary>
public class LicenseActivationTests
{
    [Fact]
    public void GeneratedCode_IsExactlyTenDecimalDigits()
    {
        for (var i = 0; i < 200; i++)
        {
            var code = LicenseActivation.GenerateActivationCode();
            Assert.True(LicenseActivation.IsValidActivationCode(code), $"'{code}' is not a valid activation code.");
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("123456789")]       // 9 digits
    [InlineData("12345678901")]     // 11 digits
    [InlineData("123456789a")]      // non-digit
    [InlineData("12345 6789")]      // 9 digits + space
    public void InvalidCodes_AreRejected(string? code)
    {
        Assert.False(LicenseActivation.IsValidActivationCode(code));
    }

    [Fact]
    public void CodeHash_IsStableAndLowercaseHex()
    {
        var hash = LicenseActivation.ComputeActivationCodeHash("1234567890");
        Assert.Equal(64, hash.Length);
        Assert.Equal(hash, hash.ToLowerInvariant());
        Assert.Equal(hash, LicenseActivation.ComputeActivationCodeHash("1234567890"));
        // Whitespace is normalized before hashing.
        Assert.Equal(hash, LicenseActivation.ComputeActivationCodeHash("1234 5678 90"));
        // Different code, different hash.
        Assert.NotEqual(hash, LicenseActivation.ComputeActivationCodeHash("1234567891"));
    }

    [Fact]
    public void ActivationCodeMatches_ComparesAgainstSignedHash()
    {
        var hash = LicenseActivation.ComputeActivationCodeHash("9876543210");

        Assert.True(LicenseActivation.ActivationCodeMatches(hash, "9876543210"));
        Assert.True(LicenseActivation.ActivationCodeMatches(hash, "9876 5432 10"));
        Assert.False(LicenseActivation.ActivationCodeMatches(hash, "9876543211"));
        Assert.False(LicenseActivation.ActivationCodeMatches(hash, null));
        Assert.False(LicenseActivation.ActivationCodeMatches(null, "9876543210"));
        Assert.False(LicenseActivation.ActivationCodeMatches("not-a-hash", "9876543210"));
    }

    [Fact]
    public void Ott_IsRandomAndBase64Url()
    {
        var a = LicenseActivation.GenerateActivationOtt();
        var b = LicenseActivation.GenerateActivationOtt();

        Assert.NotEqual(a, b);
        Assert.Equal(43, a.Length); // 32 random bytes -> unpadded base64url
        Assert.DoesNotContain('+', a);
        Assert.DoesNotContain('/', a);
        Assert.DoesNotContain('=', a);
    }

    [Fact]
    public void OttMatches_IsConstantTimeAndStrict()
    {
        var ott = LicenseActivation.GenerateActivationOtt();

        Assert.True(LicenseActivation.OttMatches(ott, ott));
        Assert.False(LicenseActivation.OttMatches(ott, LicenseActivation.GenerateActivationOtt()));
        Assert.False(LicenseActivation.OttMatches(ott, null));
        Assert.False(LicenseActivation.OttMatches(null, ott));
        Assert.False(LicenseActivation.OttMatches(ott, ott + "extra"));
    }
}
