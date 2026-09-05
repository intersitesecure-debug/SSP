// File: tests/SSP.Tests/AuthenticationCodeAbusePolicyTests.cs
//
// Pure tests for the offline Authentication Code cooldown policy. No
// network, no gateway, and no client package is involved.

using SSP.Core.Crypto;

namespace SSP.Tests;

public class AuthenticationCodeAbusePolicyTests
{
    [Fact]
    public void CooldownAfterFailures_IsTwoSecondsThenTenSeconds()
    {
        Assert.Equal(TimeSpan.Zero, AuthenticationCodeAbusePolicy.CooldownAfterFailures(0));
        Assert.Equal(TimeSpan.FromSeconds(2), AuthenticationCodeAbusePolicy.CooldownAfterFailures(1));
        Assert.Equal(TimeSpan.FromSeconds(10), AuthenticationCodeAbusePolicy.CooldownAfterFailures(2));
        Assert.Equal(TimeSpan.Zero, AuthenticationCodeAbusePolicy.CooldownAfterFailures(3));
    }

    [Fact]
    public void IsRetryAllowed_MissingTimestamp_AllowsAttempt()
    {
        var now = DateTimeOffset.Parse("2026-09-05T12:00:00Z");
        Assert.True(AuthenticationCodeAbusePolicy.IsRetryAllowed(null, now));
        Assert.True(AuthenticationCodeAbusePolicy.IsRetryAllowed(string.Empty, now));
    }

    [Fact]
    public void IsRetryAllowed_FutureTimestamp_DeniesAttempt()
    {
        var now = DateTimeOffset.Parse("2026-09-05T12:00:00Z");
        var notBefore = now.AddSeconds(2).ToString("o");
        Assert.False(AuthenticationCodeAbusePolicy.IsRetryAllowed(notBefore, now));
        Assert.True(AuthenticationCodeAbusePolicy.IsRetryAllowed(notBefore, now.AddSeconds(2)));
    }

    [Fact]
    public void IsRetryAllowed_UnparsableTimestamp_FailsClosed()
    {
        var now = DateTimeOffset.Parse("2026-09-05T12:00:00Z");
        Assert.False(AuthenticationCodeAbusePolicy.IsRetryAllowed("not-a-timestamp", now));
    }

    [Fact]
    public void NextRetryUtc_MatchesCooldownTable()
    {
        var now = DateTimeOffset.Parse("2026-09-05T12:00:00Z");

        Assert.Null(AuthenticationCodeAbusePolicy.NextRetryUtc(0, now));
        Assert.Null(AuthenticationCodeAbusePolicy.NextRetryUtc(3, now));

        var afterFirst = AuthenticationCodeAbusePolicy.NextRetryUtc(1, now);
        var afterSecond = AuthenticationCodeAbusePolicy.NextRetryUtc(2, now);

        Assert.Equal(now.AddSeconds(2), DateTimeOffset.Parse(afterFirst!));
        Assert.Equal(now.AddSeconds(10), DateTimeOffset.Parse(afterSecond!));
    }
}
