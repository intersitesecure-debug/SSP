// File: src/SSP.Core/Crypto/AuthenticationCodeAbusePolicy.cs
//
// Offline Authentication Code abuse controls that sit in front of the
// Phase 1 three-attempt lockout. All state is local to the hashed OTT on
// the server; nothing here introduces a network dependency.

namespace SSP.Core.Crypto;

/// <summary>
/// Progressive, fully offline cooldown applied after failed Authentication
/// Code submissions. The delay is keyed per hashed One-Time Token so two
/// pending enrollments cannot starve each other.
/// </summary>
public static class AuthenticationCodeAbusePolicy
{
    /// <summary>Cooldown after the first failed code for an OTT.</summary>
    public static readonly TimeSpan DelayAfterFirstFailure = TimeSpan.FromSeconds(2);

    /// <summary>Cooldown after the second failed code for an OTT.</summary>
    public static readonly TimeSpan DelayAfterSecondFailure = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Cooldown that starts once <paramref name="failedAttempts"/> wrong codes
    /// have been recorded. Zero when no delay applies (no failures yet, or
    /// the Phase 1 lockout has already consumed the OTT).
    /// </summary>
    public static TimeSpan CooldownAfterFailures(int failedAttempts)
    {
        return failedAttempts switch
        {
            1 => DelayAfterFirstFailure,
            2 => DelayAfterSecondFailure,
            _ => TimeSpan.Zero
        };
    }

    /// <summary>
    /// True when a new Authentication Code may be generated for this OTT.
    /// A missing timestamp allows the attempt. An unparsable timestamp is
    /// fail-closed: the retry is refused rather than skipping the cooldown.
    /// </summary>
    public static bool IsRetryAllowed(string? retryNotBeforeUtc, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(retryNotBeforeUtc))
            return true;

        if (!DateTimeOffset.TryParse(retryNotBeforeUtc, out var notBefore))
            return false;

        return now >= notBefore;
    }

    /// <summary>
    /// UTC timestamp (round-trip ISO-8601) at which the next guess is
    /// allowed, or null when no cooldown applies.
    /// </summary>
    public static string? NextRetryUtc(int failedAttempts, DateTimeOffset now)
    {
        var delay = CooldownAfterFailures(failedAttempts);
        if (delay <= TimeSpan.Zero)
            return null;

        return now.ToUniversalTime().Add(delay).ToString("o");
    }
}
