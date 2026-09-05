// File: tests/SSP.Tests/Helpers/EnrollmentCooldown.cs
//
// Test-side control of the Phase 2 progressive Authentication Code
// cooldown (SSP.Core.Crypto.AuthenticationCodeAbusePolicy).
//
// After a wrong Authentication Code the server stamps the One-Time Token
// with AuthenticationCodeRetryNotBeforeUtc (2s after the first failure,
// 10s after the second) and REFUSES to mint a new code before that
// instant: it answers EnrollmentResult{Success=false,
// ErrorOrWait="verification failed"}, which the client surfaces as
// InvalidOperationException("Enrollment rejected by server: verification
// failed").
//
// That is the intended production behaviour, so a test that performs a
// second enrollment attempt for the same OTT must either sleep out the
// cooldown (slow, and flaky on loaded CI agents) or clear the stamp
// explicitly. These helpers do the latter, deterministically, using the
// same cross-process file lock the server takes.

using SSP.Core.IO;

namespace SSP.Tests.Helpers;

internal static class EnrollmentCooldown
{
    /// <summary>
    /// Clear the per-OTT Authentication Code cooldown for every token of
    /// this harness's service so the next enrollment attempt is allowed
    /// to generate a fresh code immediately. Recorded failure COUNTS are
    /// deliberately left untouched: the three-attempt lockout must keep
    /// behaving exactly as in production.
    /// </summary>
    public static Task ClearAsync(SspTestHarness harness, CancellationToken ct = default) =>
        ForceAsync(harness, retryNotBeforeUtc: null, ct);

    /// <summary>Force a specific retry instant (used by rate-limit tests).</summary>
    public static Task ForceAsync(
        SspTestHarness harness,
        DateTimeOffset retryNotBefore,
        CancellationToken ct = default) =>
        ForceAsync(harness, retryNotBefore.ToString("o"), ct);

    /// <summary>Write <paramref name="retryNotBeforeUtc"/> (null clears) to every OTT record.</summary>
    public static async Task ForceAsync(
        SspTestHarness harness,
        string? retryNotBeforeUtc,
        CancellationToken ct = default)
    {
        var path = Path.Combine(harness.ServiceDir, ".cache.dat");

        using (await ServiceConfigFileLock.AcquireAsync(harness.ServiceDir, ct).ConfigureAwait(false))
        {
            var config = await ServiceConfigStore.LoadAsync(path, ct).ConfigureAwait(false);

            config.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc = retryNotBeforeUtc;

            config.PendingOneTimeTokens ??= new List<SSP.Core.Models.PendingOneTimeToken>();
            foreach (var pending in config.PendingOneTimeTokens)
                pending.AuthenticationCodeRetryNotBeforeUtc = retryNotBeforeUtc;

            await ServiceConfigStore.SaveAsync(path, config, ct).ConfigureAwait(false);
        }
    }
}
