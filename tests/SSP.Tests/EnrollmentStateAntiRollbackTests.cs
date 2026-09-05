// File: tests/SSP.Tests/EnrollmentStateAntiRollbackTests.cs
//
// Phase 4 (M-3) of the Security Correction roadmap, enrollment half: the
// Phase 1/2 Authentication-Code abuse controls (failure counter, progressive
// cooldown, three-attempt OTT revocation, single-use OTT consumption) are
// persisted only in the service directory's .cache.dat. These tests pin that
// a local administrator rolling that file back to an older copy can no
// longer:
//
//   * resurrect a REVOKED OTT (the witnessed revocation is final),
//   * reset the failure COUNTER (the next wrong code counts against the
//     witnessed total and revokes early),
//   * shrink the COOLDOWN (the witnessed retry instant is a lower bound),
//   * revive a CONSUMED OTT (the witnessed consumption is final).
//
// Every rollback is simulated exactly as an attacker would do it: a byte
// copy of .cache.dat captured earlier is written back over the current file
// (the file is encrypted at rest; the backup/restore semantics are the
// attack). The witness lives outside the service directory and is never
// restored.
//
// Also pinned: a corrupt witness fails enrollment closed, the witness is
// encrypted at rest, and a fresh service without any witness enrolls
// normally (no false positives).

using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Client.Runtime;
using SSP.Server.Runtime;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class EnrollmentStateAntiRollbackTests
{
    [Fact]
    public async Task RolledBackConfig_AfterRevocation_OttStaysRevoked()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        // The pre-attack state of .cache.dat (OTT pending, zero failures).
        var configPath = Path.Combine(harness.ServiceDir, ".cache.dat");
        var backupPath = configPath + ".rollback-test";
        File.Copy(configPath, backupPath);

        // Three wrong codes permanently revoke the OTT (Phase 1).
        for (var attempt = 0; attempt < 3; attempt++)
        {
            await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
            if (attempt < 2)
                await EnrollmentCooldown.ClearAsync(harness);
        }

        // The attack: restore the pre-revocation config.
        File.Copy(backupPath, configPath, overwrite: true);

        var (errors, ex) = await CaptureEnrollmentFailureAsync(harness, ott);

        // The witnessed revocation is final: the OTT cannot enroll again.
        Assert.NotNull(ex);
        Assert.Contains("event=Enrollment.StateRollbackDetected failedAttempts=3", errors);
        Assert.DoesNotContain("event=Enrollment.OTTRevokedAfterFailedAttempts", errors);

        var users = await AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));
        Assert.Empty(users.Users);

        TryDelete(backupPath);
    }

    [Fact]
    public async Task RolledBackConfig_AfterTwoFailures_NextWrongCodeRevokesImmediately()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var configPath = Path.Combine(harness.ServiceDir, ".cache.dat");
        var backupPath = configPath + ".rollback-test";
        File.Copy(configPath, backupPath);

        // Two wrong codes (counter 2 witnessed).
        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        await EnrollmentCooldown.ClearAsync(harness);
        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);

        // The attack: restore the zero-failure config, then submit ONE more
        // wrong code. The effective count is max(1, 2) = 3: revocation.
        File.Copy(backupPath, configPath, overwrite: true);
        await EnrollmentCooldown.ClearAsync(harness);

        var originalError = Console.Error;
        var errors = new StringWriter();
        Console.SetError(errors);
        try
        {
            await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        }
        finally
        {
            Console.SetError(originalError);
        }

        var config = await ServiceConfigStore.LoadAsync(configPath);
        Assert.Empty(config.PendingOneTimeTokens);
        Assert.Null(config.ActiveOneTimeTokenHash);
        Assert.Contains("event=Enrollment.OTTRevokedAfterFailedAttempts failedAttempts=3", errors.ToString());
        Assert.Contains("event=Enrollment.StateRollbackDetected failedAttempts=2", errors.ToString());

        TryDelete(backupPath);
    }

    [Fact]
    public async Task RolledBackConfig_WitnessedCooldownCannotBeShrunk()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var configPath = Path.Combine(harness.ServiceDir, ".cache.dat");
        var backupPath = configPath + ".rollback-test";
        File.Copy(configPath, backupPath);

        // Two wrong codes put the OTT into the 10-second cooldown.
        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        await EnrollmentCooldown.ClearAsync(harness);
        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);

        // The attack: restore the zero-failure config (no counter, no
        // cooldown) and immediately ask for a new code.
        File.Copy(backupPath, configPath, overwrite: true);

        var originalOut = Console.Out;
        var originalError = Console.Error;
        var output = new StringWriter();
        var errors = new StringWriter();
        Console.SetOut(output);
        Console.SetError(errors);
        try
        {
            var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
            var protocol = new ClientProtocol(
                runtime,
                () => throw new InvalidOperationException(
                    "Authentication code reader must not run during the witnessed cooldown."));
            var ex = await Assert.ThrowsAnyAsync<Exception>(
                () => protocol.ConnectAndAuthenticateAsync());
            Assert.Contains("verification failed", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }

        // No code was minted, no attempt was recorded against the restored
        // config, and both the rate-limit and the rollback signals fired.
        Assert.False(EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out _));
        Assert.Contains("event=Enrollment.AuthenticationCodeRateLimited failedAttempts=2", errors.ToString());
        Assert.Contains("event=Enrollment.StateRollbackDetected failedAttempts=2", errors.ToString());

        var config = await ServiceConfigStore.LoadAsync(configPath);
        var pending = Assert.Single(config.PendingOneTimeTokens);
        Assert.Equal(0, pending.FailedAuthenticationCodeAttempts);

        TryDelete(backupPath);
    }

    [Fact]
    public async Task RolledBackConfig_AfterConsumption_OttCannotEnrollTwice()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var configPath = Path.Combine(harness.ServiceDir, ".cache.dat");
        var backupPath = configPath + ".rollback-test";
        File.Copy(configPath, backupPath);

        // A completed enrollment consumes the OTT (single-use, spec §12/§16).
        await EnrollOnceAsync(harness, ott);
        var users = await AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));
        Assert.Single(users.Users);

        // The attack: restore the pre-enrollment config so the OTT looks
        // pending again, then present it for a second enrollment.
        File.Copy(backupPath, configPath, overwrite: true);

        var (errors, ex) = await CaptureEnrollmentFailureAsync(harness, ott);

        // The witnessed consumption is final: a spent OTT cannot enroll a
        // second client, no matter what .cache.dat claims.
        Assert.NotNull(ex);
        Assert.Contains("event=Enrollment.StateRollbackDetected", errors);

        users = await AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));
        Assert.Single(users.Users);

        TryDelete(backupPath);
    }

    [Fact]
    public async Task CorruptWitness_EnrollmentFailsClosed()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        // One wrong code establishes the witness.
        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        await EnrollmentCooldown.ClearAsync(harness);

        // The attack: corrupt the witness in place.
        File.WriteAllBytes(
            EnrollmentStateWitnessStore.GetWitnessPath(harness.ServiceDir),
            "not-an-envelope"u8.ToArray());

        var (errors, ex) = await CaptureEnrollmentFailureAsync(harness, ott);

        // An unreadable witness is an integrity violation: enrollment is
        // refused rather than recorded against unknown state.
        Assert.NotNull(ex);
        Assert.Contains("event=Enrollment.StateWitnessUnavailable", errors);

        var users = await AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));
        Assert.Empty(users.Users);
    }

    [Fact]
    public async Task SuccessfulEnrollment_WitnessesConsumption()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        await EnrollOnceAsync(harness, ott);

        var witness = await EnrollmentStateWitnessStore.LoadAsync(harness.ServiceDir);
        Assert.NotNull(witness);

        var entry = witness!.Find(TokenGenerator.HashOneTimeToken(ott));
        Assert.NotNull(entry);
        Assert.True(entry!.Consumed);
        Assert.False(entry.Revoked);
    }

    [Fact]
    public async Task RevokedOtt_WitnessRecordsRevocation()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        for (var attempt = 0; attempt < 3; attempt++)
        {
            await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
            if (attempt < 2)
                await EnrollmentCooldown.ClearAsync(harness);
        }

        var witness = await EnrollmentStateWitnessStore.LoadAsync(harness.ServiceDir);
        Assert.NotNull(witness);

        var entry = witness!.Find(TokenGenerator.HashOneTimeToken(ott));
        Assert.NotNull(entry);
        Assert.True(entry!.Revoked);
        Assert.Equal(3, entry.FailedAttempts);
    }

    [Fact]
    public async Task EnrollmentWitness_IsEncryptedAtRest()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);

        var bytes = File.ReadAllBytes(EnrollmentStateWitnessStore.GetWitnessPath(harness.ServiceDir));
        Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes),
            "Enrollment witness is not in the SSP encrypted-at-rest envelope.");

        var directText = System.Text.Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain("FailedAttempts", directText, StringComparison.Ordinal);
        Assert.DoesNotContain(TokenGenerator.HashOneTimeToken(ott), directText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FreshService_WithoutWitness_EnrollsNormally()
    {
        // No false positives: a service that has never recorded a failure has
        // no witness at all, and enrollment behaves exactly as before Phase 4.
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        Assert.False(File.Exists(EnrollmentStateWitnessStore.GetWitnessPath(harness.ServiceDir)));

        await EnrollOnceAsync(harness, ott);

        var users = await AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));
        Assert.Single(users.Users);
        Assert.True(users.Users[0].IsAuthorized);
    }

    // ────────────────────────────────────────────────────────────────
    // Helpers (same driving style as F4_EnrollmentTests; the enrollment
    // banner is read from the captured console output).
    // ────────────────────────────────────────────────────────────────

    private static async Task AttemptEnrollmentWithWrongCodeAsync(
        SspTestHarness harness,
        string ott)
    {
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        var originalOut = Console.Out;
        var output = new StringWriter();
        Console.SetOut(output);

        try
        {
            var protocol = new ClientProtocol(
                runtime,
                async () =>
                {
                    while (true)
                    {
                        if (EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out var code))
                        {
                            var replacement = code[0] == '0' ? '1' : '0';
                            return replacement + code[1..];
                        }

                        await Task.Delay(20);
                    }
                });

            await Assert.ThrowsAnyAsync<Exception>(() => protocol.ConnectAndAuthenticateAsync());
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    private static async Task EnrollOnceAsync(
        SspTestHarness harness,
        string ott)
    {
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        var originalOut = Console.Out;
        var output = new StringWriter();
        Console.SetOut(output);

        try
        {
            var protocol = new ClientProtocol(
                runtime,
                async () =>
                {
                    while (true)
                    {
                        if (EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out var extracted))
                            return extracted;

                        await Task.Delay(20);
                    }
                });

            var (tcp, _) = await protocol.ConnectAndAuthenticateAsync();
            tcp.Dispose();
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    /// <summary>
    /// Drives one enrollment attempt for <paramref name="ott"/> whose code
    /// reader never runs (the server must reject the OTT before the code
    /// stage), and captures stderr so the caller can assert on the security
    /// events.
    /// </summary>
    private static async Task<(string Errors, Exception? Exception)> CaptureEnrollmentFailureAsync(
        SspTestHarness harness,
        string ott)
    {
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        var originalError = Console.Error;
        var errors = new StringWriter();
        Console.SetError(errors);

        try
        {
            var protocol = new ClientProtocol(
                runtime,
                () => throw new InvalidOperationException(
                    "The code reader must not run: the OTT must be rejected before the code stage."));
            var ex = await Assert.ThrowsAnyAsync<Exception>(() => protocol.ConnectAndAuthenticateAsync());
            return (errors.ToString(), ex);
        }
        finally
        {
            Console.SetError(originalError);
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch { /* best effort */ }
    }
}
