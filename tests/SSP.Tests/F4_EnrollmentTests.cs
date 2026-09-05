using SSP.Core.Crypto;
using SSP.Core.IO;
using SSP.Client.Runtime;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class F4_EnrollmentTests
{
    [Fact]
    public async Task Enrollment_HappyPath_PersistsClientAndClearsToken()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();

        await using var harness =
            await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        var (runtime, clientDir) =
            await harness.CreateClientRuntimeAsync(ott);

        Assert.False(runtime.IsEnrolled);

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
                        if (EnrollmentHelper.TryReadAuthenticationCode(
                                output.ToString(), out var extracted))
                            return extracted;

                        await Task.Delay(20);
                    }
                });

            var (tcp, sessionKey) =
                await protocol.ConnectAndAuthenticateAsync();

            Assert.True(tcp.Connected);
            Assert.Equal(32, sessionKey.Length);

            tcp.Dispose();

            var runtime2 =
                await ClientRuntime.LoadOrCreateAsync(
                    clientDir,
                    runtime.Config);

            Assert.True(runtime2.IsEnrolled);

            var authPath =
                Path.Combine(
                    harness.ServiceDir,
                    ".index.dat");

            var users =
                await AuthorisedUsersStore.LoadAsync(authPath);

            Assert.Single(users.Users);
            Assert.True(users.Users[0].IsAuthorized);

            Assert.Equal(
                runtime2.ClientPublicKeyFingerprint,
                users.Users[0].ClientPublicKeyFingerprint);

            var configPath =
                Path.Combine(
                    harness.ServiceDir,
                    ".cache.dat");

            var cfg =
                await ServiceConfigStore.LoadAsync(configPath);

            Assert.Null(cfg.ActiveOneTimeTokenHash);
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public async Task Enrollment_WrongOneTimeToken_RejectsAndPreservesHash()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();

        await using var harness =
            await SspTestHarness.CreateWithExplicitTokenAsync(
                ott,
                "WEB");

        var (runtime, _) =
            await harness.CreateClientRuntimeAsync("wrong-token");

        var protocol =
            new ClientProtocol(runtime);

        await Assert.ThrowsAnyAsync<Exception>(
            () => protocol.ConnectAndAuthenticateAsync());

        var configPath =
            Path.Combine(
                harness.ServiceDir,
                ".cache.dat");

        var cfg =
            await ServiceConfigStore.LoadAsync(configPath);

        Assert.NotNull(cfg.ActiveOneTimeTokenHash);
    }

    [Fact]
    public async Task Enrollment_SecondAttemptWithSameToken_Rejected()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();

        await using var harness =
            await SspTestHarness.CreateWithExplicitTokenAsync(
                ott,
                "SSH");

        await EnrollOnceAsync(harness, ott);

        var (runtime2, _) =
            await harness.CreateClientRuntimeAsync(ott);

        var protocol2 =
            new ClientProtocol(runtime2);

        await Assert.ThrowsAnyAsync<Exception>(
            () => protocol2.ConnectAndAuthenticateAsync());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task WrongAuthenticationCode_BeforeLimit_PersistsAttemptAndKeepsOttValid(int failures)
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        for (var attempt = 0; attempt < failures; attempt++)
        {
            await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
            if (attempt < failures - 1)
                await ClearAuthenticationCodeCooldownAsync(harness);
        }

        var config = await ServiceConfigStore.LoadAsync(Path.Combine(harness.ServiceDir, ".cache.dat"));
        var pending = Assert.Single(config.PendingOneTimeTokens);
        Assert.Equal(failures, pending.FailedAuthenticationCodeAttempts);
        Assert.NotNull(config.ActiveOneTimeTokenHash);
        Assert.False(string.IsNullOrEmpty(pending.AuthenticationCodeRetryNotBeforeUtc));
    }

    [Fact]
    public async Task ThirdWrongAuthenticationCode_RevokesOttAndEmitsSecurityEvents()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");
        var originalError = Console.Error;
        var errors = new StringWriter();
        Console.SetError(errors);

        try
        {
            for (var attempt = 0; attempt < 3; attempt++)
            {
                await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
                if (attempt < 2)
                    await ClearAuthenticationCodeCooldownAsync(harness);
            }
        }
        finally
        {
            Console.SetError(originalError);
        }

        var config = await ServiceConfigStore.LoadAsync(Path.Combine(harness.ServiceDir, ".cache.dat"));
        Assert.Empty(config.PendingOneTimeTokens);
        Assert.Null(config.ActiveOneTimeTokenHash);
        Assert.Contains("event=Enrollment.AuthenticationCodeFailed", errors.ToString());
        Assert.Contains("event=Enrollment.OTTRevokedAfterFailedAttempts failedAttempts=3", errors.ToString());
    }

    [Fact]
    public async Task CorrectAuthenticationCode_AfterTwoFailures_EnrollsSuccessfully()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        await ClearAuthenticationCodeCooldownAsync(harness);
        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        await ClearAuthenticationCodeCooldownAsync(harness);
        await EnrollOnceAsync(harness, ott);

        var users = await AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));
        Assert.Single(users.Users);
        var config = await ServiceConfigStore.LoadAsync(Path.Combine(harness.ServiceDir, ".cache.dat"));
        Assert.Empty(config.PendingOneTimeTokens);
        Assert.Null(config.ActiveOneTimeTokenHash);
    }

    [Fact]
    public async Task CorrectAuthenticationCode_AfterThreeFailures_CannotEnrollSamePackage()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        for (var attempt = 0; attempt < 3; attempt++)
        {
            await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
            if (attempt < 2)
                await ClearAuthenticationCodeCooldownAsync(harness);
        }

        await Assert.ThrowsAnyAsync<Exception>(() => EnrollOnceAsync(harness, ott));
        var users = await AuthorisedUsersStore.LoadAsync(Path.Combine(harness.ServiceDir, ".index.dat"));
        Assert.Empty(users.Users);
    }

    [Fact]
    public async Task AuthenticationCodeRetry_BeforeCooldown_IsRateLimitedWithoutIncrementingOrMintingACode()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        await ForceAuthenticationCodeCooldownAsync(harness, DateTimeOffset.UtcNow.AddHours(1));

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
                    "Authentication code reader must not run during cooldown."));
            var ex = await Assert.ThrowsAnyAsync<Exception>(
                () => protocol.ConnectAndAuthenticateAsync());
            Assert.Contains("verification failed", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }

        var config = await ServiceConfigStore.LoadAsync(Path.Combine(harness.ServiceDir, ".cache.dat"));
        var pending = Assert.Single(config.PendingOneTimeTokens);
        Assert.Equal(1, pending.FailedAuthenticationCodeAttempts);
        Assert.NotNull(config.ActiveOneTimeTokenHash);
        Assert.False(EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out _));
        Assert.Contains("event=Enrollment.AuthenticationCodeRateLimited failedAttempts=1", errors.ToString());
    }

    [Fact]
    public async Task AuthenticationCodeRetry_AfterCooldown_AllowsAnotherGuess()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);
        await ForceAuthenticationCodeCooldownAsync(harness, DateTimeOffset.UtcNow.AddSeconds(-1));
        await AttemptEnrollmentWithWrongCodeAsync(harness, ott);

        var config = await ServiceConfigStore.LoadAsync(Path.Combine(harness.ServiceDir, ".cache.dat"));
        var pending = Assert.Single(config.PendingOneTimeTokens);
        Assert.Equal(2, pending.FailedAuthenticationCodeAttempts);
        Assert.NotNull(config.ActiveOneTimeTokenHash);
        Assert.False(string.IsNullOrEmpty(pending.AuthenticationCodeRetryNotBeforeUtc));
    }

    [Fact]
    public void AuthenticationCodeReader_IgnoresFingerprintThatStartsWithTenDigits()
    {
        // SHA-256 hex can begin with ten decimal digits. The old
        // \s{4}(\d{10}) reader would submit that prefix and fail
        // enrollment with AuthenticationCode mismatch.
        var output =
            "=== CLIENT ENROLLMENT ===" + Environment.NewLine +
            Environment.NewLine +
            "Client connected:" + Environment.NewLine +
            "    1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" + Environment.NewLine +
            Environment.NewLine +
            "Authentication Code:" + Environment.NewLine +
            Environment.NewLine +
            "    5839201746" + Environment.NewLine;

        Assert.True(EnrollmentHelper.TryReadAuthenticationCode(output, out var code));
        Assert.Equal("5839201746", code);
        Assert.NotEqual("1234567890", code);
    }

    private static Task ClearAuthenticationCodeCooldownAsync(SspTestHarness harness) =>
        ForceAuthenticationCodeCooldownAsync(harness, retryNotBeforeUtc: null);

    private static Task ForceAuthenticationCodeCooldownAsync(
        SspTestHarness harness,
        DateTimeOffset retryNotBefore) =>
        ForceAuthenticationCodeCooldownAsync(harness, retryNotBefore.ToString("o"));

    private static async Task ForceAuthenticationCodeCooldownAsync(
        SspTestHarness harness,
        string? retryNotBeforeUtc)
    {
        var path = Path.Combine(harness.ServiceDir, ".cache.dat");
        using (await ServiceConfigFileLock.AcquireAsync(harness.ServiceDir))
        {
            var config = await ServiceConfigStore.LoadAsync(path);
            config.ActiveOneTimeTokenAuthenticationCodeRetryNotBeforeUtc = retryNotBeforeUtc;
            foreach (var pending in config.PendingOneTimeTokens)
                pending.AuthenticationCodeRetryNotBeforeUtc = retryNotBeforeUtc;
            await ServiceConfigStore.SaveAsync(path, config);
        }
    }

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
        var (runtime, _) =
            await harness.CreateClientRuntimeAsync(ott);

        var originalOut = Console.Out;
        var output = new StringWriter();

        Console.SetOut(output);

        try
        {
            var protocol =
                new ClientProtocol(
                    runtime,
                    async () =>
                    {
                        while (true)
                        {
                            if (EnrollmentHelper.TryReadAuthenticationCode(
                                    output.ToString(), out var extracted))
                                return extracted;

                            await Task.Delay(20);
                        }
                    });

            var (tcp, _) =
                await protocol.ConnectAndAuthenticateAsync();

            tcp.Dispose();
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }
}
