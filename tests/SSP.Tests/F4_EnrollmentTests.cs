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