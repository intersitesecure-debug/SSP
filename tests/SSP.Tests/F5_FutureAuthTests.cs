// File: tests/SSP.Tests/F5_FutureAuthTests.cs
//
// F5 - Future Authorization Protocol functional tests.
//
// These tests rely on F4 to enroll a client first, then reconnect the
// same client. The second connection uses the future-authorization
// flow: ChallengeNonce + signature, fingerprint lookup, no One-Time
// Token required.

using SSP.Core.Crypto;
using SSP.Client.Runtime;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class F5_FutureAuthTests
{
    /// <summary>
    /// After a successful enrollment, the same client connects again
    /// using future authorization. The server must accept the
    /// ChallengeResponse and authorize the connection.
    /// </summary>
    [Fact]
    public async Task FutureAuthorization_AfterEnrollment_Succeeds()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");

        // Enroll first.
        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);

        // Reload keys so IsEnrolled is true.
        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);
        Assert.True(runtime2.IsEnrolled);

        // Connect again with future authorization.
        var protocol = new ClientProtocol(runtime2);
        var (tcp, sessionKey) = await protocol.ConnectAndAuthenticateAsync();
        Assert.True(tcp.Connected);
        Assert.Equal(32, sessionKey.Length);
        tcp.Dispose();
    }

    /// <summary>
    /// A client with an unknown fingerprint must be rejected.
    /// </summary>
    [Fact]
    public async Task FutureAuthorization_UnknownFingerprint_Rejects()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "WEB");

        // Enroll a real client.
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);

        // Build a *different* client with a fresh key pair.
        var (rogueRuntime, _) = await harness.CreateClientRuntimeAsync(ott);
        // Force IsEnrolled=true so it takes the future-auth path.
        var field = typeof(ClientRuntime).GetField("_isEnrolled",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        // We can't easily hack a private setter; instead we reload keys by saving
        // fake PEM files in a fresh dir.
        // Easiest: pre-populate the client dir with a *different* key pair.
        var rogueClientDir = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "ssp-rogue-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(rogueClientDir);
        using var rogueRsa = RsaCrypto.GenerateKeyPair();
        // Legacy-plaintext .cache.dat / .index.dat (pre-encryption
        // layout). ClientRuntime loads them via PemStore, which
        // decrypts/migrates them into the encrypted-at-rest envelope.
        await SSP.Core.IO.AtomicFile.WriteTextAsync(
            System.IO.Path.Combine(rogueClientDir, ".cache.dat"),
            RsaCrypto.ExportPrivateKeyPem(rogueRsa));
        await SSP.Core.IO.AtomicFile.WriteTextAsync(
            System.IO.Path.Combine(rogueClientDir, ".index.dat"),
            RsaCrypto.ExportPublicKeyPem(rogueRsa));
        var rogueCfg = runtime.Config;
        var rogueRuntime2 = await ClientRuntime.LoadOrCreateAsync(rogueClientDir, rogueCfg);
        Assert.True(rogueRuntime2.IsEnrolled);

        var protocol = new ClientProtocol(rogueRuntime2);
        await Assert.ThrowsAnyAsync<Exception>(() => protocol.ConnectAndAuthenticateAsync());
    }

    /// <summary>
    /// Future authorization must succeed N times in a row (each time
    /// with a fresh ChallengeNonce) - no replay protection should trip.
    /// </summary>
    [Fact]
    public async Task FutureAuthorization_RapidReconnect_SucceedsFiveTimes()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "SSH");

        var (runtime, clientDir) = await harness.CreateClientRuntimeAsync(ott);
        await EnrollmentHelper.EnrollAsync(runtime);

        var runtime2 = await ClientRuntime.LoadOrCreateAsync(clientDir, runtime.Config);
        for (var i = 0; i < 5; i++)
        {
            var protocol = new ClientProtocol(runtime2);
            var (tcp, _) = await protocol.ConnectAndAuthenticateAsync();
            Assert.True(tcp.Connected);
            tcp.Dispose();
        }
    }
}

/// <summary>
/// Helpers shared between F4 / F5 / F6 / F7 tests: complete a single
/// enrollment against a harness, capturing the AuthenticationCode that
/// the server prints and feeding it back via the console redirector.
/// </summary>
internal static class EnrollmentHelper
{
    /// <summary>
    /// Server console banner written by ServerProtocol. The 10-digit
    /// code is on its own indented line AFTER this heading. Binding
    /// extraction to the heading is required because the client
    /// fingerprint (lowercase SHA-256 hex) is printed first with the
    /// same 4-space indent and can begin with ten decimal digits.
    /// </summary>
    private const string AuthenticationCodeHeadingPattern =
        @"Authentication Code:\r?\n(?:[ \t]*\r?\n)*[ \t]{4}(\d{10})\b";

    /// <summary>
    /// Read the 10-digit Authentication Code from captured server
    /// console output. Returns false until the heading-bound code is
    /// present. Never returns a fingerprint prefix.
    /// </summary>
    public static bool TryReadAuthenticationCode(string consoleOutput, out string code)
    {
        code = string.Empty;
        if (string.IsNullOrEmpty(consoleOutput))
            return false;

        var match = System.Text.RegularExpressions.Regex.Match(
            consoleOutput,
            AuthenticationCodeHeadingPattern);
        if (!match.Success)
            return false;

        code = match.Groups[1].Value;
        return true;
    }

    public static async Task EnrollAsync(ClientRuntime runtime)
    {
        var originalOut = Console.Out;
        var outputWriter = new StringWriter();

        Console.SetOut(outputWriter);

        try
        {
            var protocol = new ClientProtocol(
                runtime,
                async () =>
                {
                    while (true)
                    {
                        if (TryReadAuthenticationCode(outputWriter.ToString(), out var extracted))
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
}
