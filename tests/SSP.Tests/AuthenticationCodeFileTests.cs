// File: tests/SSP.Tests/AuthenticationCodeFileTests.cs
//
// The Authentication Code is a local administrator readout. These tests
// cover the file writer and the enrollment path that overwrites it.

using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Server.Runtime;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class AuthenticationCodeFileTests
{
    [Fact]
    public void Write_CreatesDirectoryAndFile_WithExactTenDigitCode()
    {
        var dir = NewTempDir("create");
        var previous = Environment.GetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable);
        Environment.SetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable, dir);
        try
        {
            Assert.False(Directory.Exists(dir));

            var code = TokenGenerator.GenerateAuthenticationCode();
            AuthenticationCodeFile.Write(code);

            Assert.True(Directory.Exists(dir));
            var path = Path.Combine(dir, AuthenticationCodeFile.FileName);
            Assert.True(File.Exists(path));

            var body = File.ReadAllText(path);
            Assert.Equal(code + Environment.NewLine, body);
            Assert.Equal(code, body.Trim());
            Assert.Equal(10, code.Length);
            Assert.All(code, c => Assert.InRange(c, '0', '9'));
        }
        finally
        {
            Environment.SetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable, previous);
            TryDelete(dir);
        }
    }

    [Fact]
    public void Write_ReplacesPreviousCode()
    {
        var dir = NewTempDir("replace");
        var previous = Environment.GetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable);
        Environment.SetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable, dir);
        try
        {
            AuthenticationCodeFile.Write("1111111111");
            AuthenticationCodeFile.Write("2222222222");

            var body = File.ReadAllText(AuthenticationCodeFile.ResolvePath());
            Assert.Equal("2222222222" + Environment.NewLine, body);
            Assert.DoesNotContain("1111111111", body);
        }
        finally
        {
            Environment.SetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable, previous);
            TryDelete(dir);
        }
    }

    [Fact(Timeout = 30000)]
    public async Task Enrollment_WritesGeneratedCode_AndReplacesOnSubsequentAttempt()
    {
        var dir = NewTempDir("enroll");
        var previous = Environment.GetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable);
        Environment.SetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable, dir);

        var originalOut = Console.Out;
        var output = new StringWriter();
        Console.SetOut(output);

        try
        {
            var ott = TokenGenerator.GenerateOneTimeToken();
            await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");
            var path = Path.Combine(dir, AuthenticationCodeFile.FileName);

            // First enrollment request writes code A. Submit a wrong
            // value so the OTT stays valid for a second request.
            var firstCode = await RunEnrollmentAsync(harness, ott, output, submit: "0000000000", expectSuccess: false);
            Assert.True(File.Exists(path));
            Assert.Equal(firstCode + Environment.NewLine, File.ReadAllText(path));
            Assert.NotEqual("0000000000", firstCode);

            output.GetStringBuilder().Clear();

            // Second enrollment request must overwrite the file with a
            // freshly generated code, then succeed when that code is sent.
            var secondCode = await RunEnrollmentAsync(harness, ott, output, submit: null, expectSuccess: true);
            Assert.Equal(secondCode + Environment.NewLine, File.ReadAllText(path));
            Assert.NotEqual(firstCode, secondCode);
        }
        finally
        {
            Console.SetOut(originalOut);
            Environment.SetEnvironmentVariable(AuthenticationCodeFile.DirectoryOverrideVariable, previous);
            TryDelete(dir);
        }
    }

    /// <param name="submit">
    /// Code to send. Null means send the code the server just printed.
    /// </param>
    private static async Task<string> RunEnrollmentAsync(
        SspTestHarness harness,
        string ott,
        StringWriter output,
        string? submit,
        bool expectSuccess)
    {
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);
        string? printed = null;
        var protocol = new ClientProtocol(runtime, async () =>
        {
            while (printed == null)
            {
                if (EnrollmentHelper.TryReadAuthenticationCode(output.ToString(), out var extracted))
                    printed = extracted;
                else
                    await Task.Delay(20);
            }

            return submit ?? printed;
        });

        if (expectSuccess)
        {
            var (tcp, _) = await protocol.ConnectAndAuthenticateAsync();
            tcp.Dispose();
        }
        else
        {
            await Assert.ThrowsAnyAsync<Exception>(() => protocol.ConnectAndAuthenticateAsync());
        }

        Assert.False(string.IsNullOrEmpty(printed));
        return printed!;
    }

    private static string NewTempDir(string tag)
    {
        return Path.Combine(Path.GetTempPath(), $"ssp-authcode-{tag}-{Guid.NewGuid():N}");
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
    }
}
