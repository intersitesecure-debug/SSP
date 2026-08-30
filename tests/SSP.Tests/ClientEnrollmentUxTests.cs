// File: tests/SSP.Tests/ClientEnrollmentUxTests.cs
//
// Empty Authentication Code must fail cleanly: short message, no
// InvalidOperationException, no stack trace on the console.

using System.Text;
using SSP.Client.Runtime;
using SSP.Core.Crypto;
using SSP.Tests.Helpers;
using Xunit;

namespace SSP.Tests;

public class ClientEnrollmentUxTests
{
    [Fact(Timeout = 30000)]
    public async Task EmptyAuthenticationCode_PrintsCleanError_WithoutStackTrace()
    {
        var ott = TokenGenerator.GenerateOneTimeToken();
        await using var harness = await SspTestHarness.CreateWithExplicitTokenAsync(ott, "RDP");
        var (runtime, _) = await harness.CreateClientRuntimeAsync(ott);

        var originalOut = Console.Out;
        var originalErr = Console.Error;
        var output = new StringWriter();
        var error = new StringWriter();
        Console.SetOut(output);
        Console.SetError(error);

        try
        {
            var protocol = new ClientProtocol(runtime, () => Task.FromResult(string.Empty));
            var ex = await Assert.ThrowsAsync<EnrollmentFailedException>(
                () => protocol.ConnectAndAuthenticateAsync());

            Assert.Equal("No Authentication Code entered.", ex.Message);
            Assert.DoesNotContain("InvalidOperationException", ex.ToString());

            var combined = output.ToString() + error.ToString();
            Assert.Contains("Enter Authentication Code:", combined);
            Assert.Contains("No Authentication Code entered.", combined);
            Assert.Contains("Enrollment failed.", combined);
            Assert.DoesNotContain("InvalidOperationException", combined);
            Assert.DoesNotContain("[SSP.Client] Fatal:", combined);
            Assert.DoesNotContain("at SSP.Client.Runtime.ClientProtocol", combined);
            Assert.DoesNotContain("   at ", combined);
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalErr);
        }
    }

    [Fact]
    public void EnrollmentFailedException_IsNotAStackDump()
    {
        var ex = new EnrollmentFailedException("No Authentication Code entered.");
        var displayed = new StringBuilder();
        displayed.AppendLine(ex.Message);
        displayed.AppendLine("Enrollment failed.");

        var text = displayed.ToString();
        Assert.Equal(
            "No Authentication Code entered." + Environment.NewLine +
            "Enrollment failed." + Environment.NewLine,
            text);
        Assert.DoesNotContain("at ", text);
        Assert.DoesNotContain("InvalidOperationException", text);
    }
}
