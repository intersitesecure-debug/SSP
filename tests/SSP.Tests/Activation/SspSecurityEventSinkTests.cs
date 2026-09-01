// File: tests/SSP.Tests/Activation/SspSecurityEventSinkTests.cs
//
// Tests for the SSP security event sink: it persists structured events,
// never throws (even on a null event or a missing log directory), and never
// writes secret/signature material.

using SSP.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

public class SspSecurityEventSinkTests
{
    private static readonly Guid LicenseId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");

    [Fact]
    public void Report_WritesPersistentLogFile()
    {
        var dir = CreateTempDir();
        try
        {
            var sink = new SspSecurityEventSink(dir, writeToConsole: false);
            sink.Report(CreateEvent(LicenseSecurityEventType.LicenseValidated, LicenseState.Valid, LicenseReasons.Ok));

            var path = Path.Combine(dir, SspSecurityEventSink.LogFileName);
            Assert.True(File.Exists(path));

            var text = File.ReadAllText(path);
            Assert.Contains("LicenseValidated", text, StringComparison.Ordinal);
            Assert.Contains("licenseId=" + LicenseId.ToString("D"), text, StringComparison.Ordinal);
            Assert.Contains("state=Valid", text, StringComparison.Ordinal);
            Assert.Contains("reason=ok", text, StringComparison.Ordinal);

            // Events must never contain signature or key material.
            Assert.DoesNotContain("signature", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("BEGIN", text, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE", text, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Report_AppendsMultipleEvents()
    {
        var dir = CreateTempDir();
        try
        {
            var sink = new SspSecurityEventSink(dir, writeToConsole: false);
            sink.Report(CreateEvent(LicenseSecurityEventType.LicenseLoaded, LicenseState.Unknown, LicenseReasons.Ok));
            sink.Report(CreateEvent(LicenseSecurityEventType.LicenseValidated, LicenseState.Valid, LicenseReasons.Ok));

            var text = File.ReadAllText(Path.Combine(dir, SspSecurityEventSink.LogFileName));

            Assert.Contains("event=LicenseLoaded", text, StringComparison.Ordinal);
            Assert.Contains("event=LicenseValidated", text, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Report_NeverThrows_WithNoLogDirectoryAndNullEvent()
    {
        var sink = new SspSecurityEventSink(null, writeToConsole: false);

        // A null event and a missing log directory must both be harmless.
        sink.Report(null!);
        sink.Report(CreateEvent(LicenseSecurityEventType.ProtectedOperationDenied, LicenseState.Unknown, LicenseReasons.LicenseNotValid));
    }

    [Fact]
    public void BuildMessage_ContainsSafeStructuredFields()
    {
        var line = SspSecurityEventSink.BuildMessage(
            CreateEvent(LicenseSecurityEventType.LicenseValidationFailed, LicenseState.InvalidSignature, LicenseReasons.InvalidSignature));

        Assert.Contains("event=LicenseValidationFailed", line, StringComparison.Ordinal);
        Assert.Contains("state=InvalidSignature", line, StringComparison.Ordinal);
        Assert.Contains("reason=invalid_signature", line, StringComparison.Ordinal);
        Assert.Contains("licenseId=" + LicenseId.ToString("D"), line, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN", line, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", line, StringComparison.Ordinal);
    }

    private static LicenseSecurityEvent CreateEvent(
        LicenseSecurityEventType type,
        LicenseState state,
        string reason)
    {
        return new LicenseSecurityEvent
        {
            EventType = type,
            OccurredAtUtc = new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero),
            State = state,
            LicenseId = LicenseId,
            ReasonCode = reason,
            Detail = "sd=test detail with\nnewline"
        };
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-activation-events-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
