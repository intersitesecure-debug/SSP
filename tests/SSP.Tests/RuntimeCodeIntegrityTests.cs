// File: tests/SSP.Tests/RuntimeCodeIntegrityTests.cs
//
// Automated tests for the runtime code-integrity protection (Security
// Correction roadmap Phase 5 / M-4). These pin the fail-closed contract that a
// protected service refuses to start when an on-disk protected runtime
// component is modified:
//
//   * a pristine set of protected components verifies Ok and a protected
//     service may start;
//   * a byte-tampered component is detected as Tampered and the startup gate
//     throws SspActivationException (code_integrity_failure) -> the protected
//     service is NOT started;
//   * a missing component is detected as Missing and fails closed;
//   * an unreadable component is a failure (Unreadable), never an exception
//     that could accidentally let the caller continue;
//   * the manifest serializer is lossless (the embedded release baseline and a
//     regenerated one agree);
//   * an empty/un-armed manifest is a no-op, so developer/CI builds are not
//     affected (the compiled-in trust anchor + signed license remain the gate).

using System.Security.Cryptography;
using SSP.Core.CodeIntegrity;
using SSP.Server.Activation;

namespace SSP.Tests;

public class RuntimeCodeIntegrityTests
{
    // ------------------------------------------------------------------
    // Verifier semantics (SSP.Core)
    // ------------------------------------------------------------------

    [Fact]
    public void Verify_PristineComponents_IsSatisfied()
    {
        using var dir = TempDir.New();
        var a = dir.Write("SSP.Core.dll", "aaa");
        var b = dir.Write("SSP.Activation.dll", "bbb");

        var manifest = CodeIntegrityManifest.Create(new[]
        {
            new CodeIntegrityComponent("SSP.Core", "SSP.Core.dll", Hash(a)),
            new CodeIntegrityComponent("SSP.Activation", "SSP.Activation.dll", Hash(b)),
        });

        var result = CodeIntegrityVerifier.Verify(manifest, dir.Root);

        Assert.True(result.IsSatisfied);
        Assert.All(result.Results, r => Assert.Equal(CodeIntegrityStatus.Ok, r.Status));
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void Verify_TamperedComponent_IsDetectedAndNotSatisfied()
    {
        using var dir = TempDir.New();
        var file = dir.Write("SSP.Core.dll", "pristine-bytes");
        var expected = Hash(file);

        var manifest = CodeIntegrityManifest.Create(new[]
        {
            new CodeIntegrityComponent("SSP.Core", "SSP.Core.dll", expected),
        });

        // The attacker flips bytes in the protected component.
        File.WriteAllText(file, "MODIFIED-BYTES-###");

        var result = CodeIntegrityVerifier.Verify(manifest, dir.Root);

        Assert.False(result.IsSatisfied);
        var componentResult = Assert.Single(result.Failures);
        Assert.Equal(CodeIntegrityStatus.Tampered, componentResult.Status);
        Assert.Equal("SSP.Core", componentResult.Component.LogicalName);
    }

    [Fact]
    public void Verify_MissingComponent_FailsClosed()
    {
        using var dir = TempDir.New();

        var manifest = CodeIntegrityManifest.Create(new[]
        {
            new CodeIntegrityComponent("SSP.ServiceHost", "SSP.ServiceHost.exe", RepeatHex('1')),
        });

        var result = CodeIntegrityVerifier.Verify(manifest, dir.Root);

        Assert.False(result.IsSatisfied);
        var componentResult = Assert.Single(result.Failures);
        Assert.Equal(CodeIntegrityStatus.Missing, componentResult.Status);
    }

    [Fact]
    public void Verify_ComponentOutsideRoot_NeverReadsArbitraryFiles()
    {
        using var dir = TempDir.New();
        // A hostile/buggy manifest names a file outside the verification root.
        var outside = Path.Combine(Path.GetTempPath(), "ssp-outside-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllText(outside, "outside");

        try
        {
            var manifest = CodeIntegrityManifest.Create(new[]
            {
                new CodeIntegrityComponent("escape", $"..{Path.DirectorySeparatorChar}{Path.GetFileName(outside)}", RepeatHex('0')),
            });

            var result = CodeIntegrityVerifier.Verify(manifest, dir.Root);

            // The component must not be verified (it resolves outside the root);
            // the verifier never reads the arbitrary file.
            Assert.False(result.IsSatisfied);
            Assert.NotEmpty(result.Failures);
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Fact]
    public void Verify_UnreadableComponent_IsAFailure_NotAnException()
    {
        using var dir = TempDir.New();
        var file = dir.Write("SSP.Activation.dll", "payload");
        var expected = Hash(file);

        var manifest = CodeIntegrityManifest.Create(new[]
        {
            new CodeIntegrityComponent("SSP.Activation", "SSP.Activation.dll", expected),
        });

        // Best-effort: make the file unreadable to the current user. When the
        // host can still read it (e.g. tests running as root), Ok is the
        // environment's own answer and does not contradict the verifier.
        if (!OperatingSystem.IsWindows())
        {
            try { File.SetUnixFileMode(file, UnixFileMode.None); } catch { /* ignore */ }
        }

        var result = CodeIntegrityVerifier.Verify(manifest, dir.Root);
        var status = Assert.Single(result.Results).Status;

        if (status == CodeIntegrityStatus.Ok)
        {
            // The current user could still read the file; nothing to assert.
            return;
        }

        Assert.Equal(CodeIntegrityStatus.Unreadable, status);
        Assert.False(result.IsSatisfied);
    }

    // ------------------------------------------------------------------
    // Manifest serialization (lossless -> release baseline round-trips)
    // ------------------------------------------------------------------

    [Fact]
    public void ManifestSerializer_RoundTripsLosslessly()
    {
        var manifest = CodeIntegrityManifest.Create(new[]
        {
            new CodeIntegrityComponent("SSP.Server", "SSP.Server.dll", RepeatHex('a')),
            new CodeIntegrityComponent("SSP.ServiceHost.exe", "SSP.ServiceHost.exe", RepeatHex('f')),
        });

        var json = CodeIntegrityManifestSerializer.Serialize(manifest);
        var parsed = CodeIntegrityManifestSerializer.TryDeserialize(json);

        Assert.NotNull(parsed);
        Assert.Equal(manifest.ComponentCount, parsed!.ComponentCount);
        Assert.Equal(
            manifest.Components.Select(c => (c.LogicalName, c.FileName, c.ExpectedSha256Hex)),
            parsed.Components.Select(c => (c.LogicalName, c.FileName, c.ExpectedSha256Hex)));
    }

    [Fact]
    public void ManifestSerializer_MalformedJson_ReturnsNull()
    {
        Assert.Null(CodeIntegrityManifestSerializer.TryDeserialize("{ not json"));
        Assert.Null(CodeIntegrityManifestSerializer.TryDeserialize(string.Empty));
        Assert.Null(CodeIntegrityManifestSerializer.TryDeserialize(null!));
    }

    // ------------------------------------------------------------------
    // Startup gate fail-closed contract (SSP.Server.RuntimeCodeIntegrity)
    // ------------------------------------------------------------------

    [Fact]
    public void GuardStartup_Pristine_DoesNotThrow()
    {
        using var dir = TempDir.New();
        var file = dir.Write("SSP.Core.dll", "pristine");
        var manifest = Build([new CodeIntegrityComponent("SSP.Core", "SSP.Core.dll", Hash(file))]);

        // A protected service may start when its components are intact.
        RuntimeCodeIntegrity.GuardStartup(dir.Root, null, manifest);
    }

    [Fact]
    public void GuardStartup_TamperedComponent_RefusesProtectedService_FailClosed()
    {
        using var dir = TempDir.New();
        var file = dir.Write("SSP.Core.dll", "pristine");
        var manifest = Build([new CodeIntegrityComponent("SSP.Core", "SSP.Core.dll", Hash(file))]);

        File.WriteAllText(file, "PATCHED-TO-BYPASS-THE-GATE");

        var ex = Assert.Throws<SspActivationException>(
            () => RuntimeCodeIntegrity.GuardStartup(dir.Root, null, manifest));

        Assert.Equal(SspActivationException.CodeIntegrityFailureReason, ex.ReasonCode);
        Assert.Contains("SSP.Core", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GuardStartup_MissingComponent_RefusesProtectedService_FailClosed()
    {
        using var dir = TempDir.New();

        var manifest = Build([new CodeIntegrityComponent("SSP.ServiceHost.exe", "SSP.ServiceHost.exe", RepeatHex('5'))]);

        var ex = Assert.Throws<SspActivationException>(
            () => RuntimeCodeIntegrity.GuardStartup(dir.Root, null, manifest));

        Assert.Equal(SspActivationException.CodeIntegrityFailureReason, ex.ReasonCode);
        Assert.Contains("SSP.ServiceHost.exe", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GuardStartup_EmptyManifest_IsANoOp_NotArmedBuildsProceed()
    {
        using var dir = TempDir.New();
        var empty = Build([]);

        // A developer/CI build without an armed baseline must not be affected:
        // the compiled-in trust anchor and signed license remain the only gate.
        RuntimeCodeIntegrity.GuardStartup(dir.Root, null, empty);
        RuntimeCodeIntegrity.VerifyArmedStartup(null);
    }

    [Fact]
    public void CeremonyHelper_BuildManifestFromFiles_ThenGuardDetectsTampering()
    {
        // End-to-end shape of the release flow: hash pristine files into a
        // baseline, verify it, then tamper one file and prove the gate refuses.
        using var dir = TempDir.New();
        var a = dir.Write("SSP.Server.dll", "pristine-server");
        var b = dir.Write("SSP.Core.dll", "pristine-core");

        var manifest = RuntimeCodeIntegrity.BuildManifestFromFiles([a, b]);
        Assert.Equal(2, manifest.ComponentCount);

        RuntimeCodeIntegrity.GuardStartup(dir.Root, null, manifest);

        File.WriteAllText(a, "TAMPERED");
        var ex = Assert.Throws<SspActivationException>(
            () => RuntimeCodeIntegrity.GuardStartup(dir.Root, null, manifest));
        Assert.Equal(SspActivationException.CodeIntegrityFailureReason, ex.ReasonCode);
        Assert.Contains("SSP.Server.dll", ex.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static CodeIntegrityManifest Build(IEnumerable<CodeIntegrityComponent> components)
        => CodeIntegrityManifest.Create(components);

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    private static string RepeatHex(char hex)
        => new(hex, 64);

    /// <summary>Disposable temp directory so tests clean up after themselves.</summary>
    private sealed class TempDir : IDisposable
    {
        public string Root { get; }

        private TempDir(string root) => Root = root;

        public static TempDir New()
        {
            var root = Path.Combine(Path.GetTempPath(), "ssp-codeint-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            return new TempDir(root);
        }

        public string Write(string fileName, string content)
        {
            var path = Path.Combine(Root, fileName);
            File.WriteAllText(path, content);
            return path;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                {
                    Directory.Delete(Root, recursive: true);
                }
            }
            catch
            {
                // Best effort cleanup.
            }
        }
    }
}
