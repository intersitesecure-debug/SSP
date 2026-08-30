// File: tests/SSP.Tests/WindowsServiceStandaloneHostTests.cs
//
// Regression tests for the standalone Windows Service host.
//
// The dependency being removed:
//   * Originally every service ImagePath pointed at the setup executable
//     (C:\Program Files\SSP\SSP.Server.exe), so that file was referenced
//     and locked by the SCM/running services after setup.
//
// Why the previous fix was wrong:
//   * The rejected approach COPIED SSP.Server.exe into each service
//     directory (services\RDP\SSP.Server.exe) and pointed ImagePath at the
//     copy. That only moved the location of the same executable: the
//     service still ran a copy of the setup image. The setup tool and the
//     service runtime must be different executables.
//
// The architecture these tests pin down:
//   * Each newly created service runs its OWN standalone host binary,
//     SSP.ServiceHost.exe (a separately compiled image from
//     src/SSP.ServiceHost), extracted by WindowsServiceInstaller from the
//     setup assembly's embedded build resources into the service directory.
//   * Extraction reads ONLY the embedded image (or the explicit
//     SSP_SERVICE_HOST_IMAGE seam in tests); the setup executable is never
//     read, copied or referenced. Moving/deleting it - even before
//     extraction has finished - cannot affect the service.
//   * The service directory never receives an SSP.Server.exe (or any
//     copy of the setup image): the only new file is the host itself.
//   * ImagePath keeps the established argument layout verbatim:
//     "<image>" "--service" "<serviceDir>" "<serviceName>".
//   * dotnet-host launches (developer/test layouts, the elevated SCM test)
//     are returned unchanged; existing services are never migrated.
//
// These tests are portable: they exercise the extraction/quoting logic
// directly and never touch the real SCM. The Windows-only end-to-end
// check remains in ServiceStartRegressionTests (elevated runners).

using SSP.Core.Util;
using SSP.Server.Setup;
using Xunit;

namespace SSP.Tests;

public class WindowsServiceStandaloneHostTests
{
    private const string SetupImageContent = "SETUP-IMAGE-BYTES-DO-NOT-COPY-ME";
    private const string HostImageContent = "SSP-SERVICE-HOST-IMAGE-PAYLOAD-STANDALONE";

    [Fact]
    public async Task ProductionLayout_ExtractsStandaloneHost_NotACopyOfTheSetupImage()
    {
        var root = CreateTempDir();
        using var seam = new ServiceHostImageSeam(WriteHostImage(root));
        try
        {
            // The resolved "setup executable" of a production layout. The
            // extraction contract is that nothing in WindowsServiceInstaller
            // ever opens this path.
            var setupDir = Path.Combine(root, "Program Files", "SSP");
            Directory.CreateDirectory(setupDir);
            var setupExe = Path.Combine(setupDir, "SSP.Server.exe");
            File.WriteAllText(setupExe, SetupImageContent);

            var serviceDir = Path.Combine(root, "services", "RDP");
            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                setupExe, Array.Empty<string>(), IsServerAppHost: true);

            var result = await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, serviceDir, CancellationToken.None);

            // The service's image is its own standalone host, inside the
            // service directory ...
            var hostPath = Path.Combine(serviceDir, "SSP.ServiceHost.exe");
            Assert.Equal(hostPath, result.FileName);
            Assert.True(File.Exists(hostPath));

            // ... whose bytes are the host image, NOT the setup image.
            var extracted = File.ReadAllText(hostPath);
            Assert.Equal(HostImageContent, extracted);
            Assert.NotEqual(SetupImageContent, extracted);

            // The setup executable is untouched (no copy step read or
            // rewrote it) and no copy of it exists anywhere near the
            // service.
            Assert.True(File.Exists(setupExe));
            Assert.Equal(SetupImageContent, File.ReadAllText(setupExe));
            Assert.False(File.Exists(Path.Combine(serviceDir, "SSP.Server.exe")));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public async Task ServiceDirectory_ReceivesOnlyTheHost_NoServerBinariesAreMaterialized()
    {
        var root = CreateTempDir();
        using var seam = new ServiceHostImageSeam(WriteHostImage(root));
        try
        {
            var serviceDir = Path.Combine(root, "services", "WEB");
            Directory.CreateDirectory(serviceDir);
            File.WriteAllText(Path.Combine(serviceDir, ".cache.dat"), "{}");

            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                Path.Combine(root, "SSP.Server.exe"), Array.Empty<string>(), IsServerAppHost: true);

            await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, serviceDir, CancellationToken.None);

            // Exactly one new file: the standalone host. The rejected
            // approach dragged SSP.Server.exe plus a full SSP.Server*.dll
            // companion set into every service directory.
            var names = Directory
                .GetFiles(serviceDir)
                .Select(file => Path.GetFileName(file))
                .ToArray();
            Assert.Equal(2, names.Length);
            Assert.Contains(".cache.dat", names, StringComparer.Ordinal);
            Assert.Contains("SSP.ServiceHost.exe", names, StringComparer.Ordinal);
        }
        finally
        {
            DeleteDir(root);
        }
    }

    /// <summary>
    /// The acceptance criterion: after the service has been created, the
    /// setup executable can be moved or deleted and the service's own
    /// image - the only file the ImagePath references - is unaffected and
    /// still present. The assertion is stronger than "delete afterwards":
    /// here the setup file is already gone BEFORE extraction completes, so
    /// it is provably not a dependency of the service image at all.
    /// </summary>
    [Fact]
    public async Task DeletingAndMovingSetupExecutable_LeavesServiceImageUsable()
    {
        var root = CreateTempDir();
        using var seam = new ServiceHostImageSeam(WriteHostImage(root));
        try
        {
            var setupDir = Path.Combine(root, "Program Files", "SSP");
            Directory.CreateDirectory(setupDir);
            var setupExe = Path.Combine(setupDir, "SSP.Server.exe");
            File.WriteAllText(setupExe, SetupImageContent);

            var serviceDir = Path.Combine(root, "services", "RDP");
            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                setupExe, Array.Empty<string>(), IsServerAppHost: true);

            // Simulate the operator moving the setup file away while the
            // service is being finalized: extraction must not care.
            var movedSetup = Path.Combine(root, "Users", "Operator", "Desktop", "SSP.Server.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(movedSetup)!);
            File.Move(setupExe, movedSetup);
            Assert.False(File.Exists(setupExe));

            var result = await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, serviceDir, CancellationToken.None);

            var hostPath = Path.Combine(serviceDir, "SSP.ServiceHost.exe");
            Assert.Equal(hostPath, result.FileName);
            Assert.True(File.Exists(hostPath));
            Assert.Equal(HostImageContent, File.ReadAllText(hostPath));

            // The ImagePath file the SCM will start exists with the whole
            // setup directory tree gone; starting the service depends on
            // nothing under the former setup location.
            Directory.Delete(setupDir, recursive: true);
            var imagePath = WindowsServiceInstaller.BuildWindowsCommandLine(
                result.FileName,
                ["--service", serviceDir, "SSP RDP 4433"]);
            Assert.True(File.Exists(Path.GetFullPath(hostPath)));
            Assert.Contains("SSP.ServiceHost.exe", imagePath, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDir(root);
        }
    }

    /// <summary>
    /// The success criterion, frozen verbatim: after creating an RDP
    /// service, sc.exe qc "SSP RDP 4433" must report a BINARY_PATH_NAME
    /// that is the service's OWN standalone host in services\RDP - quoted
    /// exactly like this, in the unchanged token order (image, --service,
    /// service directory, service name). It must contain no reference to
    /// SSP.Server.exe: neither the setup file nor a copy of it.
    /// </summary>
    [Fact]
    public void ImagePathCommandLine_PointsAtTheStandaloneHost_AndNeverAtSspServerExe()
    {
        var imagePath = WindowsServiceInstaller.BuildWindowsCommandLine(
            @"C:\Program Files\SSP\services\RDP\SSP.ServiceHost.exe",
            new[] { "--service", @"C:\Program Files\SSP\services\RDP", "SSP RDP 4433" });

        Assert.Equal(
            "\"C:\\Program Files\\SSP\\services\\RDP\\SSP.ServiceHost.exe\"" +
            " \"--service\"" +
            " \"C:\\Program Files\\SSP\\services\\RDP\"" +
            " \"SSP RDP 4433\"",
            imagePath);

        // No dependency on the setup executable, and no per-service copy
        // of it either: the string SSP.Server.exe may not appear at all.
        Assert.DoesNotContain("SSP.Server.exe", imagePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExtractedImagePath_ReferencesNoSspServerExe_InSetupFolderOrServiceFolder()
    {
        var root = CreateTempDir();
        using var seam = new ServiceHostImageSeam(WriteHostImage(root));
        try
        {
            var setupDir = Path.Combine(root, "Program Files", "SSP");
            Directory.CreateDirectory(setupDir);
            var setupExe = Path.Combine(setupDir, "SSP.Server.exe");
            File.WriteAllText(setupExe, SetupImageContent);

            var serviceDir = Path.Combine(root, "services", "RDP");
            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                setupExe, Array.Empty<string>(), IsServerAppHost: true);

            var result = await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, serviceDir, CancellationToken.None);
            var imagePath = WindowsServiceInstaller.BuildWindowsCommandLine(
                result.FileName,
                ["--service", serviceDir, "SSP RDP 4433"]);

            Assert.DoesNotContain("SSP.Server.exe", imagePath, StringComparison.OrdinalIgnoreCase);

            // The service directory never receives a file named
            // SSP.Server.exe - there is no per-service copy at all, only
            // the host. (The setup folder still legitimately holds the
            // setup executable itself: that file is what the operator may
            // move/delete afterwards.)
            Assert.DoesNotContain(
                Directory.GetFiles(serviceDir),
                file => string.Equals(
                    Path.GetFileName(file), "SSP.Server.exe", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public async Task DotnetHostLaunch_IsReturnedUnchanged()
    {
        var root = CreateTempDir();
        try
        {
            var serviceDir = Path.Combine(root, "services", "RDP");
            Directory.CreateDirectory(serviceDir);

            // The framework-dependent fallback used by developer/test hosts
            // launches through dotnet with the original assembly path; that
            // is not a setup-image dependency and is preserved as-is.
            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                "dotnet.exe",
                new[] { "exec", @"C:\build\SSP.Server.dll" },
                IsServerAppHost: false);

            var result = await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, serviceDir, CancellationToken.None);

            Assert.Same(launch, result);
            Assert.Equal("dotnet.exe", result.FileName);

            // Nothing is materialized inside the service directory: there
            // is no standalone setup image to extract in this layout.
            Assert.Empty(Directory.GetFileSystemEntries(serviceDir));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public async Task MissingHostImage_IsAHardFailure_NeverFallsBackToTheSetupExecutable()
    {
        var root = CreateTempDir();
        try
        {
            var serviceDir = Path.Combine(root, "services", "RDP");
            Directory.CreateDirectory(serviceDir);
            var setupExe = Path.Combine(root, "SSP.Server.exe");
            File.WriteAllText(setupExe, SetupImageContent);

            // Seam points at a file that does not exist: the installer must
            // fail visibly instead of quietly pointing ImagePath back at
            // the setup executable.
            Environment.SetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable,
                Path.Combine(root, "does-not-exist.exe"));

            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                setupExe, Array.Empty<string>(), IsServerAppHost: true);

            var ex = await Assert.ThrowsAsync<FileNotFoundException>(() =>
                WindowsServiceInstaller.PrepareServiceHostImageAsync(launch, serviceDir, CancellationToken.None));
            Assert.Contains("does-not-exist.exe", ex.Message, StringComparison.Ordinal);
            Assert.Empty(Directory.GetFileSystemEntries(serviceDir));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable, null);
            DeleteDir(root);
        }
    }

    [Fact]
    public async Task EmptyHostImage_IsRejected()
    {
        var root = CreateTempDir();
        try
        {
            var emptyImage = Path.Combine(root, "empty-host.bin");
            File.WriteAllBytes(emptyImage, Array.Empty<byte>());
            Environment.SetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable, emptyImage);

            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                Path.Combine(root, "SSP.Server.exe"), Array.Empty<string>(), IsServerAppHost: true);

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                WindowsServiceInstaller.PrepareServiceHostImageAsync(
                    launch, Path.Combine(root, "services", "RDP"), CancellationToken.None));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable, null);
            DeleteDir(root);
        }
    }

    /// <summary>
    /// Without the test seam, production reads the embedded resource. In a
    /// test build (SSP_SKIP_EMBED=true) no host image is embedded, and the
    /// failure must name the rebuild requirement instead of falling back to
    /// the setup executable. When the resource IS embedded (full publish),
    /// the extracted file must carry exactly its bytes.
    /// </summary>
    [Fact]
    public async Task EmbeddedResource_IsTheProductionImageSource()
    {
        var root = CreateTempDir();
        try
        {
            Environment.SetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable, null);

            var embedded = ReadEmbeddedHostImage();
            var serviceDir = Path.Combine(root, "services", "RDP");
            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                Path.Combine(root, "SSP.Server.exe"), Array.Empty<string>(), IsServerAppHost: true);

            if (embedded is null)
            {
                var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    WindowsServiceInstaller.PrepareServiceHostImageAsync(
                        launch, serviceDir, CancellationToken.None));
                Assert.Contains(EmbeddedResourceNames.ServiceHostImage, ex.Message, StringComparison.Ordinal);
                Assert.Contains("Rebuild", ex.Message, StringComparison.Ordinal);
                Assert.False(Directory.Exists(serviceDir));
            }
            else
            {
                var result = await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                    launch, serviceDir, CancellationToken.None);
                Assert.Equal(
                    File.ReadAllBytes(Path.Combine(serviceDir, "SSP.ServiceHost.exe")),
                    embedded);
            }
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public async Task EachServiceDirectory_GetsItsOwnIndependentHostImage()
    {
        var root = CreateTempDir();
        using var seam = new ServiceHostImageSeam(WriteHostImage(root));
        try
        {
            var setupExe = Path.Combine(root, "SSP.Server.exe");
            File.WriteAllText(setupExe, SetupImageContent);

            var rdpDir = Path.Combine(root, "services", "RDP");
            var webDir = Path.Combine(root, "services", "WEB");

            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                setupExe, Array.Empty<string>(), IsServerAppHost: true);

            var rdpResult = await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, rdpDir, CancellationToken.None);
            var webResult = await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, webDir, CancellationToken.None);

            var rdpHost = Path.Combine(rdpDir, "SSP.ServiceHost.exe");
            var webHost = Path.Combine(webDir, "SSP.ServiceHost.exe");
            Assert.Equal(rdpHost, rdpResult.FileName);
            Assert.Equal(webHost, webResult.FileName);

            // Two distinct physical files: one service's image can be
            // replaced or removed without touching the other's.
            File.WriteAllText(rdpHost, "rewritten");
            Assert.Equal("rewritten", File.ReadAllText(rdpHost));
            Assert.Equal(HostImageContent, File.ReadAllText(webHost));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public async Task StaleHostImage_IsOverwrittenOnReinstall()
    {
        var root = CreateTempDir();
        using var seam = new ServiceHostImageSeam(WriteHostImage(root));
        try
        {
            var serviceDir = Path.Combine(root, "services", "RDP");
            Directory.CreateDirectory(serviceDir);
            File.WriteAllText(Path.Combine(serviceDir, "SSP.ServiceHost.exe"), "stale host");

            var launch = new WindowsServiceInstaller.ServerLaunchCommand(
                Path.Combine(root, "SSP.Server.exe"), Array.Empty<string>(), IsServerAppHost: true);

            await WindowsServiceInstaller.PrepareServiceHostImageAsync(
                launch, serviceDir, CancellationToken.None);

            Assert.Equal(
                HostImageContent,
                File.ReadAllText(Path.Combine(serviceDir, "SSP.ServiceHost.exe")));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public void ResolveServerLaunchCommand_FromTestHost_UsesDotnetHostNotSetupApphost()
    {
        // This test process is testhost. Even if a stray SSP.Server.exe sits
        // next to SSP.Server.dll in the output directory, the layout must
        // not be recognized as the production setup image, so no extraction
        // happens and ImagePath stays on the framework-dependent
        // `dotnet exec` path that lets the elevated SCM test start a real
        // service.
        var launch = WindowsServiceInstaller.ResolveServerLaunchCommand();

        Assert.False(launch.IsServerAppHost);
        Assert.Contains("dotnet", Path.GetFileName(launch.FileName), StringComparison.OrdinalIgnoreCase);
        Assert.Contains(launch.Arguments, argument =>
            argument.EndsWith("SSP.Server.dll", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void IncompleteReferencedApphost_IsNotAProductionImage()
    {
        var root = CreateTempDir();
        try
        {
            // Testhost / ServiceBuilder output: the referenced project's
            // apphost is copied, but not its runtimeconfig. Accepting it as
            // a production layout is how the elevated SCM test used to fail
            // with ERROR 1053.
            File.WriteAllText(Path.Combine(root, "SSP.Server.exe"), "apphost stub");
            File.WriteAllText(Path.Combine(root, "SSP.Server.dll"), "managed assembly");

            Assert.False(WindowsServiceInstaller.IsProductionServerImage(
                Path.Combine(root, "SSP.Server.exe")));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public void SingleFileApphost_IsAProductionImage()
    {
        var root = CreateTempDir();
        try
        {
            var exe = Path.Combine(root, "SSP.Server.exe");
            File.WriteAllText(exe, "single-file image");

            Assert.True(WindowsServiceInstaller.IsProductionServerImage(exe));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    [Fact]
    public void FrameworkDependentPublish_IsAProductionImage()
    {
        var root = CreateTempDir();
        try
        {
            File.WriteAllText(Path.Combine(root, "SSP.Server.exe"), "apphost");
            File.WriteAllText(Path.Combine(root, "SSP.Server.dll"), "managed");
            File.WriteAllText(Path.Combine(root, "SSP.Server.runtimeconfig.json"), "{}");

            Assert.True(WindowsServiceInstaller.IsProductionServerImage(
                Path.Combine(root, "SSP.Server.exe")));
        }
        finally
        {
            DeleteDir(root);
        }
    }

    /// <summary>
    /// The standalone host serves services and nothing else: SSP.ServiceHost
    /// must never turn into a second setup tool, so every mode other than
    /// the service modes is refused with a usage error. (The service modes
    /// themselves delegate verbatim into SSP.Server.Program.Main and are
    /// covered by the existing service-lifecycle suites.)
    /// </summary>
    [Fact]
    public async Task ServiceHost_RejectsEveryNonServiceMode()
    {
        Assert.Equal(2, await SSP.ServiceHost.Program.RunAsync(Array.Empty<string>()));
        Assert.Equal(2, await SSP.ServiceHost.Program.RunAsync(new[] { "--setup" }));
        Assert.Equal(2, await SSP.ServiceHost.Program.RunAsync(new[] { "--setup-batch", "params.json" }));
    }

    private static string WriteHostImage(string root)
    {
        var hostImage = Path.Combine(root, "SSP.ServiceHost.image");
        File.WriteAllText(hostImage, HostImageContent);
        return hostImage;
    }

    private static byte[]? ReadEmbeddedHostImage()
    {
        using var stream = typeof(SetupEngine).Assembly
            .GetManifestResourceStream(EmbeddedResourceNames.ServiceHostImage);
        if (stream is null)
            return null;

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>
    /// Process-wide seam for the host image path. Test parallelization is
    /// disabled assembly-wide, so a set/clear scope around each test is
    /// safe.
    /// </summary>
    private sealed class ServiceHostImageSeam : IDisposable
    {
        private readonly string? _previous;

        public ServiceHostImageSeam(string hostImagePath)
        {
            _previous = Environment.GetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable);
            Environment.SetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable, hostImagePath);
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable(
                WindowsServiceInstaller.ServiceHostImageOverrideVariable, _previous);
        }
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-service-host-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void DeleteDir(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort; temp files only */ }
    }
}
