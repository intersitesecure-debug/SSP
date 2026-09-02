using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Persistence;

/// <summary>
/// Tests for the durable, file-backed <see cref="FileLicenseStateStore"/>. The store is not
/// a security boundary (it can only restrict), but it must persist the anti-rollback floor
/// across process restarts and must fail closed when its file is corrupt or unreadable.
/// </summary>
public class FileLicenseStateStoreTests
{
    [Fact]
    public void FreshPath_ReturnsNull()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var store = new FileLicenseStateStore(Path.Combine(dir, "state.json"));
            Assert.Null(store.Load());
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void SaveThenLoad_RoundTrips()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "state.json");
            var store = new FileLicenseStateStore(path);
            store.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = 42,
                LastAcceptedLicenseId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"),
                LastValidatedUtc = new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero)
            });

            var loaded = store.Load();

            Assert.NotNull(loaded);
            Assert.Equal(42, loaded!.HighestAcceptedSequenceNumber);
            Assert.Equal(Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"), loaded.LastAcceptedLicenseId);
            Assert.Equal(new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero), loaded.LastValidatedUtc);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void PersistsAcrossStoreInstances()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "state.json");

            new FileLicenseStateStore(path).Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 7 });

            // A fresh store instance (as after a process restart) reads the persisted floor.
            var rebuilt = new FileLicenseStateStore(path).Load();
            Assert.NotNull(rebuilt);
            Assert.Equal(7, rebuilt!.HighestAcceptedSequenceNumber);
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void CorruptFile_FailsClosed()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "state.json");
            File.WriteAllText(path, "{ not valid json ]");

            var store = new FileLicenseStateStore(path);
            Assert.Throws<InvalidDataException>(() => store.Load());
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void EmptyFile_FailsClosed()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "state.json");
            File.WriteAllText(path, "");

            var store = new FileLicenseStateStore(path);
            Assert.Throws<InvalidDataException>(() => store.Load());
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }

    [Fact]
    public void CreatesMissingParentDirectory()
    {
        var dir = TestPaths.CreateTempDirectory();
        try
        {
            var path = Path.Combine(dir, "nested", "deeper", "state.json");
            var store = new FileLicenseStateStore(path);
            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 1 });

            Assert.True(File.Exists(path));
        }
        finally
        {
            TestPaths.DeleteDirectory(dir);
        }
    }
}
