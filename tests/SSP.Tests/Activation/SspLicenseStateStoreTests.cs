// File: tests/SSP.Tests/Activation/SspLicenseStateStoreTests.cs
//
// Tests for the DPAPI-backed activation state store. The store must persist
// the anti-rollback floor across instances, fail closed on corrupt/unreadable
// files, and always store it in the SSP encrypted-at-rest envelope.

using System.Text;
using SSP.Activation;
using SSP.Core.IO;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

public class SspLicenseStateStoreTests
{
    [Fact]
    public void FreshPath_ReturnsNull()
    {
        var dir = CreateTempDir();
        try
        {
            var store = new SspLicenseStateStore(Path.Combine(dir, SspLicenseStateStore.DefaultFileName));
            Assert.Null(store.Load());
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void SaveThenLoad_RoundTrips()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(path);
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
            TryDelete(dir);
        }
    }

    [Fact]
    public void PersistsAcrossStoreInstances()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);

            new SspLicenseStateStore(path).Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 7 });

            // A fresh store instance (as after a process restart) reads the persisted floor.
            var rebuilt = new SspLicenseStateStore(path).Load();
            Assert.NotNull(rebuilt);
            Assert.Equal(7, rebuilt!.HighestAcceptedSequenceNumber);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void CorruptFile_FailsClosed()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            File.WriteAllText(path, "{ not valid json ]");

            var store = new SspLicenseStateStore(path);
            Assert.Throws<InvalidDataException>(() => store.Load());
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void EmptyFile_FailsClosed()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            File.WriteAllText(path, "");

            var store = new SspLicenseStateStore(path);
            Assert.Throws<InvalidDataException>(() => store.Load());
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void CreatesMissingParentDirectory()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, "nested", "deeper", SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(path);
            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 1 });

            Assert.True(File.Exists(path));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void StateFile_IsEncryptedAtRest()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(path);
            store.Save(new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = 7,
                LastAcceptedLicenseId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"),
            });

            var bytes = File.ReadAllBytes(path);
            Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes), "State file is not in the SSP encrypted-at-rest envelope.");

            // Plaintext markers must not be readable directly from the file.
            var directText = Encoding.UTF8.GetString(bytes);
            Assert.DoesNotContain("HighestAcceptedSequenceNumber", directText, StringComparison.Ordinal);
            Assert.DoesNotContain("01234567-89ab-cdef-0123-456789abcdef", directText, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void PlaintextStateFile_IsReadableAndMigratedToEnvelope()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var plaintext = "{\"highestAcceptedSequenceNumber\":9,\"lastValidatedUtc\":\"2030-01-01T12:00:00Z\"}";
            File.WriteAllText(path, plaintext);

            var store = new SspLicenseStateStore(path);
            var loaded = store.Load();

            Assert.NotNull(loaded);
            Assert.Equal(9, loaded!.HighestAcceptedSequenceNumber);

            // After a successful plaintext read the file is upgraded to the
            // encrypted envelope so the floor does not remain plaintext.
            var bytes = File.ReadAllBytes(path);
            Assert.True(ProtectedFileStore.HasEncryptedEnvelope(bytes));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void RejectsNullPathAndNullRecord()
    {
        var dir = CreateTempDir();
        try
        {
            Assert.Throws<ArgumentException>(() => new SspLicenseStateStore(""));
            Assert.Throws<ArgumentException>(() => new SspLicenseStateStore("   "));

            var store = new SspLicenseStateStore(Path.Combine(dir, SspLicenseStateStore.DefaultFileName));
            Assert.Throws<ArgumentNullException>(() => store.Save(null!));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ssp-activation-state-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void TryDelete(string dir)
    {
        try { Directory.Delete(dir, recursive: true); }
        catch { /* best effort */ }
    }
}
