// File: tests/SSP.Tests/Activation/SspLicenseStateStoreTests.cs
//
// Tests for the DPAPI-backed activation state store. The store must persist
// the anti-rollback floor across instances, fail closed on corrupt/unreadable
// files, and always store it in the SSP encrypted-at-rest envelope.

using System.Text;
using System.Text.Json;
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

    // ────────────────────────────────────────────────────────────────
    // Phase 4 (M-3) — installation binding + monotonic state epoch
    // ────────────────────────────────────────────────────────────────

    [Fact]
    public void Save_StampsInstallationBindingAndMonotonicEpoch()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);
            var store = new SspLicenseStateStore(path, installationStateBindingId: "installation-a");

            store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 3 });
            var first = store.Load();

            Assert.NotNull(first);
            Assert.Equal("installation-a", first!.InstallationId);
            Assert.Equal(1, first.StateEpoch);

            // A second save (the manager's read-modify-write pattern) must
            // advance the epoch, never keep or lower it.
            store.Save(first! with { HighestAcceptedSequenceNumber = 5 });
            var second = store.Load();

            Assert.NotNull(second);
            Assert.Equal("installation-a", second!.InstallationId);
            Assert.Equal(2, second.StateEpoch);
            Assert.Equal(5, second.HighestAcceptedSequenceNumber);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Load_FailsClosed_WhenRecordBoundToAnotherInstallation()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);

            // State written by installation A...
            new SspLicenseStateStore(path, installationStateBindingId: "installation-a")
                .Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 9 });

            // ...replayed into installation B must fail closed: accepting it
            // would silently replace B's floor with a replayed one.
            var foreign = new SspLicenseStateStore(path, installationStateBindingId: "installation-b");
            var ex = Assert.Throws<InvalidDataException>(() => foreign.Load());
            Assert.Contains("different installation", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void Load_WithoutConfiguredBinding_AcceptsAnyRecord()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);

            new SspLicenseStateStore(path, installationStateBindingId: "installation-a")
                .Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 9 });

            // Unbound stores (non-Windows hosts, identity unavailable) keep
            // the pre-Phase-4 behaviour: the record loads.
            var unbound = new SspLicenseStateStore(path);
            var loaded = unbound.Load();
            Assert.NotNull(loaded);
            Assert.Equal(9, loaded!.HighestAcceptedSequenceNumber);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    [Fact]
    public void LegacyRecord_WithoutBinding_IsAdoptedAndUpgradedOnSave()
    {
        var dir = CreateTempDir();
        try
        {
            var path = Path.Combine(dir, SspLicenseStateStore.DefaultFileName);

            // A pre-Phase-4 record: no binding, no epoch.
            var legacy = new LicenseStateRecord
            {
                HighestAcceptedSequenceNumber = 4,
                LastAcceptedLicenseId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"),
            };
            var json = JsonSerializer.Serialize(legacy, new JsonSerializerOptions { WriteIndented = true });
            ProtectedFileStore.WriteTextAsync(path, json).GetAwaiter().GetResult();

            // It loads (adoption, never rejection - existing installations
            // must not brick)...
            var store = new SspLicenseStateStore(path, installationStateBindingId: "installation-a");
            var loaded = store.Load();
            Assert.NotNull(loaded);
            Assert.Equal(4, loaded!.HighestAcceptedSequenceNumber);
            Assert.Null(loaded.InstallationId);
            Assert.Equal(0, loaded.StateEpoch);

            // ...and the next save upgrades it in place with binding + epoch.
            store.Save(loaded! with { HighestAcceptedSequenceNumber = 6 });
            var upgraded = store.Load();

            Assert.NotNull(upgraded);
            Assert.Equal("installation-a", upgraded!.InstallationId);
            Assert.Equal(1, upgraded.StateEpoch);
            Assert.Equal(6, upgraded.HighestAcceptedSequenceNumber);
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
