namespace SSP.Activation;

/// <summary>
/// Non-persistent in-memory state store (default). SSP.Core should supply a tam-resistant
/// persistent implementation for durable anti-rollback; see docs/ARCHITECTURE.md §10.
/// The store only ever restricts authorization (anti-rollback floor); it can never grant it.
/// </summary>
public sealed class InMemoryLicenseStateStore : ILicenseStateStore
{
    private readonly object _gate = new();
    private LicenseStateRecord? _record;

    public LicenseStateRecord? Load()
    {
        lock (_gate)
        {
            return _record;
        }
    }

    public void Save(LicenseStateRecord record)
    {
        if (record is null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        lock (_gate)
        {
            _record = record;
        }
    }
}
