namespace SSP.Activation;

/// <summary>
/// Persistence abstraction for licensing state (anti-rollback floor, diagnostics).
/// Implementations are NOT a security boundary: the store must never be able to grant
/// authorization, only to restrict it. Hosts should provide a tam-resistant
/// implementation for durable anti-rollback; see docs/ARCHITECTURE.md.
/// </summary>
public interface ILicenseStateStore
{
    LicenseStateRecord? Load();

    void Save(LicenseStateRecord record);
}
