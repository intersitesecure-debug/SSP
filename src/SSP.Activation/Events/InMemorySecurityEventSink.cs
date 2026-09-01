namespace SSP.Activation;

/// <summary>Thread-safe in-memory event sink; useful for diagnostics and tests.</summary>
public sealed class InMemorySecurityEventSink : ISecurityEventSink
{
    private readonly object _gate = new();
    private readonly List<LicenseSecurityEvent> _events = new();

    public void Report(LicenseSecurityEvent securityEvent)
    {
        if (securityEvent is null)
        {
            return;
        }

        lock (_gate)
        {
            _events.Add(securityEvent);
        }
    }

    /// <summary>Returns a snapshot of all recorded events.</summary>
    public IReadOnlyList<LicenseSecurityEvent> Snapshot()
    {
        lock (_gate)
        {
            return _events.ToArray();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _events.Clear();
        }
    }
}
