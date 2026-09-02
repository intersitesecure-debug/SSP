using SSP.Activation;

namespace SSP.Activation.Tests.TestSupport;

/// <summary>Deterministic clock for tests; set/advance manually.</summary>
internal sealed class FixedClock : IClock
{
    private DateTimeOffset _utcNow;

    public FixedClock(DateTimeOffset utcNow)
    {
        _utcNow = utcNow;
    }

    public DateTimeOffset UtcNow => _utcNow;

    public void Set(DateTimeOffset utcNow) => _utcNow = utcNow;

    public void Advance(TimeSpan delta) => _utcNow += delta;
}
