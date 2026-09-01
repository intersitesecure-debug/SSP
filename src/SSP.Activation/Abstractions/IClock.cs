namespace SSP.Activation;

/// <summary>Time abstraction so time-dependent behavior can be tested deterministically.</summary>
public interface IClock
{
    /// <summary>Current UTC time.</summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>Production clock over the system time. All licensing time comparisons are UTC.</summary>
public sealed class SystemClock : IClock
{
    public static SystemClock Instance { get; } = new();

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
