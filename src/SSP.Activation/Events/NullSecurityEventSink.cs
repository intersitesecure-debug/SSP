namespace SSP.Activation;

/// <summary>Discards all security events (default sink). Replace with a persistent sink in production hosts.</summary>
public sealed class NullSecurityEventSink : ISecurityEventSink
{
    public static NullSecurityEventSink Instance { get; } = new();

    public void Report(LicenseSecurityEvent securityEvent)
    {
    }
}
