namespace SSP.Activation;

/// <summary>Receives structured licensing security events. Implementations must not throw.</summary>
public interface ISecurityEventSink
{
    void Report(LicenseSecurityEvent securityEvent);
}
