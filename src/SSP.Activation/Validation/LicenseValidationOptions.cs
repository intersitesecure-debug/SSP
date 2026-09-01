namespace SSP.Activation;

/// <summary>
/// Deployment constants for validation. <see cref="ExpectedProductId"/> is the identity of
/// the product this copy of SSP protects — it is a build/deployment constant of SSP.Core,
/// never user-editable runtime configuration, so configuration changes alone can never
/// redefine which licenses are considered acceptable.
/// </summary>
public sealed class LicenseValidationOptions
{
    public Guid ExpectedProductId { get; }

    public LicenseValidationOptions(Guid expectedProductId)
    {
        if (expectedProductId == Guid.Empty)
        {
            throw new ArgumentException("Expected product id must not be empty.", nameof(expectedProductId));
        }

        ExpectedProductId = expectedProductId;
    }
}
