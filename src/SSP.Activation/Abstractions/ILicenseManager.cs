namespace SSP.Activation;

/// <summary>
/// Central runtime-facing licensing API: loads and validates license artifacts, exposes
/// the current license state and gates protected operations. Implementations must be
/// thread-safe.
/// </summary>
public interface ILicenseManager
{
    /// <summary>Runtime state: Unknown (nothing loaded yet), Valid, or LockedDown.</summary>
    LicenseState CurrentState { get; }

    /// <summary>Most recent validation result, including the precise failure state and reason.</summary>
    LicenseValidationResult? LastValidationResult { get; }

    /// <summary>Current license; non-null only while the state is Valid.</summary>
    License? CurrentLicense { get; }

    /// <summary>Loads the license through the configured provider and validates it.</summary>
    LicenseValidationResult Load();

    /// <summary>Validates an explicitly supplied artifact (e.g. from an online activation response or file import).</summary>
    LicenseValidationResult LoadLicense(string artifactJson);

    /// <summary>Revalidates the currently loaded artifact (e.g. periodically or after time has passed).</summary>
    LicenseValidationResult Revalidate();

    /// <summary>Evaluates a protected operation against the current license state and policy.</summary>
    AuthorizationDecision Authorize(ProtectedOperation operation);
}
