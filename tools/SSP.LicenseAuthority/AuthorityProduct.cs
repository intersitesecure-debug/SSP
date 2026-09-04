// File: tools/SSP.LicenseAuthority/AuthorityProduct.cs
//
// SSP product identity used when the authority issues a license. These values
// MUST stay identical to SSP.Core.Activation.SspLicensing — the relying party
// binds ExpectedProductId to that constant. They are duplicated here so this
// tool depends only on SSP.Activation (BCL-only) and never on SSP.Core,
// SSP.Server or any shipped project.
//
// Drift is pinned by tests/SSP.Tests/Activation/Authority/
// LicenseAuthoritySecurityIsolationTests.AuthorityProduct_MatchesSspLicensing.

using SSP.Activation;

namespace SSP.LicenseAuthority;

internal static class AuthorityProduct
{
    public static readonly Guid ProductId = new("d81f65cb-bd7e-4a6e-9b4c-3be9d13c0f2a");

    public const string ProductName = "SSP";

    public static readonly IReadOnlyList<string> KnownFeatures = new[]
    {
        "rdp",
        "ssh",
        "sql",
        "web",
    };

    public static readonly IReadOnlyList<string> KnownLimits = new[]
    {
        LicenseLimitNames.MaxServices,
        LicenseLimitNames.MaxClients,
        LicenseLimitNames.MaxSessions,
        LicenseLimitNames.MaxConcurrentSessions,
        LicenseLimitNames.MaxConcurrentTunnels,
    };
}
