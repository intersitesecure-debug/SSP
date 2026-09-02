using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Validation;

/// <summary>
/// Validation pipeline tests: valid, expired, not-yet-valid, wrong product, wrong
/// installation, revoked, invalid signature, malformed, missing, plus exact time
/// boundary conditions and anti-rollback.
/// </summary>
public class LicenseValidatorTests
{
    [Fact]
    public void ValidLicense_IsAccepted()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var result = validator.Validate(artifact);

        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, result.State);
        Assert.Equal(LicenseReasons.Ok, result.ReasonCode);
        Assert.NotNull(result.License);
        Assert.NotNull(result.License!.Payload);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingLicense_YieldsUnknownState(string? artifactJson)
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);

        var result = validator.Validate(artifactJson);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Unknown, result.State);
        Assert.Equal(LicenseReasons.MissingLicense, result.ReasonCode);
        Assert.Null(result.License);
    }

    [Fact]
    public void MalformedLicense_YieldsMalformedState()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);

        var result = validator.Validate("{ this is not an artifact");

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Malformed, result.State);
        Assert.Equal(LicenseReasons.MalformedArtifact, result.ReasonCode);
    }

    [Fact]
    public void ExpiredLicense_IsRejected_AtExactExpirationTime()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        var expiresAt = payload.ExpiresAt;

        var beforeExpiry = ValidatorFactory.Create(authority, new FixedClock(expiresAt - TimeSpan.FromTicks(1)));
        Assert.True(beforeExpiry.Validate(authority.Issue(payload)).IsValid);

        var atExpiry = ValidatorFactory.Create(authority, new FixedClock(expiresAt));
        var result = atExpiry.Validate(authority.Issue(payload));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Expired, result.State);
        Assert.Equal(LicenseReasons.Expired, result.ReasonCode);
    }

    [Fact]
    public void NotYetValidLicense_IsRejected_BeforeNotBefore()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        var notBefore = payload.NotBefore;

        var atNotBefore = ValidatorFactory.Create(authority, new FixedClock(notBefore));
        Assert.True(atNotBefore.Validate(authority.Issue(payload)).IsValid);

        var justBefore = ValidatorFactory.Create(authority, new FixedClock(notBefore - TimeSpan.FromTicks(1)));
        var result = justBefore.Validate(authority.Issue(payload));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.NotYetValid, result.State);
        Assert.Equal(LicenseReasons.NotYetValid, result.ReasonCode);
    }

    [Fact]
    public void WrongProduct_IsRejected()
    {
        using var authority = new TestAuthority();
        var otherProduct = Guid.NewGuid();
        var validator = new LicenseValidator(
            authority.TrustAnchor,
            new LicenseValidationOptions(otherProduct),
            new FixedClock(LicensePayloadFactory.BaseTime),
            new StaticInstallationIdentityProvider("INSTALLATION-A"));

        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());
        var result = validator.Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.WrongProduct, result.State);
        Assert.Equal(LicenseReasons.WrongProduct, result.ReasonCode);
    }

    [Fact]
    public void RevokedStatus_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).WithStatus(LicenseStatus.Revoked).Build());

        var result = validator.Validate(artifact);

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Revoked, result.State);
        Assert.Equal(LicenseReasons.Revoked, result.ReasonCode);
    }

    [Fact]
    public void RevocationChecker_ReportsRevoked_IsRejected()
    {
        using var authority = new TestAuthority();
        var payload = LicensePayloadFactory.For(authority).Build();
        var checker = new StubRevocationChecker(revokedIds: new[] { payload.LicenseId });
        var validator = ValidatorFactory.Create(authority, revocationChecker: checker);

        var result = validator.Validate(authority.Issue(payload));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Revoked, result.State);
    }

    [Fact]
    public void RevocationChecker_NotRevoked_IsAccepted()
    {
        using var authority = new TestAuthority();
        var checker = new StubRevocationChecker(revokedIds: Array.Empty<Guid>());
        var validator = ValidatorFactory.Create(authority, revocationChecker: checker);

        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).Build()));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void RevocationChecker_Throws_FailsClosed()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority, revocationChecker: new ThrowingRevocationChecker());

        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).Build()));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.RevocationCheckFailed, result.ReasonCode);
    }

    [Fact]
    public void InvalidSignature_IsRejected()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority);
        var artifact = authority.Issue(LicensePayloadFactory.For(authority).Build());

        var mutated = ArtifactTestHelper.MutatePayloadJson(
            ArtifactTestHelper.GetPayloadJson(artifact),
            node => node["productName"] = "Tampered Product");

        var result = validator.Validate(ArtifactTestHelper.MakeArtifact(mutated, ArtifactTestHelper.GetSignatureBytes(artifact)));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.InvalidSignature, result.State);
    }

    [Fact]
    public void AntiRollback_OlderSequence_IsRejected()
    {
        using var authority = new TestAuthority();
        var store = new InMemoryLicenseStateStore();
        store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 5 });
        var validator = ValidatorFactory.Create(authority, stateStore: store);

        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).WithSequence(4).Build()));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseState.Superseded, result.State);
        Assert.Equal(LicenseReasons.Superseded, result.ReasonCode);
    }

    [Fact]
    public void AntiRollback_EqualSequence_IsAccepted()
    {
        using var authority = new TestAuthority();
        var store = new InMemoryLicenseStateStore();
        store.Save(new LicenseStateRecord { HighestAcceptedSequenceNumber = 5 });
        var validator = ValidatorFactory.Create(authority, stateStore: store);

        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).WithSequence(5).Build()));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void AntiRollback_NoPersistedFloor_IsAccepted()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority, stateStore: new InMemoryLicenseStateStore());

        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).WithSequence(0).Build()));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void StateStoreThrows_FailsClosed()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority, stateStore: new ThrowingStateStore());

        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).Build()));

        Assert.False(result.IsValid);
        Assert.Equal(LicenseReasons.StateStoreUnavailable, result.ReasonCode);
    }

    [Fact]
    public void FailedValidation_DoesNotExposeTrustedLicense_ButKeepsDecodedPayloadForDiagnostics()
    {
        using var authority = new TestAuthority();
        var validator = ValidatorFactory.Create(authority, new FixedClock(LicensePayloadFactory.BaseTime.AddYears(2)));

        var result = validator.Validate(authority.Issue(LicensePayloadFactory.For(authority).Build()));

        Assert.False(result.IsValid);
        Assert.NotNull(result.License); // diagnostics only; IsValid=false
        Assert.Equal("Contoso Ltd.", result.License!.Payload.CustomerName);
    }

    private sealed class StubRevocationChecker : ILicenseRevocationChecker
    {
        private readonly HashSet<Guid> _revokedIds;

        public StubRevocationChecker(IEnumerable<Guid> revokedIds)
        {
            _revokedIds = new HashSet<Guid>(revokedIds);
        }

        public LicenseRevocationCheckResult Check(LicensePayload license)
            => _revokedIds.Contains(license.LicenseId)
                ? LicenseRevocationCheckResult.Revoked("License is on the simulated revocation list.")
                : LicenseRevocationCheckResult.NotRevoked();
    }

    private sealed class ThrowingRevocationChecker : ILicenseRevocationChecker
    {
        public LicenseRevocationCheckResult Check(LicensePayload license) => throw new InvalidOperationException("revocation service down");
    }

    private sealed class ThrowingStateStore : ILicenseStateStore
    {
        public LicenseStateRecord? Load() => throw new IOException("store unavailable");

        public void Save(LicenseStateRecord record) => throw new IOException("store unavailable");
    }
}
