namespace SSP.Activation.Tests.TestSupport;

/// <summary>
/// Fluent builder for test license payloads. Base time is fixed so every test is
/// deterministic and independent of the wall clock.
/// </summary>
internal sealed class LicensePayloadFactory
{
    public static readonly DateTimeOffset BaseTime = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private Guid _productId;
    private Guid _licenseId = Guid.NewGuid();
    private Guid _customerId = Guid.NewGuid();
    private string _productName = "SSP";
    private string _customerName = "Contoso Ltd.";
    private string _edition = "Enterprise";
    private string _licenseVersion = "1.0";
    private DateTimeOffset _issuedAt = BaseTime.AddDays(-2);
    private DateTimeOffset _notBefore = BaseTime.AddDays(-1);
    private DateTimeOffset _expiresAt = BaseTime.AddYears(1);
    private string? _installationId;
    private List<string> _features = new() { "rdp", "web", "ssh" };
    private Dictionary<string, long?> _limits = new()
    {
        [LicenseLimitNames.MaxConcurrentSessions] = 5,
        [LicenseLimitNames.MaxServices] = 3
    };
    private LicenseStatus _status = LicenseStatus.Active;
    private long _sequenceNumber = 1;

    public LicensePayloadFactory(Guid productId)
    {
        _productId = productId;
    }

    public static LicensePayloadFactory For(TestAuthority authority) => new(authority.ProductId);

    public LicensePayloadFactory WithProductId(Guid productId) { _productId = productId; return this; }

    public LicensePayloadFactory WithLicenseId(Guid licenseId) { _licenseId = licenseId; return this; }

    public LicensePayloadFactory WithCustomerId(Guid customerId) { _customerId = customerId; return this; }

    public LicensePayloadFactory WithCustomerName(string name) { _customerName = name; return this; }

    public LicensePayloadFactory WithEdition(string edition) { _edition = edition; return this; }

    public LicensePayloadFactory WithLicenseVersion(string version) { _licenseVersion = version; return this; }

    public LicensePayloadFactory WithIssuedAt(DateTimeOffset issuedAt) { _issuedAt = issuedAt; return this; }

    public LicensePayloadFactory WithNotBefore(DateTimeOffset notBefore) { _notBefore = notBefore; return this; }

    public LicensePayloadFactory WithExpiresAt(DateTimeOffset expiresAt) { _expiresAt = expiresAt; return this; }

    public LicensePayloadFactory WithWindow(DateTimeOffset notBefore, DateTimeOffset expiresAt)
    {
        _notBefore = notBefore;
        _expiresAt = expiresAt;
        return this;
    }

    public LicensePayloadFactory WithInstallationId(string? installationId) { _installationId = installationId; return this; }

    public LicensePayloadFactory WithFeatures(params string[] features) { _features = features.ToList(); return this; }

    public LicensePayloadFactory WithFeature(string feature) { _features.Add(feature); return this; }

    public LicensePayloadFactory WithLimits(Dictionary<string, long?> limits) { _limits = limits; return this; }

    public LicensePayloadFactory WithLimit(string name, long? max) { _limits[name] = max; return this; }

    public LicensePayloadFactory WithStatus(LicenseStatus status) { _status = status; return this; }

    public LicensePayloadFactory WithSequence(long sequenceNumber) { _sequenceNumber = sequenceNumber; return this; }

    public LicensePayload Build() => new()
    {
        LicenseId = _licenseId,
        ProductId = _productId,
        ProductName = _productName,
        CustomerId = _customerId,
        CustomerName = _customerName,
        Edition = _edition,
        LicenseVersion = _licenseVersion,
        IssuedAt = _issuedAt,
        NotBefore = _notBefore,
        ExpiresAt = _expiresAt,
        InstallationId = _installationId,
        FeatureSet = new LicenseFeatureSet(_features),
        Limits = new LicenseLimits(_limits),
        Status = _status,
        SequenceNumber = _sequenceNumber
    };
}
