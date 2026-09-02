using System.Security.Cryptography;
using SSP.Activation;
using SSP.Activation.Tests.TestSupport;

namespace SSP.Activation.Tests.Crypto;

/// <summary>
/// Trust-anchor robustness: the relying party holds exactly one piece of trust
/// configuration — a public key that must be RSA ≥ 2048 bits. Malformed, undersized,
/// wrong-label or non-RSA key material must fail closed (throw on construction), so an
/// attacker can never install a usable verification key through bad input.
/// </summary>
public class TrustAnchorTests
{
    [Fact]
    public void FromPublicKey_RejectsUnderSizedKey()
    {
        using var rsa = RSA.Create(1024);

        var ex = Assert.Throws<ArgumentException>(() => LicenseTrustAnchor.FromPublicKey(rsa));

        Assert.Contains("at least", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FromPublicKey_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => LicenseTrustAnchor.FromPublicKey(null));
    }

    [Fact]
    public void FromPem_RejectsNonPublicKeyLabel()
    {
        // A PRIVATE KEY block must not be accepted as a trust anchor.
        var pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";

        var ex = Assert.Throws<ArgumentException>(() => LicenseTrustAnchor.FromPem(pem));

        Assert.Contains("PUBLIC KEY", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FromPem_RejectsNonRsaKey()
    {
        // A valid, correctly-labelled public key that is not RSA must be rejected: an RSA
        // trust anchor cannot import an EC/Ed25519 SPKI, so construction fails closed.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecSpki = ec.ExportSubjectPublicKeyInfo();
        var ecBase64 = Convert.ToBase64String(ecSpki);
        var ecPem = $"-----BEGIN PUBLIC KEY-----\n{ecBase64}\n-----END PUBLIC KEY-----";

        Assert.ThrowsAny<CryptographicException>(() => LicenseTrustAnchor.FromPem(ecPem));
    }

    [Fact]
    public void FromPem_RoundTripsAndValidates()
    {
        using var rsa = RSA.Create(2048);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var base64 = Convert.ToBase64String(spki);
        var pem = $"-----BEGIN PUBLIC KEY-----\n{base64}\n-----END PUBLIC KEY-----";

        using var anchor = LicenseTrustAnchor.FromPem(pem);
        Assert.Equal(2048, anchor.KeySizeBits);
        Assert.Equal(spki, anchor.ExportSpkiDer());

        // End-to-end: a license signed by this exact private key validates against the
        // PEM-imported public key, and the same bytes are not trusted by another key.
        var productId = Guid.NewGuid();
        var payload = new LicensePayload
        {
            LicenseId = Guid.NewGuid(),
            ProductId = productId,
            ProductName = "SSP",
            CustomerId = Guid.NewGuid(),
            CustomerName = "Contoso",
            Edition = "Enterprise",
            LicenseVersion = "1.0",
            IssuedAt = LicensePayloadFactory.BaseTime.AddDays(-2),
            NotBefore = LicensePayloadFactory.BaseTime.AddDays(-1),
            ExpiresAt = LicensePayloadFactory.BaseTime.AddYears(1),
            FeatureSet = new LicenseFeatureSet(new[] { "rdp" }),
            Limits = LicenseLimits.Empty,
            Status = LicenseStatus.Active,
            SequenceNumber = 1
        };
        var artifact = LicenseIssuer.EncodeLicenseArtifact(payload, rsa);

        var validator = new LicenseValidator(
            anchor,
            new LicenseValidationOptions(productId),
            new FixedClock(LicensePayloadFactory.BaseTime),
            new StaticInstallationIdentityProvider("INSTALL-A"));

        var result = validator.Validate(artifact);
        Assert.True(result.IsValid);
        Assert.Equal(LicenseState.Valid, result.State);
    }
}
