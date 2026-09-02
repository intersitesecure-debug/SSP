using System.Security.Cryptography;

namespace SSP.Activation.Tests.TestSupport;

/// <summary>
/// Simulated SSP Licensing Authority for automated tests: generates an EPHEMERAL RSA key
/// pair at runtime and issues signed license artifacts. Test keys are never production
/// secrets; no key material is committed or embedded in the library.
/// </summary>
internal sealed class TestAuthority : IDisposable
{
    private readonly RSA _signingKey;

    public TestAuthority(int keySizeBits = 2048)
    {
        _signingKey = RSA.Create(keySizeBits);
        ProductId = Guid.NewGuid();
        TrustAnchor = LicenseTrustAnchor.FromPublicKey(_signingKey);
    }

    /// <summary>Trust anchor holding ONLY the public half of the ephemeral key.</summary>
    public LicenseTrustAnchor TrustAnchor { get; }

    /// <summary>Stable product identity owned by this simulated authority.</summary>
    public Guid ProductId { get; }

    /// <summary>Issues a signed artifact for the payload (authority-side operation).</summary>
    public string Issue(LicensePayload payload) => LicenseIssuer.EncodeLicenseArtifact(payload, _signingKey);

    /// <summary>Signs raw canonical bytes directly (used to prove canonicalization semantics).</summary>
    public byte[] SignCanonicalForTest(byte[] canonicalBytes)
        => _signingKey.SignData(canonicalBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public void Dispose()
    {
        TrustAnchor.Dispose();
        _signingKey.Dispose();
    }
}
