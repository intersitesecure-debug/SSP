namespace SSP.Activation;

/// <summary>
/// The license-specific key certification ("leaf-key certificate"): the exact content the
/// SSP root authority signs to authorize one license-specific RSA public key.
///
/// This is the ROOT OF TRUST boundary of the two-level licensing chain. The compiled-in
/// root authority public key does not sign <see cref="LicensePayload"/> directly anymore;
/// it signs this certification object, which
///
///   * names exactly one license (<see cref="LicenseId"/>),
///   * binds that license to its product and customer,
///   * carries the DER SubjectPublicKeyInfo of the license-specific public key,
///   * bounds the validity window in which that key may sign license payloads, and
///   * optionally carries the license activation material (OTT and activation-code hash).
///
/// The private key paired with <see cref="PublicKeySpkiDer"/> never leaves the authority
/// side. A relying party uses this object only after verifying the root signature over its
/// canonical form (<see cref="LicenseKeyCertificationCanonicalJson"/>).
/// </summary>
public sealed record LicenseKeyCertification
{
    /// <summary>Identifier of the license this key is authorized to sign for.</summary>
    public required Guid LicenseId { get; init; }

    /// <summary>Identifier of the product the license belongs to.</summary>
    public required Guid ProductId { get; init; }

    /// <summary>Identifier of the customer the license was issued to.</summary>
    public required Guid CustomerId { get; init; }

    /// <summary>Earliest time the license-specific key may sign (UTC, inclusive).</summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>Latest time the license-specific key may sign (UTC, exclusive).</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>DER SubjectPublicKeyInfo (SPKI) of the license-specific RSA public key.</summary>
    public required byte[] PublicKeySpkiDer { get; init; }

    /// <summary>
    /// License activation one-time token (base64url), present when the license requires the
    /// activation flow, null for a pre-activated license. Generated and retained only by the
    /// Licensing Authority; signed into the certification so the customer cannot replace it.
    /// </summary>
    public string? ActivationOtt { get; init; }

    /// <summary>
    /// Lowercase-hex SHA-256 of the activation code that unlocks this license, present when
    /// the license requires the activation flow, null for a pre-activated license. Computed
    /// by <see cref="LicenseActivation.ComputeActivationCodeHash"/>.
    /// </summary>
    public string? ActivationCodeHash { get; init; }

    /// <summary>
    /// True when this certification carries activation material, i.e. the license must be
    /// activated with the 10-digit code before it can authorize anything.
    /// </summary>
    public bool RequiresActivation => !string.IsNullOrEmpty(ActivationCodeHash);
}
