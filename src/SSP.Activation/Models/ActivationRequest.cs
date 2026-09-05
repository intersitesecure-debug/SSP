namespace SSP.Activation;

/// <summary>
/// The activation-request message SSP.Server produces for the Licensing Authority when a
/// license is in the <see cref="LicenseState.ActivationRequired"/> state. It carries the
/// license identity, the administrative bindings, and the activation OTT the authority
/// signed into the key certification.
///
/// This type is the transport-independent protocol message: it is produced by the
/// activation core, serialized by <see cref="ActivationRequestCodec"/>, and delivered by a
/// transport. The current transport is the offline request file written by SSP.Server and
/// read by the authority CLI; a future HTTPS transport would send the same serialized
/// message over the network.
///
/// The request is NOT a security boundary and is not signed: its authenticity is
/// established when the authority matches the OTT against its own activation record
/// (an OTT that does not match is simply refused). The OTT itself is only revealed here
/// because the authority signed it into the certification that the customer already holds.
/// </summary>
public sealed record ActivationRequest
{
    /// <summary>Identifier of the license awaiting activation.</summary>
    public required Guid LicenseId { get; init; }

    /// <summary>Identifier of the product the license belongs to.</summary>
    public required Guid ProductId { get; init; }

    /// <summary>Identifier of the customer the license was issued to.</summary>
    public required Guid CustomerId { get; init; }

    /// <summary>Organization/person the license is issued to (when present in the license).</summary>
    public string? OrganizationOrPersonName { get; init; }

    /// <summary>Target computer name the license is administratively bound to (when present).</summary>
    public string? ComputerName { get; init; }

    /// <summary>Installation the license is cryptographically bound to (when present).</summary>
    public string? InstallationId { get; init; }

    /// <summary>The activation one-time token signed into this license's key certification.</summary>
    public required string ActivationOtt { get; init; }

    /// <summary>UTC time the request was produced.</summary>
    public required DateTimeOffset RequestedAtUtc { get; init; }
}
