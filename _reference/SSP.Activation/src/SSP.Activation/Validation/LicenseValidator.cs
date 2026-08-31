namespace SSP.Activation;

/// <summary>Internal default identity provider: reports the identity as unavailable (fail closed).</summary>
internal sealed class NullInstallationIdentityProvider : IInstallationIdentityProvider
{
    public static NullInstallationIdentityProvider Instance { get; } = new();

    public string? GetInstallationId() => null;
}

/// <summary>
/// Centralized validation pipeline:
/// <code>
///   load → parse → schema → signature → status/revocation → product → installation
///        → not-before → expiration → anti-rollback → VALID
/// </code>
/// Every failure produces an explicit, deterministic failure state. The pipeline never
/// fails open: missing input, malformed data, infrastructure errors or unexpected
/// exceptions all result in a non-valid result, and protected operations stay denied.
/// </summary>
/// <remarks>
/// The validator is stateless with respect to authorization (it only reads the state
/// store for the anti-rollback floor) and can be used standalone (e.g. by activation
/// tooling) as well as through <see cref="LicenseManager"/>.
/// </remarks>
public sealed class LicenseValidator
{
    private readonly LicenseTrustAnchor _trustAnchor;
    private readonly LicenseValidationOptions _options;
    private readonly IClock _clock;
    private readonly IInstallationIdentityProvider _identityProvider;
    private readonly ILicenseStateStore _stateStore;
    private readonly ILicenseRevocationChecker _revocationChecker;
    private readonly ISecurityEventSink _eventSink;

    public LicenseValidator(
        LicenseTrustAnchor trustAnchor,
        LicenseValidationOptions options,
        IClock? clock = null,
        IInstallationIdentityProvider? identityProvider = null,
        ILicenseStateStore? stateStore = null,
        ILicenseRevocationChecker? revocationChecker = null,
        ISecurityEventSink? eventSink = null)
    {
        if (trustAnchor is null)
        {
            throw new ArgumentNullException(nameof(trustAnchor));
        }

        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        _trustAnchor = trustAnchor;
        _options = options;
        _clock = clock ?? SystemClock.Instance;
        _identityProvider = identityProvider ?? NullInstallationIdentityProvider.Instance;
        _stateStore = stateStore ?? new InMemoryLicenseStateStore();
        _revocationChecker = revocationChecker ?? NullLicenseRevocationChecker.Instance;
        _eventSink = eventSink ?? NullSecurityEventSink.Instance;
    }

    /// <summary>
    /// Runs the full validation pipeline against an artifact. Null/empty input yields an
    /// explicit Unknown/missing_license result (never an exception, never a pass).
    /// </summary>
    public LicenseValidationResult Validate(string? artifactJson)
    {
        if (string.IsNullOrWhiteSpace(artifactJson))
        {
            return Fail(
                LicenseState.Unknown,
                LicenseReasons.MissingLicense,
                "No license artifact was provided.",
                LicenseSecurityEventType.LicenseValidationFailed);
        }

        if (!LicenseArtifactCodec.TryDecode(artifactJson, out var artifact, out var decodeError) || artifact is null)
        {
            return Fail(
                LicenseState.Malformed,
                LicenseReasons.MalformedArtifact,
                $"License artifact could not be decoded ({decodeError!.Code}): {decodeError.Detail}",
                LicenseSecurityEventType.LicenseValidationFailed);
        }

        _eventSink.Report(MakeEvent(
            LicenseSecurityEventType.LicenseLoaded,
            LicenseState.Unknown,
            artifact.Payload.LicenseId,
            LicenseReasons.Ok,
            $"License artifact loaded (algorithm {artifact.SignatureAlgorithm}, artifact version {artifact.ArtifactVersion})."));

        var payload = artifact.Payload;

        // Stage 1 — signature support and verification. No content is trusted before this passes.
        if (!SignatureAlgorithms.IsSupported(artifact.SignatureAlgorithm))
        {
            return Fail(
                LicenseState.InvalidSignature,
                LicenseReasons.UnsupportedSignatureAlgorithm,
                $"Signature algorithm '{artifact.SignatureAlgorithm}' is not supported.",
                LicenseSecurityEventType.InvalidSignature,
                payload,
                artifact.ArtifactVersion);
        }

        byte[] canonical;
        try
        {
            canonical = LicenseCanonicalJson.Serialize(payload);
        }
        catch (Exception ex)
        {
            return Fail(
                LicenseState.Malformed,
                LicenseReasons.InvalidSchema,
                $"Payload could not be canonicalized: {ex.GetType().Name}",
                LicenseSecurityEventType.LicenseValidationFailed,
                payload,
                artifact.ArtifactVersion);
        }

        bool signatureValid;
        try
        {
            signatureValid = SignatureAlgorithms.Verify(artifact.SignatureAlgorithm, _trustAnchor, canonical, artifact.Signature);
        }
        catch (Exception ex)
        {
            return Fail(
                LicenseState.InvalidSignature,
                LicenseReasons.InvalidSignature,
                $"Signature verification failed with a cryptographic error: {ex.GetType().Name}",
                LicenseSecurityEventType.InvalidSignature,
                payload,
                artifact.ArtifactVersion);
        }

        if (!signatureValid)
        {
            return Fail(
                LicenseState.InvalidSignature,
                LicenseReasons.InvalidSignature,
                "License signature does not verify against the licensing authority public key.",
                LicenseSecurityEventType.InvalidSignature,
                payload,
                artifact.ArtifactVersion);
        }

        // Stage 2 — revocation / status (payload is now authenticated).
        if (payload.Status == LicenseStatus.Revoked)
        {
            return Fail(
                LicenseState.Revoked,
                LicenseReasons.Revoked,
                "License status is revoked.",
                LicenseSecurityEventType.LicenseRevoked,
                payload,
                artifact.ArtifactVersion);
        }

        LicenseRevocationCheckResult revocation;
        try
        {
            revocation = _revocationChecker.Check(payload);
        }
        catch (Exception ex)
        {
            return Fail(
                LicenseState.Unknown,
                LicenseReasons.RevocationCheckFailed,
                $"Revocation check failed: {ex.GetType().Name}",
                LicenseSecurityEventType.LicenseValidationFailed,
                payload,
                artifact.ArtifactVersion);
        }

        if (revocation.IsRevoked)
        {
            return Fail(
                LicenseState.Revoked,
                LicenseReasons.Revoked,
                revocation.Detail ?? "License was reported revoked by the revocation checker.",
                LicenseSecurityEventType.LicenseRevoked,
                payload,
                artifact.ArtifactVersion);
        }

        // Stage 3 — product binding.
        if (payload.ProductId != _options.ExpectedProductId)
        {
            return Fail(
                LicenseState.WrongProduct,
                LicenseReasons.WrongProduct,
                $"License is for product {payload.ProductId}; this deployment requires {_options.ExpectedProductId}.",
                LicenseSecurityEventType.LicenseValidationFailed,
                payload,
                artifact.ArtifactVersion);
        }

        // Stage 4 — installation binding. The identity provider is consulted only when the
        // license is actually installation-bound; a floating license (InstallationId == null)
        // does not depend on identity plumbing. Unavailable identity fails closed.
        if (payload.InstallationId is not null)
        {
            string? installedId;
            try
            {
                installedId = _identityProvider.GetInstallationId();
            }
            catch (Exception ex)
            {
                return Fail(
                    LicenseState.Unknown,
                    LicenseReasons.IdentityUnavailable,
                    $"Installation identity provider failed: {ex.GetType().Name}",
                    LicenseSecurityEventType.LicenseValidationFailed,
                    payload,
                    artifact.ArtifactVersion);
            }

            if (string.IsNullOrWhiteSpace(installedId))
            {
                return Fail(
                    LicenseState.Unknown,
                    LicenseReasons.IdentityUnavailable,
                    "Installation identity is unavailable; installation-bound licenses cannot be validated.",
                    LicenseSecurityEventType.LicenseValidationFailed,
                    payload,
                    artifact.ArtifactVersion);
            }

            if (!string.Equals(payload.InstallationId.Trim(), installedId.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return Fail(
                    LicenseState.WrongInstallation,
                    LicenseReasons.WrongInstallation,
                    "License is bound to a different installation.",
                    LicenseSecurityEventType.LicenseBindingFailed,
                    payload,
                    artifact.ArtifactVersion);
            }
        }

        // Stage 5 — time window (UTC; ExpiresAt is exclusive).
        var now = _clock.UtcNow;
        if (now < payload.NotBefore)
        {
            return Fail(
                LicenseState.NotYetValid,
                LicenseReasons.NotYetValid,
                $"License is not valid before {FormatTime(payload.NotBefore)} (now {FormatTime(now)}).",
                LicenseSecurityEventType.LicenseValidationFailed,
                payload,
                artifact.ArtifactVersion);
        }

        if (now >= payload.ExpiresAt)
        {
            return Fail(
                LicenseState.Expired,
                LicenseReasons.Expired,
                $"License expired at {FormatTime(payload.ExpiresAt)} (now {FormatTime(now)}).",
                LicenseSecurityEventType.LicenseExpired,
                payload,
                artifact.ArtifactVersion);
        }

        // Stage 6 — anti-rollback (state store can only restrict, never grant).
        LicenseStateRecord? stored;
        try
        {
            stored = _stateStore.Load();
        }
        catch (Exception ex)
        {
            return Fail(
                LicenseState.Unknown,
                LicenseReasons.StateStoreUnavailable,
                $"License state store is unavailable: {ex.GetType().Name}",
                LicenseSecurityEventType.LicenseValidationFailed,
                payload,
                artifact.ArtifactVersion);
        }

        if (stored is not null && payload.SequenceNumber < stored.HighestAcceptedSequenceNumber)
        {
            return Fail(
                LicenseState.Superseded,
                LicenseReasons.Superseded,
                $"License sequence {payload.SequenceNumber} is older than the highest accepted sequence {stored.HighestAcceptedSequenceNumber}.",
                LicenseSecurityEventType.LicenseSuperseded,
                payload,
                artifact.ArtifactVersion);
        }

        var license = new License
        {
            Payload = payload,
            SignatureAlgorithm = artifact.SignatureAlgorithm,
            ArtifactVersion = artifact.ArtifactVersion
        };

        var validEvent = MakeEvent(
            LicenseSecurityEventType.LicenseValidated,
            LicenseState.Valid,
            payload.LicenseId,
            LicenseReasons.Ok,
            "License validated successfully.");

        _eventSink.Report(validEvent);

        return LicenseValidationResult.Valid(license, validEvent);
    }

    private static string FormatTime(DateTimeOffset value)
        => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private LicenseSecurityEvent MakeEvent(
        LicenseSecurityEventType eventType,
        LicenseState state,
        Guid? licenseId,
        string reasonCode,
        string detail)
        => new()
        {
            EventType = eventType,
            OccurredAtUtc = _clock.UtcNow,
            State = state,
            LicenseId = licenseId,
            ReasonCode = reasonCode,
            Detail = detail
        };

    private LicenseValidationResult Fail(
        LicenseState state,
        string reasonCode,
        string detail,
        LicenseSecurityEventType eventType,
        LicensePayload? payload = null,
        int artifactVersion = LicenseArtifactCodec.CurrentArtifactVersion,
        string signatureAlgorithm = SignatureAlgorithms.RsaPssSha256)
    {
        License? license = null;
        if (payload is not null)
        {
            license = new License
            {
                Payload = payload,
                SignatureAlgorithm = signatureAlgorithm,
                ArtifactVersion = artifactVersion
            };
        }

        var securityEvent = MakeEvent(eventType, state, payload?.LicenseId, reasonCode, detail);
        _eventSink.Report(securityEvent);

        return LicenseValidationResult.Fail(state, reasonCode, detail, license, securityEvent);
    }

    private sealed class NullLicenseRevocationChecker : ILicenseRevocationChecker
    {
        public static NullLicenseRevocationChecker Instance { get; } = new();

        public LicenseRevocationCheckResult Check(LicensePayload license) => LicenseRevocationCheckResult.NotRevoked();
    }
}
