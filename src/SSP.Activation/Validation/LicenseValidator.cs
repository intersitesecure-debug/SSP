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
///        → monotonic UTC checkpoint / both validity windows → anti-rollback → activation → VALID
/// </code>
/// Every failure produces an explicit, deterministic failure state. The pipeline never
/// fails open: missing input, malformed data, infrastructure errors or unexpected
/// exceptions all result in a non-valid result, and protected operations stay denied.
/// </summary>
/// <remarks>
/// The validator is stateless with respect to authorization and can be used standalone
/// or through LicenseManager. Phase 6 also persists restrictive time observations
/// (including expiration), never acceptance/activation. A standalone validation cannot
/// forget observed expiry between calls simply because no manager applies the result.
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
    private readonly LicenseTimeIntegrity _time;

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
        _time = new LicenseTimeIntegrity(_clock, _stateStore, _eventSink);
    }

    // The manager shares this guard, so concurrent validations, Apply and Authorize
    // retain the same in-process high-water mark even after a persistence failure.
    internal LicenseTimeIntegrity TimeIntegrity => _time;

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

        _time.Report(MakeEvent(
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

        var certification = artifact.Certification;
        LicenseTrustAnchor? payloadSignerAnchor = _trustAnchor;

        // The leaf anchor (when the certified chain is in use) lives only for this
        // artifact's verification and is disposed on every path.
        LicenseTrustAnchor? leafAnchor = null;
        try
        {
            if (certification is not null)
            {
                // Version-2 (certified) chain: root certifies the per-license key; that
                // leaf key signs the payload. The root anchor is the only trust anchor; the
                // key in the certification is usable only after the root signature verifies.

                // 1a — the certification must be signed by the root authority. Nothing in
                // the certification (including its embedded public key) is trusted before.
                byte[] certificationCanonical;
                try
                {
                    certificationCanonical = LicenseKeyCertificationCanonicalJson.Serialize(certification);
                }
                catch (Exception ex)
                {
                    return Fail(
                        LicenseState.InvalidCertification,
                        LicenseReasons.InvalidCertificationSignature,
                        $"Key certification could not be canonicalized: {ex.GetType().Name}",
                        LicenseSecurityEventType.InvalidSignature,
                        payload,
                        artifact.ArtifactVersion,
                        certification: certification);
                }

                bool certificationValid;
                try
                {
                    certificationValid = SignatureAlgorithms.Verify(
                        artifact.SignatureAlgorithm, _trustAnchor, certificationCanonical, artifact.CertificationSignature!);
                }
                catch (Exception ex)
                {
                    return Fail(
                        LicenseState.InvalidCertification,
                        LicenseReasons.InvalidCertificationSignature,
                        $"Certification verification failed with a cryptographic error: {ex.GetType().Name}",
                        LicenseSecurityEventType.InvalidSignature,
                        payload,
                        artifact.ArtifactVersion,
                        certification: certification);
                }

                if (!certificationValid)
                {
                    return Fail(
                        LicenseState.InvalidCertification,
                        LicenseReasons.InvalidCertificationSignature,
                        "Key certification signature does not verify against the licensing authority public key.",
                        LicenseSecurityEventType.InvalidSignature,
                        payload,
                        artifact.ArtifactVersion,
                        certification: certification);
                }

                // 1b — the certified key becomes the payload-signer anchor. It is not a
                // trust anchor by itself: it is only used because the root authority
                // certified it.
                try
                {
                    leafAnchor = LicenseTrustAnchor.FromSpkiDer(certification.PublicKeySpkiDer);
                }
                catch (Exception ex)
                {
                    return Fail(
                        LicenseState.InvalidCertification,
                        LicenseReasons.InvalidCertificationKey,
                        $"The certified per-license public key is unusable: {ex.GetType().Name}",
                        LicenseSecurityEventType.InvalidSignature,
                        payload,
                        artifact.ArtifactVersion,
                        certification: certification);
                }

                payloadSignerAnchor = leafAnchor;

                // 1c — binding: the certification must be about exactly this payload. This
                // is what stops a certification for license A from authenticating a payload
                // for license B, and stops a substituted payload from riding a valid
                // certification.
                if (certification.LicenseId != payload.LicenseId ||
                    certification.ProductId != payload.ProductId ||
                    certification.CustomerId != payload.CustomerId)
                {
                    return Fail(
                        LicenseState.InvalidCertification,
                        LicenseReasons.CertificationBindingMismatch,
                        "Key certification does not match the license payload it is embedded with.",
                        LicenseSecurityEventType.InvalidSignature,
                        payload,
                        artifact.ArtifactVersion,
                        certification: certification);
                }

                // Phase 6 evaluates the certification window together with
                // the payload window, from one protected time observation below.
                // Both RSA-PSS signatures still MUST verify before acceptance.
            }

            bool signatureValid;
            try
            {
                signatureValid = SignatureAlgorithms.Verify(artifact.SignatureAlgorithm, payloadSignerAnchor!, canonical, artifact.Signature);
            }
            catch (Exception ex)
            {
                return Fail(
                    LicenseState.InvalidSignature,
                    LicenseReasons.InvalidSignature,
                    $"Signature verification failed with a cryptographic error: {ex.GetType().Name}",
                    LicenseSecurityEventType.InvalidSignature,
                    payload,
                    artifact.ArtifactVersion,
                    certification: certification);
            }

            if (!signatureValid)
            {
                return Fail(
                    LicenseState.InvalidSignature,
                    LicenseReasons.InvalidSignature,
                    certification is null
                        ? "License signature does not verify against the licensing authority public key."
                        : "License signature does not verify against the certified per-license public key.",
                    LicenseSecurityEventType.InvalidSignature,
                    payload,
                    artifact.ArtifactVersion,
                    certification: certification);
            }
        }
        finally
        {
            leafAnchor?.Dispose();
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

        var license = new License
        {
            Payload = payload,
            SignatureAlgorithm = artifact.SignatureAlgorithm,
            ArtifactVersion = artifact.ArtifactVersion,
            Certification = certification
        };

        // Stage 5 — Phase 6 time integrity + BOTH UTC validity windows. The
        // observation is checkpointed even if a window is expired; recording only
        // successful validations would allow an observed expiration to be revived.
        var observation = _time.Observe(license,
            (record, now) => (record, _time.CheckWindow(license, now)));
        if (observation.Failure is { } timeFailure)
            return timeFailure;

        // Stage 6 — anti-rollback (state store can only restrict, never grant).
        var stored = observation.Record;
        if (stored is not null && payload.SequenceNumber < stored.HighestAcceptedSequenceNumber)
        {
            return Fail(
                LicenseState.Superseded,
                LicenseReasons.Superseded,
                $"License sequence {payload.SequenceNumber} is older than the highest accepted sequence {stored.HighestAcceptedSequenceNumber}.",
                LicenseSecurityEventType.LicenseSuperseded,
                payload,
                artifact.ArtifactVersion,
                certification: certification);
        }

        // Stage 7 — activation state (version-2 certified licenses only). A license whose
        // certification carries an activation-code hash must have been activated for THIS
        // license id before it can be Valid. Activation state can only restrict (an
        // activation-required license stays ActivationRequired); it can never grant.
        if (certification is { RequiresActivation: true } &&
            stored?.ActivatedLicenseId != payload.LicenseId)
        {
            return Fail(
                LicenseState.ActivationRequired,
                LicenseReasons.ActivationRequired,
                "License is valid but requires activation. Enter the 10-digit activation code issued by the Licensing Authority.",
                LicenseSecurityEventType.ActivationRequired,
                payload,
                artifact.ArtifactVersion,
                certification: certification);
        }

        var validEvent = MakeEvent(
            LicenseSecurityEventType.LicenseValidated,
            LicenseState.Valid,
            payload.LicenseId,
            LicenseReasons.Ok,
            "License validated successfully.");

        _time.Report(validEvent);

        return LicenseValidationResult.Valid(license, validEvent);
    }

    private LicenseSecurityEvent MakeEvent(
        LicenseSecurityEventType eventType,
        LicenseState state,
        Guid? licenseId,
        string reasonCode,
        string detail)
        => new()
        {
            EventType = eventType,
            OccurredAtUtc = _time.EventTimeUtc,
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
        string signatureAlgorithm = SignatureAlgorithms.RsaPssSha256,
        LicenseKeyCertification? certification = null)
    {
        License? license = null;
        if (payload is not null)
        {
            license = new License
            {
                Payload = payload,
                SignatureAlgorithm = signatureAlgorithm,
                ArtifactVersion = artifactVersion,
                Certification = certification
            };
        }

        var securityEvent = MakeEvent(eventType, state, payload?.LicenseId, reasonCode, detail);
        _time.Report(securityEvent);

        return LicenseValidationResult.Fail(state, reasonCode, detail, license, securityEvent);
    }

    private sealed class NullLicenseRevocationChecker : ILicenseRevocationChecker
    {
        public static NullLicenseRevocationChecker Instance { get; } = new();

        public LicenseRevocationCheckResult Check(LicensePayload license) => LicenseRevocationCheckResult.NotRevoked();
    }
}
