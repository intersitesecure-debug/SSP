# SSP.Activation — Architecture

Standalone, dependency-free licensing subsystem for the **SSP (Secure Session Protocol)** product.
Target: .NET 8 / C# 12, nullable enabled, zero external NuGet packages.

> **Prime invariant.** *Without a cryptographically valid license issued by the trusted SSP
> Licensing Authority, protected SSP functionality must not become operational.* Every design
> decision below traces back to this sentence.

---

## 1. Trust Model

```text
        SSP LICENSING AUTHORITY                    SSP DEPLOYMENT (SSP.Core)
        private signing key (RSA)                  LicenseTrustAnchor (public key ONLY)
              │                                            │
              │ signs canonical payload                    │ verifies
              ▼                                            ▼
        License Artifact  ──── transport ────►   LicenseValidator → LicenseManager
                                                       │
                                          ┌────────────┴────────────┐
                                        VALID                    INVALID
                                          ▼                        ▼
                                    SSP.Core runtime           LOCKDOWN
```

- The **private signing key exists only at the Licensing Authority** (offline HSM/key vault).
  It is *never* embedded, stored, cached or logged by this library.
- The relying-party library holds exactly one piece of trust configuration: the
  **`LicenseTrustAnchor`** — the authority's *public* key (SPKI DER or PEM), supplied by the
  host at startup. Minimum accepted RSA key size: 2048 bits (3072+ recommended).
- Authorization decisions are **derived exclusively from signature verification** of the
  license artifact plus policy evaluation. Configuration, environment, registry, UI or
  persistence can never *create* authorization — the state store can only *restrict* it
  (see §10, §11).
- The authority-side issuing API (`LicenseIssuer.EncodeLicenseArtifact`) lives in the same
  assembly so issuance and verification share one canonicalization implementation, but it
  requires the caller to pass the private key on every call.

### Authority vs. Customer boundary (explicit)

| Side | Types / responsibilities | Key material | Ships to customer |
|---|---|---|---|
| **Licensing Authority** | `LicenseIssuer` — canonicalize + sign a `LicensePayload` into an artifact. Owns the private signing key (HSM/vault), the product `Guid`, and the issuance sequence counter. | **private RSA key** (never embedded/persisted/logged by the library) | not shipped |
| **Customer SSP runtime** | `LicenseTrustAnchor` (public key only), `LicenseValidator`, `LicenseManager`, `LicenseEnforcement`, policies, providers, state store, event sink. | **public key only** | shipped into SSP.Core |

The authority side never runs on a customer host. The customer side never holds, requests or
receives a private key. `LicenseIssuer` requires the caller to pass an `RSA` private key on
every call and never generates, stores, caches or logs one — so it cannot accidentally leak
signing capability into a deployment that does not already possess a private key.

## 2. License Artifact

The artifact ("license file") is a strict JSON envelope:

```json
{
  "format": "ssp-license",
  "artifactVersion": 1,
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "payload": "<base64url(canonical payload JSON)>",
  "signature": "<base64url(RSA-PSS signature over the canonical payload bytes)>"
}
```

- **Signed payload vs. signature are strictly separated.** The payload travels as base64url
  of its *canonical* UTF-8 JSON form, so the exact signed bytes are unambiguous (no JSON
  string-escaping ambiguity, no double-encoding hazards).
- The signed payload (`LicensePayload`) is an immutable record containing: `LicenseId`,
  `ProductId`, `ProductName`, `CustomerId`, `CustomerName`, `Edition`, `LicenseVersion`,
  `IssuedAt`, `NotBefore`, `ExpiresAt`, `InstallationId` (optional → floating license),
  `FeatureSet`, `Limits`, `Status` (`active`/`revoked`), `SequenceNumber` (anti-rollback).
- `LicenseArtifactCodec` decodes **strictly**: unknown fields, duplicate fields, wrong types,
  unknown artifact versions, non-canonical base64url characters and invalid payload schemas
  are all rejected. Malformed artifacts fail closed (`Malformed`) and never reach signature
  verification.
- Unknown `signatureAlgorithm` *names* are format-valid but fail support-check at validation
  (`InvalidSignature` / `unsupported_signature_algorithm`), which lets a future library that
  understands more algorithms still parse old artifacts.

## 3. Signature Algorithm

**Selected: `RSA-PSS-SHA256`** — RSA-PSS (salt length = SHA-256 digest size, MGF1 with
SHA-256) over the canonical payload bytes.

Evaluation of candidates:

| Criterion                | RSA-PSS-SHA256 (chosen)               | Ed25519                          | ECDSA P-256                       |
|--------------------------|---------------------------------------|----------------------------------|-----------------------------------|
| .NET 8 native support    | Yes, all platforms                    | Yes, .NET 7+ (platform-limited)  | Yes                               |
| Platform support         | Windows CNG (all servers), Linux/macOS OpenSSL | Old Windows Server CNG lacks it; needs OpenSSL 1.1.1+/3.x | Universal |
| FIPS approval            | Approved (PSS + SHA-256)              | Not FIPS-approved                | Approved (with caveats)           |
| Deterministic signing    | No (randomized salt — fine; only the *payload* must be canonical) | Yes | No |
| Signature size           | 256 B @ RSA-2048 / 384 B @ RSA-3072   | 64 B                             | ~70 B                             |
| Deployment complexity    | None (no certs required)              | None                             | Signature encoding care (ASN.1)   |

RSA signature size is irrelevant for a license file, while FIPS compatibility and
guaranteed availability on legacy Windows Server CNG matter for enterprise deployments.
**No cryptography is invented**; nothing beyond `System.Security.Cryptography` is used.
The algorithm registry (`SignatureAlgorithms`) is a fail-closed allow-list: artifacts
declaring any other algorithm can never verify.

## 4. Canonicalization

`LicenseCanonicalJson.Serialize(LicensePayload)` produces **exactly one byte
representation per logical payload**. Rules (artifact version 1):

1. UTF-8, no BOM, no whitespace between tokens.
2. JSON object keys in fixed lexicographic (ordinal) order:
   `customerId, customerName, edition, expiresAt, featureSet, [installationId], issuedAt,
   licenseId, licenseVersion, limits, notBefore, productId, productName, sequenceNumber,
   status`.
3. GUIDs: lowercase hyphenated `"D"` form.
4. Timestamps: RFC 3339 UTC, fixed format `yyyy-MM-ddTHH:mm:ss.fffffffZ` (exactly seven
   fractional digits). Non-UTC offsets are converted to UTC before serialization.
5. Numbers: integers only; **floating point never appears** in the payload.
6. Strings: minimal JSON escaping (only what JSON mandates); non-ASCII preserved as UTF-8;
   no Unicode normalization (RFC 8785 practice).
7. `featureSet`: normalized (trimmed, invariant lower-case), de-duplicated, sorted
   ordinally — a *set*, not an ordered list.
8. `limits`: object with normalized, ordinally sorted keys; explicit `null` = "unlimited"
   and is preserved; absent limit = unconstrained.
9. Optional unset members (`installationId`) are omitted.

**Verification path.** The validator parses the payload into the strict schema model and
re-canonicalizes *the model*, then verifies the signature over those canonical bytes.
Consequences:

- Property order, whitespace and indentation of the transmitted JSON are irrelevant →
  semantically equal artifacts always verify.
- Any modification of any signed field yields different canonical bytes → signature fails.
- Because parsing is schema-complete (unknown fields rejected, no hidden defaults), the
  model→canonical mapping is injective for all practical purposes; verification cannot
  silently accept a modified payload.

Tests in `tests/.../Canonicalization/` prove determinism, order/whitespace independence,
stable dates/numbers/GUIDs and canonical-byte changes on any signed-field modification.

## 5. Installation Binding

- The payload may carry an `InstallationId`. Comparison against the current installation
  is ordinal, case-insensitive and whitespace-trimmed; a mismatch fails
  `WrongInstallation`. A license copied to another installation does not become valid.
- `InstallationId == null` means a *floating* (installation-independent) license; the
  identity provider is not consulted for it.
- Identity is supplied by **`IInstallationIdentityProvider`**. The library deliberately
  performs **no** hardware/OS fingerprinting. For production, SSP.Core provides a
  *protected* identity (e.g. a machine key sealed with DPAPI/TPM, persisted on first run
  and verified on startup). Fragile hardware fingerprints are not the security mechanism —
  the signature is; binding is a deployment-control measure.
- If the provider returns null/throws, validation fails closed
  (`Unknown` / `installation_identity_unavailable`) for installation-bound licenses.
- `StaticInstallationIdentityProvider` exists for explicit wiring and tests only.

## 6. Validation Pipeline

`LicenseValidator.Validate` — centralized, sequential, fail-fast, deterministic:

```text
load → parse → schema → signature → status/revocation → product → installation
     → not-before → expiration → anti-rollback → VALID
```

| Stage | Failure state | Reason code |
|---|---|---|
| parse / schema | `Malformed` | `malformed_artifact`, `invalid_payload_schema` |
| signature (support + verify) | `InvalidSignature` | `unsupported_signature_algorithm`, `invalid_signature` |
| status / revocation | `Revoked` | `revoked`, `revocation_check_failed` |
| product binding | `WrongProduct` | `wrong_product` |
| installation binding | `WrongInstallation` / `Unknown` | `wrong_installation`, `installation_identity_unavailable` |
| not-before (`now < NotBefore`, inclusive boundary passes) | `NotYetValid` | `not_yet_valid` |
| expiration (`now >= ExpiresAt`, exclusive) | `Expired` | `expired` |
| anti-rollback | `Superseded` | `superseded` |
| infrastructure errors (identity, store, revocation, unexpected) | `Unknown` | `installation_identity_unavailable`, `state_store_unavailable`, `revocation_check_failed`, `internal_error` |

No stage can succeed "by exception": every expected condition returns a structured
`LicenseValidationResult` (state + stable reason code + safe detail + untrusted decoded
license for diagnostics + security event). Exceptions are reserved for programmer errors
(null arguments, missing provider configuration). Time is taken from `IClock` (UTC only;
`ExpiresAt` is exclusive, `NotBefore` inclusive — boundary tested).

## 7. License States

`LicenseState` (enum, never magic integers/strings scattered around):
`Unknown, Valid, NotYetValid, Expired, InvalidSignature, Malformed, WrongProduct,
WrongInstallation, Revoked, LockedDown, Superseded`.

Two layers exist by design:

- **Validation layer** — `LicenseValidationResult.State` reports the precise license
  condition (e.g. `Expired`).
- **Runtime layer** — `LicenseManager.CurrentState` collapses to the operating posture:
  `Unknown` (nothing loaded) / `Valid` / `LockedDown` (a loaded artifact failed
  validation; all protected operations denied). The precise cause is always available via
  `LastValidationResult`.

## 8. Lockdown

Headless, **non-destructive** enforcement state.

```text
Unknown  ──(valid license)──►          Valid
Unknown  ──(invalid artifact)──►       LockedDown
Unknown  ──(no artifact)──►            Unknown        (operations denied)
Valid    ──(revalidation failure)──►   LockedDown
LockedDown ──(valid license)──►        Valid          (lockdown cleared)
LockedDown ──(license deleted)──►      LockedDown     (deletion never recovers)
```

Lockdown **denies** every protected operation (`Authorize` → deny + `ProtectedOperationDenied`
event), survives service restart by construction (a restarted process must revalidate; the
state store never grants), and is exited **only** by loading a cryptographically valid
license (`LicenseLockdownActivated` / `LicenseLockdownCleared` events mark transitions).

Lockdown **never** deletes files, corrupts data, modifies the OS or self-damages — verified
by `Invariant_LockdownIsNonDestructive` (files byte-identical before/after). Deleting the
license cannot clear lockdown; only revalidation with a valid artifact can.

## 9. Provider Abstraction

`ILicenseProvider` performs **transport only** — it never evaluates or authorizes.

| Provider | Status |
|---|---|
| `LocalLicenseFileProvider` | Implemented (file transport; missing/unreadable file → fail-closed `HasLicense=false`) |
| Online activation provider | Architecture-ready: implement `ILicenseProvider` (or call `LoadLicense(artifact)` with the activation response). HTTP/network details stay out of the validation core |
| Offline activation | Architecture-ready: authority issues the signed artifact out-of-band; the customer installs it as a file |

Absence and transport errors are indistinguishable from "no license" at the policy layer —
they authorize nothing.

## 10. Persistence Assumptions

- Persistence is isolated behind **`ILicenseStateStore`**.
- Two implementations ship:
  - **`InMemoryLicenseStateStore`** — the default, and the only state that persists for the
    lifetime of a single process. It is suitable for tests and for hosts that supply their
    own durable store.
  - **`FileLicenseStateStore`** — a BCL-only, durable, repository-local implementation that
    persists the anti-rollback floor to a file. Writes are atomic (write to a temp file,
    then move into place). **Reads fail closed**: a corrupt/unreadable/empty state file makes
    `Load()` throw, which the pipeline converts to `state_store_unavailable` and therefore
    denies — the floor can never be silently reset by a corrupted file.
- The store holds an anti-rollback floor (highest accepted sequence number) and diagnostics
  (last accepted license id, last validation time).
- **The store is not a security boundary.** It can only *restrict* (reject older sequences);
  it can never *grant* authorization. Poisoning it with "valid-looking" data is harmless —
  tested by `Invariant_ConfigurationCannotCreateAuthorization` and `PoisonedStateStore_...`.
- SSP.Core should still supply a tam-resistant implementation (e.g. a value sealed with DPAPI
  over TPM, or ACL-protected service storage) for the strongest anti-rollback; the library
  deliberately does not bake in the registry/config-file assumption of Windows.

## 11. Anti-Rollback Strategy

- Each license carries a monotonic `SequenceNumber` (per product/customer issuance order).
- On successful validation the manager persists the highest accepted sequence.
- A license whose sequence is *lower* than the floor is rejected as `Superseded`; equal or
  higher is accepted (idempotent re-validation of the same license works).
- **The floor is re-checked atomically under the manager lock at apply time**, in addition to
  the validator's own check. This closes the race where two concurrent validations could
  otherwise install an older license as *current* after a newer one had already persisted its
  floor (covered by `ConcurrencyTests`). Otherwise a lower-sequence license validated against
  a stale floor could briefly become current.
- **Documented security assumption:** the floor is only as strong as the state store. A
  local attacker who can wipe protected storage resets the floor; the worst case is
  re-enabling an *older, previously legitimately accepted* license — never an unsigned one.
  Full protection against coordinated rollback requires tam-resistant storage (TPM-backed)
  and/or online status checking (§12).

## 11a. Concurrency Semantics

`LicenseManager` is thread-safe and is designed for a service that may validate, replace or
authorize concurrently.

- **Authorization is atomic.** `Authorize` takes the state snapshot and evaluates
  `ILicensePolicy` under the *same* lock that governs state transitions, so a concurrent
  license invalidation (Valid → LockedDown) can never be observed as a present authorization.
  A policy that throws is treated as a denial (never fail-open).
- **License replacement is serialized.** `Load`/`LoadLicense`/`Revalidate` apply their result
  under a single lock; the anti-rollback floor is read and written under that same lock, so
  concurrent validations cannot interleave a lower sequence past the floor.
- **`ILicensePolicy.Evaluate` must be fast and non-blocking** — it runs while the manager lock
  is held. The default policy performs no I/O.
- Validation/cryptography runs *outside* the lock, so a slow RSA verification does not stall
  concurrent authorizations longer than necessary; only the state transition is serialized.

## 12. Revocation Strategy

Two complementary mechanisms, extensible without redesign:

1. **Signed status** — `Status` is part of the signed payload; the authority re-issues a
   license with `Status = revoked` (or customers install a superseding license).
2. **`ILicenseRevocationChecker`** — consulted after signature verification (only authentic
   payloads reach it). Future implementations: signed CRL-style revocation lists, online
   status endpoints, cached server verdicts. A failing checker fails closed
   (`revocation_check_failed`).

## 13. Future SSP.Core Integration

SSP.Core needs to know nothing about canonicalization, signatures, codec or parsing:

```csharp
// Composition (once, at startup):
var trustAnchor = LicenseTrustAnchor.FromPem(SspAuthorityPublicKeyPem);   // public key only
var identity    = new SspInstallationIdentityProvider();                   // SSP's protected identity
var manager     = new LicenseManager(
    new LicenseValidationOptions(SspProductId), trustAnchor, identity,
    licenseProvider: new LocalLicenseFileProvider(licensePath),
    eventSink: sspSecurityLog, stateStore: sspProtectedStore);

manager.Load();                                                            // or LoadLicense(activationResponse)

// Enforcement boundary (everywhere in SSP.Core):
ILicenseEnforcement enforcement = new LicenseEnforcement(manager);
if (!enforcement.CanUseFeature("rdp").IsAllowed)   /* deny */;
if (!enforcement.CanCreateSession(activeSessions).IsAllowed) /* deny */;
if (!enforcement.CanStartProtectedService(running).IsAllowed) /* deny */;

// Periodic / on-demand:
manager.Revalidate();                                                      // expiry, revocation, rollback
```

Interfaces consumed by SSP.Core: `ILicenseManager`, `ILicenseEnforcement`, `ILicensePolicy`,
plus the injectable boundaries `IClock`, `IInstallationIdentityProvider`,
`ILicenseProvider`, `ILicenseStateStore`, `ISecurityEventSink`, `ILicenseRevocationChecker`.

## 14. Security Assumptions

1. The authority private key is protected (HSM/vault) and never reaches customer hosts.
2. The trust anchor public key is delivered to SSP.Core through a build/deployment channel
   that SSP trusts (it is a deployment constant, not user configuration).
3. `ExpectedProductId` is a build/deployment constant — configuration cannot redefine which
   product's licenses are acceptable.
4. Hosts run SSP.Core inside a process they control; memory-inspection/debugger bypasses of
   a .NET application are out of scope for a software-only licensing layer.
5. The state store is tam-resistant but not the root of trust; the signature is.
6. Event sinks are trusted local log targets; event payloads contain no secrets.
7. The system clock is host-controlled; anti-rollback (§11) and online checks mitigate,
   not eliminate, clock manipulation for air-gapped deployments.

## 15. Known Limitations

- **No key rotation / KeyId** — the artifact schema reserves room (`signatureAlgorithm`,
  versionable envelope) but multiple simultaneous trust anchors are not yet implemented.
- **No online provider implementation** — abstraction only (per scope); HTTP, retry and
  activation-protocol concerns are left to the future SSP integration.
- **Durable anti-rollback ships as a plain file store** — `FileLicenseStateStore` persists the
  floor on the local file system; it is *not* tamper-resistant. Strongest rollback protection
  requires a host-supplied DPAPI/TPM-protected store (§10).
- **Artifact and license-file size are bounded.** `LicenseArtifactCodec` rejects artifacts
  larger than `MaxArtifactCharacters` (256 KiB) and `LocalLicenseFileProvider` refuses to read
  an oversized license file, both fail-closed. This prevents a malicious artifact from being
  an easy CPU/memory exhaustion vector.
- **No license-file confidentiality** — artifacts are signed, not encrypted; payload fields
  (customer name, features) are readable by anyone holding the file. Confidentiality can be
  added at the transport/envelope layer without touching validation.
- **Clock manipulation** is only partially mitigable offline (§11, §14.7).
- **Feature/limit vocabularies are host conventions** — the library validates shape and
  normalization, not product semantics; SSP.Core decides what "rdp" means.
- Lockdown is process-level: it gates SSP.Core's calls through this API; SSP.Core must
  actually consult the enforcement API before each protected operation (integration
  contract, enforced by tests at the licensing boundary only).
