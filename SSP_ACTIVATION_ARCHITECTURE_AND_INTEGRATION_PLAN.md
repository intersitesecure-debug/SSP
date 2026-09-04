# SSP — Activation Integration Architecture (Evidence-Based, v2)

**Document:** `SSP_ACTIVATION_ARCHITECTURE_AND_INTEGRATION_PLAN.md` (v2 — supersedes the v1 provisional analysis)
**Mode:** READ-ONLY architecture & integration analysis. No source created/modified/deleted. No git state-changing operations performed. No implementation patches produced.
**Date:** 2026-08-31
**Analyst role:** Senior Software Architect / Security Architect

---

## 0. Verification Protocol and Repository State (answers the mandatory first step)

**`_reference/SSP.Activation` is present and verified — inside the git object store, on `main`, at commit `a599f90ab49ae7774afe56e1d46a82f0983a180e` ("Add SSP.Activation reference implementation", authored 2026-08-31 by intersitesecure-debug), parent `1ae920f9f71736140b2adcbacc2c06fc2085b4e7`.**

The working tree of this session's branch (`arena/01a05920-ssp`, still at `1ae920f`) does **not** have `_reference/` checked out, and the task rules forbid `git checkout` / creating source files. Therefore the reference was audited **directly from the commit content** using read-only plumbing (`git show a599f90:<path>`, `git ls-tree`, `git diff`, `git grep`). No state was modified by these commands.

Definitive scope of commit `a599f90` (from `git diff --name-status 1ae920f a599f90`):

- **70 files changed, 6,756 insertions, all additions, ALL under `_reference/`.**
- **Zero changes outside `_reference/`** — the SSP production tree (`src/`, `tests/`, `SSP.sln`, `.gitignore`) is byte-identical between the two commits. Every SSP-side finding in the v1 report (full source read of all 37 production `.cs` files) therefore still stands verbatim and needs no re-derivation; this v2 focuses on the reference and the integration.

Reference inventory (`git ls-tree -r a599f90 -- _reference`): 68 files =
`README.md`, `docs/ARCHITECTURE.md` (363 lines), `docs/SECURITY_AUDIT_REPORT.md` (230 lines), `SSP.Activation.sln`, two `.gitignore`, library `src/SSP.Activation/` (25 files), tests `tests/SSP.Activation.Tests/` (14 test files + 7 TestSupport files + csproj).

Build caveat that governs everything below: the reference's own `SECURITY_AUDIT_REPORT.md` states **the code was never compiled or tested** (no .NET 8 SDK in the author's sandbox), and this sandbox has no .NET SDK either (`dotnet` absent). The library is delivered with `TreatWarningsAsErrors=true`. **"Reuse unchanged" verdicts below therefore mean "architecturally cleared for verbatim vendoring, gated on a first compile+test pass"** — formalized as Phase 0 in IMPLEMENTATION READINESS §7.

---

## 1. Executive Summary

- The reference is a **genuinely well-built, fail-closed, BCL-only licensing subsystem** (net8.0, zero NuGet deps; verified `grep`: no networking, no process spawning, no environment/config reads, no registry, no reflection — only `System.Buffers/Globalization/Security.Cryptography/Text.Json/Text`). Its own audit found and fixed the two races (authorization TOCTOU; anti-rollback apply race) that typically sink licensing libraries.
- It was **designed for exactly this integration**: its docs repeatedly say the host (SSP) must supply the trust anchor, a *protected* installation identity, a *tam-resistant* (DPAPI/TPM) state store, a real event sink, and the enforcement call sites. Those four host-supplied pieces plus the call-site glue are precisely the only new code SSP needs.
- **Verdict in one paragraph:** vendor the library verbatim as `src/SSP.Activation` (do **not** project-reference `_reference/`, and do **not** dissolve it into SSP.Core); put **all** SSP-specific integration — MachineGuid identity, DPAPI-backed state store, security-event sink, paths, trust-anchor constant, composition root, CLI, and the enforcement glue — into `SSP.Server` (plus 1 additive protected-name line in `SSP.Core` and a tiny constants file); add an authority-only tool `tools/SSP.LicenseAuthority` that alone uses `LicenseIssuer` with a private key and is never shipped; enforce at four server-side control-plane seams (setup, service start, enrollment, future-authorization/tunnel establishment) with a periodic revalidation timer; keep the client, the wire protocol, all crypto, the tunnel, the patch-slot mechanism, and the service-start contract byte-identical; adopt the reference artifact format (`ssp-license` v1, RSA-PSS-SHA256) **unchanged**; port all 21 reference test files plus new SSP integration tests; preserve every existing SSP test by keeping enforcement active only when a trust anchor is compiled in (development builds without an anchor run a loudly-logged unmanaged mode).
- **The dev-mode seam is the price of never breaking the 33 existing suites** — it sits in SSP's composition root (never in the library) and is documented as a build-time trust decision.

---

## 2. SSP-Side Audit Status (delta from v1)

Verified by `git diff 1ae920f a599f90 -- src tests SSP.sln .gitignore` → **empty**. The complete v1 audit stands; the facts the integration depends on:

| Fact (evidence) | Integration consequence |
|---|---|
| `SSP.Core`: `RsaCrypto` (RSA-3072/SHA-256/PKCS#1 sign+verify, OAEP wrap, PEM/SPKI helpers), `AesGcmCrypto`, `TokenGenerator`, `ProtectedFileStore` (envelope `SSP-EAR1`, DPAPI LocalMachine, protected names hardcoded to `.cache.dat/.sysdata.bin/.runtime.dat/.index.dat`, fail-closed envelope, plaintext auto-migration), `AtomicFile`, `ServiceConfigFileLock`, `ClientInstallPaths` | The DPAPI state store rides `ProtectedFileStore` with **one additive name**; licensing crypto stays inside the licensing assembly and never shares code paths with tunnel/enrollment crypto |
| `SSP.Server/Program.cs`: `--service` fast path must run **nothing fallible** before `ServiceBase.Run` (ERROR 1053 contract); `RunServiceModeAsync` loads config+keys then constructs `ServerGateway`; System.CommandLine root already exists | Start gate goes **inside** `SspWindowsService.OnStart` and `RunServiceModeAsync` (both already inside the failible region with `ServiceDiagnostics` → diagnosed ERROR 1064); license CLI plugs into the existing root command |
| `SetupEngine.RunAsync` routes new-app vs additional-client on disk state; throws `ArgumentException`/`InvalidOperationException` for denials; used by Server, ServiceBuilder, and many tests | Activation denials use the exact same exception pattern; provisioning limits count `.index.dat` in the additional-client path |
| `ServerGateway(config, rsa, pubPem, serviceDir)` ctor — **48 call sites** (mostly tests, via `SspTestHarness` and `ServiceStartRegressionTests`); `HandleClientAsync` → `ServerProtocol.HandleAsync` → session key → eager bridge to `127.0.0.1:LocalApplicationPort` | Gateway gains an **optional** activation parameter (source-compatible with all 48 sites); it tracks an active-tunnel counter and hosts the revalidation timer |
| `ServerProtocol` is constructed **only** in `ServerGateway.HandleClientAsync` (verified: no other `new ServerProtocol(`) | Its handler methods can receive the enforcement context non-optionally — no external callers break |
| Enrollment (`HandleEnrollmentLockedAsync`) runs under per-service semaphore + `ServiceConfigFileLock`, reloads `.cache.dat` under lock; failures throw before/without consuming the OTT; client-visible failure text only via existing `EnrollmentResult.ErrorOrWait` / `AuthorizationOutcome.Message` strings | Enrollment gate reuses the same lock region, reloads `.index.dat` for the `max_clients` count, and denies with an existing outcome message — **no protocol change** |
| Future auth (`HandleFutureAuthorizationAsync`) loads `.index.dat`, verifies challenge signature, then requires `SessionKeyOffer` | Gate placed before honoring the identity check; deny path already exists (`SendOutcomeAsync(false,…)` + throw) |
| `SspTestHarness.CreateAsync` etc. construct `ServerGateway(config, rsa, pubPem, serviceDir)` with no license material | Unmanaged-development mode (no compiled anchor ⇒ loud allow) keeps all 33 suites green **without touching a single existing test file** |

---

## 3. `_reference/SSP.Activation` — Complete File-by-File Audit

Every production file was read in full; every test file was read or fully inventoried (bodies of the security-critical ones — invariants, concurrency, configuration-bypass, lockdown, signature verification, time-boundary — read verbatim).

### 3.1 Documentation

| File | Content | Assessment |
|---|---|---|
| `README.md` | Prime invariant ("without a cryptographically valid license… protected SSP functionality must not become operational"), quick-start already aimed at "future SSP.Core integration", authority-side issuing sample, public API table | Honest; integration example literally shows `FileLicenseStateStore` + `StaticInstallationIdentityProvider` with comments *"replace with SSP's protected provider"* |
| `docs/ARCHITECTURE.md` | Trust model, explicit **authority/customer boundary table**, artifact format, algorithm evaluation (RSA-PSS-SHA256 chosen over Ed25519/ECDSA for FIPS + legacy Windows Server CNG), canonicalization rules, installation binding, 6-stage validation pipeline, state list, lockdown semantics, provider abstraction, persistence assumptions, anti-rollback + **§11a concurrency semantics**, revocation, integration sketch, **§14 security assumptions, §15 known limitations (no key rotation/kid, no online provider, file store not tamper-resistant, no artifact confidentiality, clock manipulation only partially mitigable, feature vocabularies are host conventions, lockdown is process-level)** | Unusually candid; the limitations section defines exactly the work SSP must do |
| `docs/SECURITY_AUDIT_REPORT.md` | Audit of the reference itself: fixed Critical anti-rollback race, High authorization TOCTOU, High failing-open policy exceptions, Medium resource exhaustion, Medium durable anti-rollback; ~178 test cases claimed; **build/tests never executed** (no SDK) | Findings are credible and consistent with the code I read; the never-compiled disclaimer drives Phase 0 |

### 3.2 Production source (`src/SSP.Activation/`, 25 files)

| File | Purpose (as read) | Security role | Limitations/assumptions observed | Verdict (§A–§D detail in §7) |
|---|---|---|---|---|
| `Abstractions/IClock.cs` | `IClock.UtcNow` + `SystemClock` singleton | Testable time | none | **Reuse unchanged** |
| `Abstractions/IInstallationIdentityProvider.cs` | `GetInstallationId(): string?`; null ⇒ validation fails closed | Host-supplied identity port | library does no fingerprinting by design | **Reuse unchanged (interface)** |
| `Abstractions/ILicenseEnforcement.cs` | `CanStartProtectedService/CanEstablishTunnel/CanCreateSession/CanUseFeature/CheckLimit/RequireValidLicense` → `AuthorizationDecision` | Headless enforcement API | usage counts host-supplied | **Reuse unchanged** |
| `Abstractions/ILicenseManager.cs` | `CurrentState/LastValidationResult/CurrentLicense/Load/LoadLicense/Revalidate/Authorize`; thread-safe contract | Core runtime API | none | **Reuse unchanged** |
| `Abstractions/ILicensePolicy.cs` | `Evaluate(LicenseEvaluationContext)` | Policy decision point | must be fast/no I/O (runs under manager lock — §11a) | **Reuse unchanged** |
| `Abstractions/ILicenseProvider.cs` | `FetchLicense()` + `LicenseFetchResult` (FromArtifact/Empty/Error) | Transport-only port | absence ≡ error ≡ "no license" (fail closed) | **Reuse unchanged** |
| `Abstractions/ILicenseRevocationChecker.cs` | `Check(payload)` post-signature only; checker exceptions fail closed (`revocation_check_failed`) | Revocation port | no shipped implementation (null checker default) | **Reuse unchanged (seam kept, not wired)** |
| `Abstractions/ILicenseStateStore.cs` | `Load()/Save(LicenseStateRecord)`; documented *restricts-only, never grants* | Anti-rollback persistence port | impl must be tam-resistant | **Reuse unchanged (interface)** |
| `Abstractions/ISecurityEventSink.cs` | `Report(LicenseSecurityEvent)`; impls must not throw | Audit port | none | **Reuse unchanged** |
| `Canonicalization/LicenseCanonicalJson.cs` | Deterministic canonical payload bytes: fixed ordinal key order (`customerId…status`), UTF-8 no-BOM no-whitespace, GUID "D" lowercase, RFC3339 `yyyy-MM-ddTHH:mm:ss.fffffffZ` (UTC-normalized), integers only, minimal escaping, featureSet normalized/deduped/sorted, limits sorted with explicit-null=unlimited, `installationId` omitted when unset | The signed-bytes definition | none found; matches its spec | **Reuse unchanged** |
| `Crypto/LicenseTrustAnchor.cs` | Single RSA public key anchor; SPKI DER / PEM ("PUBLIC KEY" label only) / RSA copy import; **≥2048 enforced**; trailing-data rejected; `Verify` = SHA256+PSS; IDisposable | Root of trust holder | single anchor (no kid) — §15 known limitation | **Reuse unchanged** |
| `Crypto/SignatureAlgorithms.cs` | Allow-list registry: exactly `"RSA-PSS-SHA256"`; `Sign` enforces ≥2048; internal sign/verify | Algorithm agility firewall | none | **Reuse unchanged** |
| `Serialization/Base64Url.cs` | Strict RFC4648§5 codec (rejects `+ / =`, whitespace; canonical length rules) | Envelope encoding hygiene | internal | **Reuse unchanged** |
| `Serialization/ArtifactDecodeError.cs` | Decode error taxonomy (10 codes) | Structured fail-closed parsing | none | **Reuse unchanged** |
| `Serialization/LicenseArtifactCodec.cs` (616 lines) | Envelope `{format:"ssp-license", artifactVersion:1, signatureAlgorithm, payload(b64url canonical JSON), signature(b64url)}`; `Encode` re-canonicalizes payload itself; `TryDecode` never throws: **256 KiB cap**, JSON MaxDepth 16, no comments/trailing commas, duplicate-field detection (envelope, payload, limits), unknown fields rejected, strict types, GUID "D" exact, string length caps, `notBefore≤expiresAt`, `issuedAt≤notBefore`, status active/revoked, optional non-negative `sequenceNumber` (default 0) | Untrusted-input boundary | none found | **Reuse unchanged** |
| `Validation/LicenseValidationOptions.cs` | `ExpectedProductId` (non-empty Guid) — "build/deployment constant, never user config" | Product binding config | host must hard-code | **Reuse unchanged** |
| `Validation/LicenseValidator.cs` | 6-stage pipeline with explicit states/reasons at every stage; `Validate(null)`→Unknown/missing; decode error→Malformed; alg unsupported→InvalidSignature/`unsupported_signature_algorithm`; canonicalize-then-verify →`invalid_signature`; payload `Status=revoked`→Revoked; revocation checker (throw→`revocation_check_failed` Unknown); wrong product→WrongProduct; `InstallationId` present → provider consulted (throw/empty→Unknown `installation_identity_unavailable`; mismatch→WrongInstallation; comparison ordinal-ignore-case trimmed); `now<NotBefore`→NotYetValid; `now≥ExpiresAt`→Expired; store read throw→Unknown `state_store_unavailable`; `sequence<floor`→Superseded; else Valid; emits events at every terminal stage; valid result carries `License`; failures carry untrusted `License` for diagnostics only | The validation engine | stateless aside from reading floor; suitable for standalone tooling use | **Reuse unchanged** |
| `LicenseManager.cs` (396 lines) | Composition root + runtime state machine (Unknown/Valid/LockedDown); `Authorize` takes snapshot **and evaluates policy under the same lock** (throwing policy → deny, never propagates); lock-free volatile snapshot readers (documented deadlock avoidance); `Apply` serializes transitions and **re-checks the anti-rollback floor atomically under the lock**; `PersistAcceptedSequence` best-effort (store write failure doesn't block a validated license — "signature is root of trust"); Load with missing artifact keeps/enters Unknown but **never clears Lockdown**; invalid artifact enters Lockdown; deletion never recovers | Thread-safe runtime authority | note: Apply's defensive floor re-check fails closed on store read failure (validator path is also fail-closed); dwell on in §8 | **Reuse unchanged** |
| `LicenseIssuer.cs` | Static `EncodeLicenseArtifact(payload, RSA privateKey, alg?)`; bring-your-own-key; never retains key | Authority-side signing | co-located in runtime assembly (audit Low: optional future split) | **Reuse unchanged; authority boundary in §N** |
| `Models/*` (13 files) | `LicensePayload` (LicenseId/ProductId/ProductName/CustomerId/CustomerName/Edition/LicenseVersion/IssuedAt/NotBefore/ExpiresAt/InstallationId?/FeatureSet/Limits/Status/SequenceNumber), `License`, `LicenseArtifact`, `LicenseState` (11 members), `LicenseStatus`, `LicenseStateRecord` (HighestAcceptedSequenceNumber/LastAcceptedLicenseId/LastValidatedUtc), `LicenseReasons` (22 stable codes), `LicenseLimitNames` (`max_services`, `max_clients`, `max_sessions`, `max_concurrent_sessions`, `max_concurrent_tunnels`), `LicenseFeatureSet` (normalize/dedupe/sort, ≤64 chars, no whitespace), `LicenseLimits` (sorted, null=unlimited, absent=unconstrained), `ProtectedOperation` (UseFeature/StartProtectedService/EstablishTunnel/CreateSession/CheckLimit; usage measured **before** grant), `AuthorizationDecision`, `LicenseEvaluationContext`, `LicenseValidationResult`, `LicenseSecurityEvent`(+11 event types) | The contract surface | schema has **no grace, no kid** — frozen; see §J | **Reuse unchanged** |
| `Enforcement/DefaultLicensePolicy.cs` | Fail-closed: only Valid state + covered operation allows; unknown kinds denied; invalid feature/limit names denied; negative usage denied; absent/null limits unconstrained | Reference policy | evaluate runs under lock — SSP custom policies must be I/O-free | **Reuse unchanged** |
| `Enforcement/LicenseEnforcement.cs` | Facade routing the 5 operations to `manager.Authorize` | Call-site convenience | none | **Reuse unchanged** |
| `Providers/LocalLicenseFileProvider.cs` | File transport; missing→Empty; unreadable→Error (never throws); oversized (file length > 256 KiB cap)→Error | Artifact transport | none | **Reuse unchanged** |
| `Identity/StaticInstallationIdentityProvider.cs` | Fixed-id provider | tests/explicit wiring | not for production identity | **Reuse unchanged — test wiring only (§D)** |
| `Events/InMemorySecurityEventSink.cs`, `Events/NullSecurityEventSink.cs` | In-memory sink (thread-safe snapshot/clear); discarding sink | event plumbing | production must wire a persistent sink | **Reuse unchanged (sink impls); SSP supplies production sink (§C)** |
| `Persistence/InMemoryLicenseStateStore.cs` | In-memory floor store | test default | not durable | **Reuse unchanged — tests only (§D)** |
| `Persistence/FileLicenseStateStore.cs` | JSON file store; atomic temp+move writes; **fail-closed reads** (corrupt/empty/unreadable → throw → `state_store_unavailable`) | durable floor (repository default) | **plaintext, FS-permission-only; not tamper-resistant (its own docblock + audit §9)** | **Not wired in production — superseded by SSP's DPAPI store (§D/§M)** |
| `SSP.Activation.csproj` | net8.0, nullable, LangVersion latest, **TreatWarningsAsErrors=true**, zero PackageReferences | build config | compile gate pending | **Reuse (near-)unchanged** |

### 3.3 Test suite (`tests/SSP.Activation.Tests/`, 14 test files + 7 support files)

| File | Cases (read/inventoried) | Why it matters for SSP |
|---|---|---|
| `Security/SecurityInvariantTests.cs` | **9 named invariants**: no-license⇒no operation; signed-field tamper⇒InvalidSignature+LockedDown (entire artifact rejected incl. originally-licensed features); wrong key⇒reject; configuration/env/poisoned-store cannot authorize; restart requires revalidation (fresh manager denies even with valid file on disk until revalidated); deletion⇒Unknown deny-all; old-license-after-newer⇒Superseded+LockedDown; lockdown non-destructive (files byte-identical); valid replacement recovers then re-locks on invalid | These become SSP's acceptance floor — run them unchanged against the vendored copy |
| `Security/ConcurrencyTests.cs` | 100-iteration concurrent low/high sequence loads (current never below floor); authorize atomicity vs concurrent invalidation (blocking policy + gates); throwing policy ⇒ deny + `ProtectedOperationDenied` event | Proves the two races the audit fixed stay fixed after vendoring |
| `Security/ConfigurationBypassTests.cs` | env var claiming licensed; config file claiming licensed; replacing license file with config; poisoned state store; deleting config directory — none can authorize | Directly addresses SSP question "configuration bypass" |
| `Lockdown/LockdownTests.cs` | lockdown activation/denial semantics, single transition event, clock-driven expiry lockdown via `Revalidate`, restart revalidation requirement, clear-only-with-valid-license, re-lockdown, deletion-never-recovers | Lockdown contract SSP inherits |
| `Crypto/SignatureVerificationTests.cs` | valid accept; payload tamper reject; signature flip reject; wrong key reject; unsupported alg reject; **unknown alg + valid signature still rejected** (proves fail-closed alg firewall); missing/truncated/random-length-correct signatures reject; reformatted payload still verifies (canonicalization semantics) | The crypto contract in executable form |
| `Crypto/TrustAnchorTests.cs` | undersized/null/wrong-label/non-RSA reject; PEM round-trip | Anchor hardening proof |
| `Canonicalization/CanonicalJsonTests.cs` (15) | determinism, key order, optional omission, explicit-null limits preserved, 7-digit RFC3339 UTC, integer stability, GUID form, no whitespace, property-order/whitespace independence, any signed-field mutation changes canonical bytes | Canonicalization is *proven*, not asserted |
| `Enforcement/PolicyAndEnforcementTests.cs` (14) | licensed/unlicensed/unknown feature cases, case-insensitivity, invalid names denied, empty set denies all, limit within/exceeded/unlimited/absent, negative usage denied, facade routes all 5 ops, custom policy consulted, denied ops emit events | Enforcement vocabulary SSP will call |
| `Identity/InstallationBindingTests.cs` (6) | bound-match valid; copied-to-other-installation rejected; case/whitespace-insensitive compare; **unbound (floating) license accepted on any installation**; identity unavailable/throwing ⇒ fail closed | Defines exactly what SSP's identity provider must satisfy |
| `Persistence/FileLicenseStateStoreTests.cs` (6) | fresh=null; round-trip; cross-instance persistence; **corrupt/empty fail closed**; creates parent dir | Reference floor-store behavior (SSP's DPAPI store must match this contract — fail-closed reads) |
| `Providers/LocalLicenseFileProviderTests.cs` (7) | present/missing/unreadable/oversized/empty semantics; integration: valid file ⇒ Valid; on-disk update picked up on next `Load()` | The on-disk-update test is what makes `--install-license` usable without restart semantics guesswork |
| `Security/SecurityEventTests.cs` (9) | event types per outcome; lockdown transition events; **events never contain `signature`/`BEGIN`/`PRIVATE` material** | Event hygiene gate for SSP's sink |
| `Serialization/LicenseArtifactCodecTests.cs` (~20) | round-trip; null/malformed/oversized; duplicate/unknown/missing envelope & payload fields; bad version/alg/encoding; payload schema violations; inverted time window; issued>notBefore | Strictness surface of the artifact parser |
| `Validation/LicenseValidatorTests.cs` (~17) | full pipeline table incl. **expiry exclusive at exactly ExpiresAt / NotBefore inclusive at exactly NotBefore** (±1 tick), revocation checker paths, anti-rollback (older/equal/no-floor), store-throw fail-closed, failed validation exposes untrusted payload for diagnostics but is not trusted | Boundary semantics for §O answers |
| `TestSupport/*` (7) | `TestAuthority` (ephemeral RSA-2048 authority), `LicensePayloadFactory` (fixed base time 2030-01-01 ⇒ deterministic), `ArtifactTestHelper` (raw JSON mutation tooling), `FixedClock`, `TestPaths` (temp under `AppContext.BaseDirectory/test-tmp`), `ValidatorFactory` (default id `INSTALLATION-A`), `TestLicenseSystem` (pre-wired manager) | The entire harness ports; `TestAuthority` doubles as the pattern for authority-side tests of SSP's tool |

---

## 4. Reference Architecture As Found (condensed, evidence-referenced)

- **Trust model**: private RSA key lives only at the Licensing Authority; relying party holds a single immutable `LicenseTrustAnchor` (public, ≥2048). Authorization derives *exclusively* from signature verification + policy; "configuration, environment, registry, UI or persistence can never create authorization — the state store can only restrict it" (ARCHITECTURE §1).
- **Artifact**: strict JSON envelope `ssp-license` v1; payload = base64url of canonical JSON; signature over canonical bytes; strict fail-closed decode (§3.2 codec).
- **Crypto**: RSA-PSS-SHA256 only; FIPS-motivated; allow-list registry; unknown algorithm never verifies even with a valid signature (test `UnknownAlgorithmWithValidSignature_IsStillRejected`).
- **Pipeline**: load → parse → schema → signature → status/revocation → product → installation → not-before → expiration → anti-rollback → VALID; structured `LicenseValidationResult` per stage; no fail-open exception paths.
- **Runtime**: `LicenseManager` state machine Unknown/Valid/LockedDown; lockdown sticky and non-destructive, cleared only by a valid artifact; deletion of the license never recovers a lockdown; restart requires revalidation.
- **Concurrency**: single gate serializes transitions; `Authorize` atomic under that gate; RSA verification runs outside the gate; volatile immutable snapshot for lock-free reads.
- **Self-declared gaps (§15)**: no multi-anchor/key-id rotation; no online provider; default durable store is plaintext-file; artifacts not encrypted; clock manipulation only partially mitigable offline; lockdown is process-level and only as strong as the host's consultation discipline.

---

## 5. Compatibility Analysis (evidence vs SSP)

| Axis | Reference fact | SSP fact | Fit |
|---|---|---|---|
| Dependencies | zero (BCL only — verified) | Core has exactly 1 package (ProtectedData); Server 2 more | Perfect — adds nothing to the supply chain |
| Wiring style | explicit constructor composition, statics; **no DI container** | same | Perfect |
| Threading | designed/audited for a Windows-Service process (§11a) | gateway spawns per-connection tasks | Perfect |
| Test stack | xunit 2.5.3 / Test SDK 17.8.0 / coverlet 6.0.0 | **identical versions** | Vendored tests drop in |
| Crypto overlap | RSA-PSS-SHA256 inside licensing boundary only | RSA-PKCS#1/SHA-256 in enrollment/tunnel boundary | Disjoint by design — **no algorithm unification needed or desirable** |
| Persistence | expects host DPAPI/TPM store for production (audit §9/§12.3) | `ProtectedFileStore` provides exactly DPAPI LocalMachine envelopes | SSP writes one ~70-line adapter |
| Identity | expects host provider (no fingerprinting in library) | SSP has no machine identity today | SSP writes one ~40-line provider |
| Lifetime | manager = long-lived, `Revalidate()` periodic hook, `Authorize` fast per-op check | `SspWindowsService`/`ServerGateway` are long-lived | Map 1:1 |
| Protocol | none (no wire format) | enrollment/future-auth protocol frozen | No contact |

---

## 6. DECISIONS (the architecture)

### E. Final activation architecture inside SSP

```
tools/SSP.LicenseAuthority (NEW; internal-only, never shipped)
   keygen / issue / renew / inspect ──uses──► LicenseIssuer (bring-your-own RSA-3072 key)

CUSTOMER SHIP (server side only):
src/SSP.Activation                 ← vendored VERBATIM from _reference (namespace SSP.Activation)
src/SSP.Core/Activation/           ← 1 NEW constants file (SspLicensing: ProductId, feature/limit doc)
src/SSP.Core/IO/ProtectedFileStore ← +1 additive protected name ".license-state.dat" (only Core edit)
src/SSP.Server/Activation/         ← ALL SSP-specific integration:
   SspTrustAnchor.cs        (compiled production anchor constant + dev detection)
   SspActivationService.cs  (composition root & lifetime owner; injectable IClock for tests)
   SspInstallationIdentityProvider.cs (MachineGuid → SHA-256 hex)
   SspLicenseStateStore.cs  (ILicenseStateStore over ProtectedFileStore)
   SspSecurityEventSink.cs  (ISecurityEventSink → console + ServiceDiagnostics/EventLog)
   SspLicensePaths.cs       (canonical licensing dir + SSP_LICENSE_ROOT test seam)
   ActivationGate.cs        (the EP0..EP3 glue mapped to LicenseEnforcement calls)
src/SSP.Server                     ← 4 surgical edits: Program.cs (CLI), SspWindowsService.cs (start gate),
                                     ServerGateway.cs (context + timer + tunnel counter),
                                     ServerProtocol.cs (2 control-plane guards)
```

### F. Where activation lives — decided

**A combination**, and *not* where the reference docs casually suggest ("into SSP.Core"): in this repository's actual layout, `SSP.Core` is consumed by the **client** too. Anything placed in (or referenced by) Core lands inside every `SSP.Client.exe`. The licensed *value* lives on the server; the client must carry zero licensing code. Therefore:

- The **vendored library is its own project** `src/SSP.Activation` — referenced by `SSP.Server`, `SSP.Tests`, and the authority tool only. Vendoring (verbatim copy) instead of project-referencing `_reference/` keeps the product build independent of the reference drop and keeps `_reference/` pristine for diffing against future reference updates.
- `SSP.Core` gets **only**: one additive protected-file name (the DPAPI gate must stay single — previous-report principle, now confirmed as the reference's own §10 recommendation) and a constants file. No dependency edge is added to Core.
- All integration code lives in `SSP.Server` — every enforcement seam (SetupEngine, service start, gateway, protocol) is already there.
- **Not** merged into Core; **not** a runtime project referenced by Client; ServiceHost inherits enforcement transitively through `SSP.Server.Program.Main`.

### The preservation seam (why existing tests never break)

The library itself is unconditionally fail-closed — that stays untouched. SSP's **composition root** decides enforcement activation: when SSP is built **without a compiled production trust anchor** (this repo's dev/test builds), `SspActivationService` runs in *unmanaged-development* mode: the gates allow, and exactly one clearly-marked security event + console line is emitted at startup. When an anchor constant is present (production release), enforcement is unconditional. All 48 `ServerGateway` call sites and all 33 existing suites keep passing with **zero test-file edits**, while new anchored-mode integration tests prove the gates fire. This mirrors SSP's existing test-seam philosophy (`SSP_CLIENT_ROOT`, `SSP_AUTHCODE_DIR`, `SSP_SERVICE_HOST_IMAGE`, `SSP_SKIP_EMBED`) and is recorded as a deliberate build-time trust decision in the threat model.

---

## 7. Component Decisions (answers A–D)

### A. Reused unchanged (verbatim vendored, pending Phase-0 compile gate)

All `Abstractions/` (9 files) · `Canonicalization/LicenseCanonicalJson.cs` · `Crypto/LicenseTrustAnchor.cs` + `SignatureAlgorithms.cs` · `Serialization/` (3 files) · `Validation/` (2 files) · `LicenseManager.cs` · all 13 `Models/` files · `Enforcement/` (2 files) · `Providers/LocalLicenseFileProvider.cs` · `Events/` (2 files) · `LicenseIssuer.cs` (usage restricted per §N) · `Persistence/InMemoryLicenseStateStore.cs` (tests) · `.csproj` (near-verbatim) · **all 21 test/support files** (namespace-preserved `SSP.Activation.Tests.*` inside `tests/SSP.Tests/Activation/`).

Evidence basis: each file's role listed in §3.2; invariants/concurrency/strictness are test-proven (§3.3).

### B. Requiring adaptation — realized as *substitution at composition time*, not file edits

| Component | Adaptation |
|---|---|
| `IInstallationIdentityProvider` | satisfied by NEW `SspInstallationIdentityProvider` (§L) — `StaticInstallationIdentityProvider` retained for tests only |
| `ILicenseStateStore` | satisfied by NEW `SspLicenseStateStore` (DPAPI) — `FileLicenseStateStore` retained for its test suite only (§M) |
| `ISecurityEventSink` | satisfied by NEW `SspSecurityEventSink` (§C) |
| `ILicenseProvider` | `LocalLicenseFileProvider` reused; the *path* it reads is supplied by NEW `SspLicensePaths` |
| `LicenseValidationOptions.ExpectedProductId` | bound to NEW `SspLicensing.ProductId` build constant |
| `ILicensePolicy` | `DefaultLicensePolicy` used; no policy fork — SSP semantics map onto `limits` (§P) |

Zero reference *source files* need modification. If the Phase-0 compile surfaces issues under our SDK/compiler (never-built code + `TreatWarningsAsErrors`), the corrections land as the only "adaptation" edits, each documented.

### C. Rewritten/new specifically for SSP (all in `src/SSP.Server/Activation/` unless stated)

| New component | Why it must be SSP-native |
|---|---|
| `SspInstallationIdentityProvider` | The library deliberately ships no fingerprinting; SSP must bind to `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, hashed (SHA-256 hex) so the raw MachineGuid never appears in a readable artifact; non-Windows test hosts return null (then only *floating* test licenses validate — matches library semantics) |
| `SspLicenseStateStore` | Reference's own audit: durable anti-rollback needs "a host-supplied DPAPI/TPM-protected store (SSP integration responsibility)" — SSP implements `ILicenseStateStore` over `ProtectedFileStore` (`.license-state.dat`, DPAPI LocalMachine, atomic, fail-closed reads: DPAPI/IO errors throw → validator maps to `state_store_unavailable`) |
| `SspSecurityEventSink` | Reference ships only Null/InMemory sinks; SSP must persist events (console + `ServiceDiagnostics`-style Application event log), never throwing |
| `SspLicensePaths` | Canonical `C:\Program Files\SSP\licensing\` root + `SSP_LICENSE_ROOT` override, mirroring `ClientInstallPaths`/`AuthenticationCodeFile` seam conventions. (Safe: an env var can only *choose the directory read* — it can never create authorization; proven by reference Invariant 4) |
| `SspTrustAnchor` + `SspLicensing` constants | The anchor is a host deployment constant by design ("never from user-editable config", audit §5) plus the product Guid; production-vs-dev detection lives here |
| `SspActivationService` | Process-lifetime owner: builds anchor/identity/store/sink/provider, runs `manager.Load()`, exposes `ILicenseManager`/`ILicenseEnforcement`, hosts a revalidation timer hook, injectable `IClock` for tests |
| `ActivationGate` | Maps §G enforcement points to `LicenseEnforcement` calls and to SSP's failure vocabulary (exceptions the host already uses; existing protocol outcome strings) |
| CLI (`--license-status`, `--install-license`) | Uses standalone `LicenseValidator` (README API) + atomic artifact install; `--license-status` prints the machine installation id (so operators can request licenses), state, reason, expiry, limit summary |
| `tools/SSP.LicenseAuthority` | The only artifact producer; §N |

### D. Must NOT be used in SSP (and why)

| Component/idea | Verdict reason |
|---|---|
| `FileLicenseStateStore` in production wiring | Plaintext floor protected only by FS permissions; superseded by the DPAPI store (reference audit §9 agrees) — kept solely so its vendored tests document the contract |
| `InMemoryLicenseStateStore` as production default | Library default when no store passed ⇒ floor lost on restart. SSP's composition root *always* passes the durable store (construction enforced) |
| `StaticInstallationIdentityProvider` in production | Not an identity; test-only |
| `NullSecurityEventSink` in production | Would silently drop every licensing security event |
| Any `ILicenseProvider` other than the file provider | No online activation in SSP: verified the library has no networking, and SSP's constitution is offline |
| `ILicenseRevocationChecker` implementations (for now) | No online status channel exists; revocation comes via signed `Status`/superseding artifacts (§K). Seam stays available |
| Artifact schema extensions (kid, grace, etc.) | §J: format frozen; do not invent — the reference format suffices; rotation/grace handled procedurally (§K) |
| Forking/editing reference source beyond Phase-0 compile fixes | A verbatim vendored copy diffable against `_reference` is the only safe update path |

---

## 8. Traceable Answers (G, H, O, P, J, K, L, M, N)

### G. Exact runtime enforcement points (traced from source) and why

| # | Point (actual code location) | Library call mapped | Why correct here |
|---|---|---|---|
| EP0a | `SetupEngine.RunNewApplicationAsync` entry (after `ResolveServiceDirectory`, before RSA generation) | `enforcement.CanStartProtectedService(existingServiceCount)` where count = sibling application dirs under canonical services root | Both authoring paths (interactive/batch/ServiceBuilder) funnel through `SetupEngine`; creation of protected services is the primary commercial act; denial pattern = existing `InvalidOperationException` ⇒ `[setup] Failed:` + exit 1 |
| EP0b | `SetupEngine.RunAdditionalClientAsync` (config loaded; beside the existing duplicate checks) | `enforcement.CheckLimit(max_clients, existingAuthorizedUsers)` (+ license must be Valid) | Provisioning a client is where per-customer client counts are enforced *before* an OTT is minted |
| EP1 | `SspWindowsService.OnStart` (after config/key load, before `ServerGateway` construction) **and** equivalently `Program.RunServiceModeAsync` before gateway construction | `service.Load()`; `CurrentState != Valid` (production mode) ⇒ throw activation exception | The only two convergent start paths (SCM and foreground); both already sit in the fallible region with `ServiceDiagnostics` → diagnosed ERROR 1064; the pre-`ServiceBase.Run` ERROR 1053 contract is preserved because *nothing* runs before the dispatcher |
| EP2 | `ServerProtocol.HandleEnrollmentLockedAsync` — inside the *existing* per-service semaphore + `ServiceConfigFileLock` region, right after `.cache.dat` reload, before OTT comparison | `manager.Revalidate()` (enrollment is rare → full re-read is correct) ⇒ state must be Valid; `enforcement.CheckLimit(max_clients, users.Users.Count)` before adding the new `AuthorisedUser` | Enrollment is the only operation that grows `.index.dat`; the lock already held makes the count race-free; denial = `SendOutcomeAsync(false, detail)` + throw (existing pattern), client sees a plain message; **OTT not consumed on licensing denial** (throw happens before consumption code) — verified ordering in source |
| EP3 | `ServerProtocol.HandleFutureAuthorizationAsync` — before honoring the fingerprint/signature verdict | `enforcement.CanEstablishTunnel(gateway.ActiveTunnels)` — policy requires Valid state AND `max_concurrent_tunnels` not exceeded | Per-tunnel hot path; `Authorize` performs no I/O (library §11a) so this adds ~zero latency; existing tunnels are never touched |
| EP-T | `ServerGateway` periodic timer (~5 min, dispose in `DisposeAsync`) | `manager.Revalidate()` | `Authorize` deliberately does *not* re-run the pipeline (audit §7); without this, expiry/revocation between enrollments would never be noticed until restart |
| — | `TunnelCodec`/`TunnelRelay`/frames | **never** | Data plane stays provably untouched (F7/Tunnel* regression envelope); library has no per-frame concept |

### H. Interaction per SSP component

| Component | Interaction |
|---|---|
| `SetupEngine` | EP0a/EP0b injected; exceptions re-use its denial conventions; no signature/OTT/bundle logic changes |
| `SspWindowsService` | EP1 inserted *inside* the existing OnStart try/catch (its failure path already records via `ServiceDiagnostics` and rethrows); constructor/`ResolveServiceName` untouched |
| `RunServiceModeAsync` | Same EP1 call before `new ServerGateway(...)` |
| `ServerGateway` | Receives activation context via a new **optional** ctor parameter (48 existing call sites compile unchanged); exposes `ActiveTunnels` (Interlocked counter in `HandleClientAsync` try/finally); hosts the EP-T timer; passes context into `ServerProtocol` (its only constructor call site) |
| `ServerProtocol` | EP2/EP3 guards inside the two handlers; no message/method/signature changes to anything on the wire |
| Enrollment | Gated (EP2); all sub-steps (OTT hash compare, client-nonce signature, Authentication Code human channel, `.index.dat` write, OTT consumption) byte-identical |
| Future authorization | Gated (EP3); challenge/response untouched |
| Client provisioning | Entirely inside `SetupEngine` → inherits EP0a/EP0b; patched-client generation untouched |
| `ServiceBuilder` | Kept license-tool-free; inherits gates through `SetupEngine`; never gains issuance |
| `SspWindowsService` start contract | Nothing fallible before `ServiceBase.Run`: preserved — gate lives inside OnStart |

### O. Exact behavior per scenario (library state → SSP runtime behavior)

| Scenario | Library evidence | SSP behavior |
|---|---|---|
| No license exists | `Load()` → Unknown/`missing_license`; ops denied | EP1: service refuses to start (diagnosed 1064 in production mode); EP0: setup refuses; `--license-status` explains + prints installation id |
| License malformed | Malformed → **LockedDown (sticky)** | Same refusals; lockdown survives restart by construction (fresh process revalidates; store never grants) |
| Signature invalid / unsupported alg | InvalidSignature → LockedDown; alg firewall test | Same; `SspSecurityEventSink` persists `InvalidSignature` event |
| Expired | `now ≥ ExpiresAt` (exclusive boundary, ±1-tick tested) → Expired → LockedDown on next `Revalidate` | Renewal is operator-driven *before* expiry; after expiry all control-plane gates deny; `--license-status` shows expiry. **No grace period** (schema has none; §J) — operational mitigation: renewal workflow documented + days-remaining shown by status |
| Not yet valid | NotYetValid (NotBefore inclusive at boundary) → LockedDown | Same refusals until window opens |
| Wrong installation binding | WrongInstallation → LockedDown (comparison ordinal-ignore-case trimmed) | Re-issue flow via vendor; event persisted |
| Anti-rollback trip | Superseded → LockedDown; manager's atomic Apply re-check (ConcurrencyTests) | Re-install the current-or-newer artifact |
| State store corrupted | Store `Load` throws → validator Unknown/`state_store_unavailable`; artifact-present failure ⇒ manager enters LockedDown (evidence: `Apply`) | Fail closed. Operator recovery: artifact is reinstallable (same artifact re-validates idempotently); a fresh floor then rebuilds. Note (honest): manager's defensive re-check treats a store read failure as absent-floor and floor *writes* are best-effort — library's "signature is root of trust" stance; SSP accepts it because the *next start's* full validation read is fail-closed |
| License revoked | Payload `Status=revoked` → Revoked (post-signature stage) → LockedDown; optional checker seam un-wired | Vendor re-issues `active` (higher sequence) or customer installs superseding artifact |
| Service starts without valid license | restart-requires-revalidation invariant | EP1 refuses start; Windows reports diagnosed failure; `ssp-service-startup.log` + event log carry the reason code |
| Existing tunnel when license becomes invalid | Lockdown is process-level (§15);`Authorize` consults latest state | **The tunnel is never killed** — SSP's data plane is decision-free by design; the flip is noticed by EP-T (`Revalidate`) or any EP2; *new* tunnels (EP3) deny from that point |

### P. What activation gates — decision matrix

| Operation | Gated? | Mechanism |
|---|---|---|
| Setup/provisioning (new protected service) | **Yes** | EP0a + `max_services` |
| Service startup | **Yes (hard)** | EP1 |
| Enrollment | **Yes** | EP2 + `max_clients` (count `.index.dat` users under the existing lock) |
| Future authorization | **Yes** | EP3 (Valid-state requirement is inherent in `DefaultLicensePolicy`) |
| Tunnel establishment | **Yes** | EP3 = `CanEstablishTunnel` (`max_concurrent_tunnels`) |
| Protected service creation | **Yes** | = EP0a (`max_services` counts application dirs under the canonical services root) |
| Client creation (provisioning) | **Yes** | = EP0b (`max_clients` on authorized users) |
| Maximum clients | `LicenseLimitNames.MaxClients` — per-service, measured before grant (library convention) |
| Maximum services | `LicenseLimitNames.MaxServices` |
| `max_sessions` / `max_concurrent_sessions` | **Not wired initially** — SSP has no session concept distinct from tunnels ("one local TCP connection == one tunnel", `ClientTunnelRuntime`); documented as available seam |
| Feature flags (`CanUseFeature`) | **Not wired initially** — vocabulary is a host convention (§15); reserved for future capabilities (e.g., `servicebuilder`). Adding a gate later = one call site; none are needed for the first correct deployment |
| Tunnel data frames | **Never** | §I |

### J. Artifact format decision

**Adopt the reference format exactly — `ssp-license` v1.** Do not invent anything:

```json
{ "format": "ssp-license", "artifactVersion": 1,
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "payload": "<base64url(canonical-payload-JSON)>",
  "signature": "<base64url(RSA-PSS over canonical payload bytes)>" }
```

Payload fields: `licenseId, productId, productName, customerId, customerName, edition, licenseVersion, issuedAt, notBefore, expiresAt, installationId?, featureSet[], limits{}, status, sequenceNumber`. Canonicalization per `LicenseCanonicalJson` (fixed ordinal keys, RFC3339-UTC 7-digit, GUID "D", normalized sorted sets, explicit-null = unlimited). On-disk: one file `license.json` (transport is plaintext *signed* JSON by design — confidentiality explicitly out of scope in reference §15) in the canonical licensing directory, read by `LocalLicenseFileProvider`. 256 KiB cap enforced by the codec.

### K. Cryptographic contract decision

| Item | Contract (evidence) |
|---|---|
| Signature algorithm | **RSA-PSS-SHA256** (salt = digest length, MGF1/SHA-256), only entry in `SignatureAlgorithms.Supported`; unknown names fail closed even with otherwise-valid signatures |
| Canonicalization | `LicenseCanonicalJson` v1 rules; verification = parse-strict → re-canonicalize model → verify over those bytes (proven by `SignatureCoversCanonicalBytes_ReformattedPayloadStillVerifies`) |
| Trust anchor | Single authority RSA public key, SPKI/PEM, ≥2048 enforced at import; SSP compiles it into `SspTrustAnchor` (never config/env-loadable — audit §5); ceremony key = **3072 bits** |
| Key rotation | Library ships one anchor (§15). SSP procedure: (1) new production build carries new anchor constant; (2) authority re-issues all live artifacts signed by the new key **before** the old-anchor build is retired (`sequenceNumber` monotonic protects direction); overlap handled by release cadence, not schema. Multi-anchor support is a future, explicitly-scoped library change — not invented now |
| Installation binding | `payload.installationId` (optional) vs `SspInstallationIdentityProvider` = `SHA256(MachineGuid ‖ purpose-tag)` hex, compared by the library (ordinal, case-insensitive, trimmed); `installationId` absent = floating (test/dev licenses only; production policy: always bound) |
| Anti-rollback | `sequenceNumber` (authority-side monotonic) + durable floor (`HighestAcceptedSequenceNumber`) in the DPAPI store + manager's atomic Apply re-check |
| Expiry | `notBefore` inclusive / `expiresAt` exclusive, `IClock` UTC only; no grace field exists — grace is an ops process (renew-ahead), not code |
| Revocation | Signed `status=revoked` + superseding artifacts (floor blocks rollback to pre-revocation artifacts); `ILicenseRevocationChecker` seam documented but not wired (no offline-online contradiction) |
| Fail-closed | Library: every stage/action defaults to deny (parse, crypto, time, identity availability, store availability, policy exceptions, unknown operation kinds). SSP: production mode requires `Valid` to start/setup/enroll/tunnel; dev-unmanaged mode only when no anchor is compiled in |

### L. Installation identity in SSP

- `SspInstallationIdentityProvider` (Server): reads `HKLM\SOFTWARE\Microsoft\Cryptography` **`MachineGuid`** (BCL registry read; no dependency added to the library), returns `Convert.ToHexString(SHA256(UTF8(MachineGuid) ‖ "SSP-LICENSE-INSTALL-v1")).ToLowerInvariant()` as the installation id. Hashing keeps the raw MachineGuid out of the readable artifact file and out of events.
- Stability/security notes: survives reboots and hardware churn; changes on OS reinstall/VM re-sysprep ⇒ re-issue (intended commercial binding). Not combined with MACs/SMBIOS (fragile + clone-duplicated). Never weakens SSP identity mechanisms — disjoint from `ConnectionIdentity`/key fingerprints by purpose and storage.
- Non-Windows test hosts: provider returns null ⇒ installation-bound licenses fail closed there (library behavior); SSP's *test* licenses are issued floating or with injected static ids — no env-var identity override is added to production code (stricter than v1's plan).

### M. Activation state persistence on Windows

- `SspLicenseStateStore : ILicenseStateStore` over `ProtectedFileStore` with one additive protected name **`.license-state.dat`** in `C:\Program Files\SSP\licensing\` (test-redirectable via `SSP_LICENSE_ROOT`, same pattern as `SSP_CLIENT_ROOT`).
- This is strictly stronger than `FileLicenseStateStore`: DPAPI LocalMachine envelope ⇒ the anti-rollback floor **cannot be decrypted off-machine** (a copied licensing folder is useless elsewhere — defense compounding the installation binding); writes remain atomic (`AtomicFile`); reads fail closed (DPAPI error → throw → `state_store_unavailable` → deny, never reset).
- Not blindly adopting the plaintext store directly answers the task's §13/M requirement and the reference audit's own recommendation.

### N. LicenseIssuer boundary

- **Decision: issuance never runs in customer flows.** Concretely: the *type* remains inside the vendored library (safe by construction — it holds no key, generates none, requires a caller-owned `RSA` on every call; its co-location keeps issuance and verification on one canonicalization implementation, exactly as the reference authors designed and their audit rated only a Low/optional split).
- The **capability boundary** is: private key + issuance UX live exclusively in `tools/SSP.LicenseAuthority` (keygen/issue/inspect CLI; references the vendored library + optionally SSP.Core for PEM helpers). The tool is **not referenced by any shipped project**, **not added to any publish target**, and **not distributed**. Rule enforcement: CI grep asserts `src/SSP.Server/**`, `src/SSP.Core/**` never call `LicenseIssuer`; code review; optional future hard-split listed as hardening (matches audit's Low recommendation) — not required to be safe.

---

## 9. I — Components that must remain completely untouched (confirmed against both codebases)

| Component | Status | Mechanism guaranteeing it |
|---|---|---|
| RSA identity/authentication (`RsaCrypto`, key pairs, fingerprints, `.sysdata.bin`/`.runtime.dat` key files) | **Untouched** | Licensing uses its own isolated RSA-PSS code; zero shared call sites |
| Enrollment protocol (`Messages.cs` types 1–5 flows, OTT comparison, nonce signature) | **Untouched** | EP2 is a guard *around* the flow; error text rides the existing `ErrorOrWait`/`Message` strings; no new `MessageType` |
| Authentication Code (generation, human channel, `Authcode.txt`, dialog) | **Untouched** | No interaction |
| OTT lifecycle (hash-only storage, consume-on-success) | **Untouched** | EP2 denial occurs before consumption code — verified ordering |
| AES-GCM | **Untouched** | No contact |
| `TunnelCodec` / `TunnelRelay` | **Untouched** | No licensing calls anywhere in the data plane |
| Patch-slot client binary mechanism (`ClientTemplate`, 4096/131072 slots, `PatchSlot.cs`, `ClientServicesResource.cs`) | **Untouched** | Client is licensing-free; nothing new embedded |
| DPAPI `ProtectedFileStore` mechanism | **Mechanism untouched — one additive allowed-name line** | Envelope, migration, entropy string unchanged; existing four names' behavior byte-identical (`ProtectedFileStoreTests` green) |
| Service-startup contract (SCM fast path, 1053/1064 semantics, wait hints, `ResolveServiceName`) | **Untouched** | Gate inserted *inside* OnStart's fallible region only |
| `SSP.Client/**` (entire project) | **Untouched** (zero references, zero code) | No dependency edge to `SSP.Activation` is ever added from Client or Core graphs it uses |
| `_reference/SSP.Activation/**` | **Untouched** | Vendored *copy*; reference stays pristine for future diffing |

## 10. Q — Dependency graph & acyclicity proof

```
BCL
 ├── src/SSP.Core               (deps: ProtectedData pkg)                [no edge to Activation]
 ├── src/SSP.Activation         (VENDORED; deps: none)
 ├── src/SSP.Client             → SSP.Core
 ├── src/SSP.Server             → SSP.Core, SSP.Client, SSP.Activation   [NEW edge: Server→Activation]
 ├── src/SSP.ServiceHost        → SSP.Server
 ├── src/SSP.ServiceBuilder     → SSP.Core, SSP.Server                   [no direct Activation edge; gates via SetupEngine]
 ├── tools/SSP.LicenseAuthority → SSP.Activation (+ optional SSP.Core PEM helpers)
 └── tests/SSP.Tests            → SSP.Core, SSP.Client, SSP.Server, SSP.ServiceHost, SSP.Activation [NEW edge]
```

Topological order exists: `SSP.Core`, `SSP.Activation` → `SSP.Client` → `SSP.Server` → {`SSP.ServiceHost`, `SSP.ServiceBuilder`} → `SSP.Tests`; the tool hangs off `SSP.Activation`. **No cycles** (the single new runtime edge points leaves-ward; nothing under `_reference/` is referenced).
Publish graph note: `SSP.Activation.dll` rides into `SSP.Server`/`SSP.ServiceHost` single-file bundles automatically (managed BCL-only assembly ⇒ no single-file/native-extract complications; `PublishClientTemplate`/`PublishServiceHostTemplate` targets need no change; `SSP.Client.exe` never contains it).

## 11. R — File-level migration matrix

**Existing SSP files:**

| File | Action | Activation component | Reason | Security impact | Regression risk |
|---|---|---|---|---|---|
| `src/SSP.Core/IO/ProtectedFileStore.cs` | **MODIFY** (+1 name) | `SspLicenseStateStore` storage | Single DPAPI authority | Strictly positive (floor encrypted) | Minimal — additive; covered by existing `ProtectedFileStoreTests` + new store tests |
| `src/SSP.Core/IO/*, Crypto/*, Protocol/*, Models/*, Util/*` | KEEP | — | — | None | None |
| `src/SSP.Server/Program.cs` | **MODIFY** (+2 CLI commands; wire service start gate via `RunServiceModeAsync`) | `SspActivationService`, CLI | Operator lifecycle | Positive; `--service` fast path untouched | Low — command-table additions only |
| `src/SSP.Server/ServiceHost/SspWindowsService.cs` | **MODIFY** (EP1 ~6 lines inside OnStart) | gate | Start refusal | Positive (fail-closed + diagnosed) | Low — `ServiceStartRegressionTests` must stay green |
| `src/SSP.Server/Runtime/ServerGateway.cs` | **MODIFY** (optional context param, `ActiveTunnels`, timer) | context host, EP-T, EP3 counter | Control-plane gating | Positive | Medium — 48 ctor sites verified source-compatible (optional param); timer disposal in `DisposeAsync`; F7/A1 suites watch |
| `src/SSP.Server/Runtime/ServerProtocol.cs` | **MODIFY** (EP2/EP3 guards ~25 lines) | gate call sites | Enrollment/tunnel gating | Positive | Medium — F4/F5 semantics pinned by tests; denial must not consume OTT |
| `src/SSP.Server/Setup/SetupEngine.cs` | **MODIFY** (EP0a/EP0b ~15 lines) | limits | Service/client creation gating | Positive | Low/Medium — provisioning suites watch for exception-behavior parity in dev mode (allow) |
| `src/SSP.Server/SSP.Server.csproj` | **MODIFY** (+ProjectReference to vendored lib) | build | — | None (BCL-only assembly) | Low — recursive publish targets verified unaffected |
| `src/SSP.Server/Setup/WindowsServiceInstaller.cs`, `Runtime/AuthenticationCodeFile.cs`, `UI/AuthenticationCodeDialog.cs`, `ServiceHost/ServiceDiagnostics.cs` | KEEP | — | Event sink *uses* ServiceDiagnostics patterns without editing it | None | None |
| `src/SSP.ServiceHost/Program.cs` | KEEP | — | inherits gate through `SSP.Server.Program.Main` | None | None |
| `src/SSP.ServiceBuilder/**` | KEEP | — | gates inherit through `SetupEngine` | None | None |
| `src/SSP.Client/**` (all 10 files + csproj + bins) | KEEP | — | §I | None | None |
| `SSP.sln` | **MODIFY** (implementation phase: add 2 projects) | build | includes vendored lib + tool | None | None |
| `tests/SSP.Tests/**` (all existing files) | KEEP (unedited) | — | preservation mandate; harness extension is *optional additive* overloads only | None | None by construction |
| `tests/SSP.Tests/SSP.Tests.csproj` | **MODIFY** (+ProjectReference to vendored lib) | test wiring | — | None | None |
| `_reference/**` | KEEP (never edited, never referenced by build) | provenance | diff baseline | None | None |

**New files:**

| File | Action | Contents |
|---|---|---|
| `src/SSP.Activation/**` (25 files) | **NEW (vendored verbatim)** | Reference library copy (namespace `SSP.Activation` preserved) |
| `src/SSP.Server/Activation/*.cs` (8) | **NEW** | §6/C components |
| `src/SSP.Core/Activation/SspLicensing.cs` | **NEW** | ProductId constant + documented limit/feature vocabulary |
| `tools/SSP.LicenseAuthority/**` | **NEW** | Authority CLI |
| `tests/SSP.Tests/Activation/**` (21 vendored + ~8 new SSP integration files) | **NEW** | §S |

**DELETE: none** (no legacy licensing exists in SSP; nothing is removed).

## 12. S — Test migration/addition plan

1. **Port the whole reference suite unchanged** into `tests/SSP.Tests/Activation/…` (namespaces already unique: `SSP.Activation.Tests.*`; xunit/versions identical; global non-parallelization already set in the SSP test assembly suits its env-var tests; `TestPaths` writes under the test output dir which is gitignored by `bin/`).
2. **Keep every existing SSP test file byte-identical.** This is guaranteed structurally: (a) optional-parameter wiring; (b) dev-unmanaged mode when no anchor is compiled (test runs never ship one); (c) no message/persistence/behavior drift.
3. **New SSP integration tests** (anchored compositions built explicitly, `FixedClock` injection via `SspActivationService`):
   - start gate: no license ⇒ start refused; valid ⇒ runs; wrong-machine ⇒ refused; expired ⇒ refused (clock-advanced);
   - setup gates: `max_services` refusal; additional-client `max_clients` refusal;
   - enrollment denial keeps OTT un-consumed and `.index.dat` unchanged; valid license enrolls end-to-end against the real gateway harness (extends `SspTestHarness` via a new optional anchored-activation parameter — existing call sites unchanged);
   - future-auth denial after `Revalidate()` flips to Expired; **in-flight tunnel keeps pumping** while the next connection is denied (explicit non-kill test);
   - `max_clients` end-to-end (license count = 1 ⇒ first client enrolls, second denied);
   - DPAPI state store: round-trip, cross-instance persistence, corruption ⇒ fail closed, floor blocks lower-sequence artifact, poisoned floor cannot authorize (SSP edition of invariants 4/8);
   - identity provider: hashing non-disclosure (artifact contains no raw MachineGuid), stability;
   - CLI: `--install-license` valid/invalid/tampered/oversized flows; `--license-status` output contract;
   - lockdown non-destructive against a live SSP service directory (files byte-identical incl. `.cache.dat`, `.index.dat`, keys).
4. **Regression proof**: solution-wide test run with zero existing-file diffs; F10 full-system test passes in dev mode; anchored mode suites pass on Windows CI and Linux CI.

## 13. T — v1 assumptions, verified against the actual reference source

| # | v1 assumption | Evidence now read | Verdict |
|---|---|---|---|
| 1 | Reference might not exist | Commit `a599f90` on `main`; 68 files | **Superseded — audited for real** |
| 2 | "Do not simply reference the `_reference` project" | Reference ships as its own standalone solution meant for host integration | **Confirmed → verbatim vendoring into `src/SSP.Activation`** (independence + pristine diff base) |
| 3 | LicenseManager likely a god-class / unknown threading | Read in full: documented state machine, volatile snapshot readers, atomic `Authorize`, atomic anti-rollback re-check, ~396 lines | **Reusable unchanged** |
| 4 | Validator pure w/ injectable clock? | `IClock` ctor-injected; validator stateless except floor reads | **True — reuse unchanged** |
| 5 | Canonicalization would be the correctness trap; TLV fallback sketched | Canonical-JSON with fixed key order + strict schema-complete parse + re-canonicalize-verify + 15 dedicated tests incl. order/whitespace independence and mutate-any-field flips signature | **Adopt reference approach; TLV idea dropped** |
| 6 | Crypto: expect PKCS#1/ECDSA; prefer one crypto stack | **RSA-PSS-SHA256**, self-contained, allow-listed; tunnel crypto disjoint by boundary | **Adopt as-is; crypto stacks remain separated by purpose** |
| 7 | Identity provider maybe MAC-based (would reject) | Library does *no* fingerprinting; host port only | **SSP writes MachineGuid-hash provider (§L)** |
| 8 | Plaintext `FileLicenseStateStore` risk | Confirmed in code + their audit recommends DPAPI host store | **SSP DPAPI store (§M)** |
| 9 | Online revocation risk | Zero networking anywhere (grep-verified); signed `status` + checker seam | **Offline-compatible — adopt; seam un-wired** |
| 10 | Key rotation/kid support uncertain | §15: explicitly absent (single anchor) | **Build-time rotation procedure (§K); no schema invention** |
| 11 | Their enforcement engine would be foreign to SSP seams | `LicenseEnforcement`/`DefaultLicensePolicy` are seam-free (usage counts host-supplied) | **Reuse both; SSP writes call sites only** |
| 12 | SecurityEventSink needs rewriting | It's an interface + test sinks; SSP writes one production sink | **Interface reused; impl new (as designed)** |
| 13 | Tests portable to SSP conventions | xunit versions identical; helpers self-contained | **Port wholesale** |
| 14 | v1's grace-period design | Schema has no grace; expiry is hard | **Grace dropped** (would violate "don't invent format"); renewal-ahead operations instead |
| 15 | v1's compiled anchor list + kid rotation | Single anchor by design | **Simplified to constant + release-cadence rotation** |
| 16 | v1's EP0–EP3 seam choices in SSP | SSP tree unchanged; mappings validated against the library's real API (`CanStartProtectedService`, `CheckLimit`, `CanEstablishTunnel`, `Revalidate`) | **Confirmed, now with concrete call mapping** |
| 17 | New warning: never-compiled source + `TreatWarningsAsErrors` | Audit disclaimer; no SDK here either | **Phase-0 compile/test gate before any adoption credit** |

---

# IMPLEMENTATION READINESS

## 1. Approved architecture

Vendored verbatim `src/SSP.Activation` library + SSP-native integration in `src/SSP.Server/Activation/` (identity provider, DPAPI state store, event sink, paths, trust anchor + product constants, composition root, gate, CLI) + 1 additive line in `SSP.Core/ProtectedFileStore` + 1 constants file in `SSP.Core/Activation/` + authority-only `tools/SSP.LicenseAuthority` + full test port & additions. Enforcement at EP0a/EP0b (SetupEngine), EP1 (service start: `SspWindowsService.OnStart` + `RunServiceModeAsync`), EP2 (enrollment, inside existing locks), EP3 (future-auth/tunnel establishment) + EP-T periodic revalidation. Artifact format `ssp-license` v1 / RSA-PSS-SHA256 / canonical JSON — unchanged from reference. Production enforcement active iff a trust anchor is compiled in; development builds run unmanaged-permissive with loud logging. Zero client impact; zero protocol impact; zero data-plane impact.

## 2. Exact files that MAY be changed (implementation phase)

- `src/SSP.Core/IO/ProtectedFileStore.cs` (additive protected-name only)
- `src/SSP.Server/Program.cs`, `src/SSP.Server/ServiceHost/SspWindowsService.cs`, `src/SSP.Server/Runtime/ServerGateway.cs`, `src/SSP.Server/Runtime/ServerProtocol.cs`, `src/SSP.Server/Setup/SetupEngine.cs`
- `src/SSP.Server/SSP.Server.csproj`, `tests/SSP.Tests/SSP.Tests.csproj`, `SSP.sln`
- NEW files only: `src/SSP.Activation/**` (vendored), `src/SSP.Server/Activation/**`, `src/SSP.Core/Activation/SspLicensing.cs`, `tools/SSP.LicenseAuthority/**`, `tests/SSP.Tests/Activation/**`
- `tests/SSP.Tests/Helpers/SspTestHarness.cs` may gain **additive optional** overloads only (no signature breaks)

## 3. Exact files that must NOT be changed

All of `src/SSP.Client/**` · `src/SSP.Core/Crypto/**` · `src/SSP.Core/Protocol/**` · `src/SSP.Core/Models/**` · `src/SSP.Core/Util/ClientTemplate.cs` · `src/SSP.Core/IO/{AtomicFile⇢inside ConfigStore.cs, PemStore.cs, ClientInstallPaths.cs}` · `src/SSP.ServiceHost/**` · `src/SSP.ServiceBuilder/**` · `src/SSP.Server/Setup/WindowsServiceInstaller.cs` · `src/SSP.Server/Runtime/AuthenticationCodeFile.cs` · `src/SSP.Server/UI/**` · `src/SSP.Server/ServiceHost/ServiceDiagnostics.cs` · **every existing test file** (except optional additive harness overload noted above) · `_reference/**` · the vendored `src/SSP.Activation/**` after Phase 0 (verbatim-ness is a diff invariant).

## 4. Exact components to reuse (verbatim)

§7.A list: all abstractions, canonicalization, crypto (anchor + algorithms), all serialization, validation pipeline, LicenseManager, all models, both enforcement classes, LocalLicenseFileProvider, both event sinks, LicenseIssuer (authority tool only), InMemoryLicenseStateStore (tests), all 21 reference test/support files.

## 5. Exact components to write new (rewrite-for-SSP)

`SspInstallationIdentityProvider` · `SspLicenseStateStore` (DPAPI) · `SspSecurityEventSink` · `SspLicensePaths` · `SspTrustAnchor` + `SspLicensing` constants · `SspActivationService` · `ActivationGate` · license CLI verbs · `tools/SSP.LicenseAuthority` · new integration tests (§12.3).

## 6. Exact tests required

Phase-gate: reference suite compiles+passes as-is (its 9 invariants, concurrency trio, codec/validation/policy tables). SSP additions per §12.3 (start gate, setup gates, enrollment limits + OTT-preservation, expiry flip with live-tunnel non-kill, DPAPI store incl. corruption/rollback/poison, identity, CLI, service-dir non-destructiveness). Regression: entire pre-existing suite green **unmodified**, Windows + Linux. Authority tool: issue→install→validate round-trip; revocation and sequence-monotonicity scenarios.

## 7. Ordered implementation phases

- **P0 — Verification gate (no adoption):** copy `_reference/SSP.Activation` → `src/SSP.Activation` verbatim; temporarily wire a throwaway local build (or isolated `dotnet build/test` run); record and minimally fix compile issues (`TreatWarningsAsErrors`). Output: green vendored build + green reference tests. *No SSP runtime changes.*
- **P1 — SSP adapters (dormant):** `SspLicensePaths`, identity provider, DPAPI state store, event sink, constants (+ Core additive line); unit tests; nothing wired into runtime paths.
- **P2 — Operator lifecycle:** composition root + CLI (`--license-status`, `--install-license`); CLI tests; still no runtime gating.
- **P3 — Runtime gating (the behavior change):** `ActivationGate` + EP0/EP1/EP2/EP3 + EP-T timer; dev-unmanaged mode; integration tests; full regression run.
- **P4 — Authority tool + ceremony:** keygen/issue/inspect; end-to-end license issuance → install → validation; `docs/` key-ceremony + renewal/revocation runbooks.
- **P5 — Hardening & readiness:** threat-model sign-off, event-log taxonomy review, (optional) `LicenseIssuer` hard-split, Authenticode guidance for shipped binaries.

## 8. Rollback strategy per phase

- **P0:** delete `src/SSP.Activation` (self-contained).
- **P1:** delete new adapter files; revert the single ProtectedFileStore line; state file unused ⇒ delete licensing dir.
- **P2:** remove CLI verbs + composition root; nothing gating ⇒ behavior identical to P1.
- **P3:** per-edit reversibility (each of the 5 SSP edits is isolated/additive); instant production rollback = rebuild from pre-P3 commit; *emergency field relief* = vendors issue a superseding artifact — deliberately **no** runtime kill-switch/env override (would be a bypass primitive); removing the licensing dir returns a machine to pristine unlicensed state; SSP service data is never touched by activation.
- **P4/P5:** tool/docs/hardening are additive-only; remove without runtime effect.

## 9. Definition of Done

1. P0 green: vendored library builds with warnings-as-errors and its full test suite passes on Windows and Linux CI.
2. Fail-closed matrix (§O) implemented row-for-row, each covered by a passing test.
3. Byte-proof of non-interference: `git diff` shows zero changes in every §3-must-not-change path; wire protocol untouched (message schema diff = empty); the F10 full-system test and all 33 pre-existing suites pass **without a single edit**.
4. Anchored-mode SSP tests pass: service refuses start unlicensed (diagnosed, event-logged), setup/enrollment/tunnel gates fire with correct reason codes, OTT never consumed on licensing denial, in-flight tunnels never killed on expiry flip.
5. DPAPI state store round-trips across process restarts, fails closed on corruption, blocks rollback, and cannot be used off-machine (decrypt fails elsewhere).
6. Authority ceremony executed on a scratch key: artifact issued → installed → validated → renewed (higher sequence) → revoked (status) → refusal behaviors observed; private key proven absent from repo, build outputs, and customer packages (grep + packaging review).
7. Anti-rollback floor + manager atomic re-check verified under the ported concurrency tests plus SSP's multi-service/multi-client provisioning tests (unmodified) in anchored mode.
8. Documentation: operator runbook (install/status/renew/revoke), key-ceremony doc, limitations (clock manipulation partial mitigation; process-level lockdown consultation contract; rotation cadence) — copied forward from reference §14/§15 and extended with SSP specifics.
9. This document updated to "As-Built"; every deviation from the blueprint recorded with reason.

---

*End of report. Nothing in this phase modified source, projects, the solution, or git state; one report file was updated. No code follows this analysis.*

---

# AS-BUILT STATUS (recorded after P0–P5, 2026-09-04)

Per Definition-of-Done item 9, this blueprint is now updated to as-built. Every
deviation from the blueprint above is recorded here with its reason; anything
not listed was built exactly as specified.

| Phase | Outcome |
| --- | --- |
| P0 | `src/SSP.Activation` vendored verbatim from `_reference/SSP.Activation`; only the csproj carries the documented `DebugType=embedded` compile fix. Reference test suite lives in `tests/SSP.Activation.Tests` (135 declarations, verbatim) and is part of `SSP.sln`. |
| P1 | SSP-native adapters as specified: `SspLicensePaths`, `SspInstallationIdentityProvider`, `SspLicenseStateStore`, `SspSecurityEventSink`, `SspLicensing` constants, one additive `ProtectedFileStore` name. |
| P2 | Composition root (`SspActivationService`) + operator CLI (`--license-status`, `--install-license` via `SspLicenseInstaller`, `--trust-anchor-info`). |
| P3 | Runtime gating at EP0a/EP0b/EP1/EP2/EP3/EP-T as specified. |
| P4 | `tools/SSP.LicenseAuthority` (keygen/export-public/fingerprint/issue/renew/inspect/verify), `docs/LICENSE_AUTHORITY.md`, `TRUST_ANCHOR_KEY_CEREMONY.md`, `LICENSING_LIMITS_AND_RESOURCE_SEMANTICS.md`. |
| P5 | `docs/THREAT_MODEL.md` (sign-off), event-log taxonomy (below), Authenticode guidance (`TRUST_ANCHOR_KEY_CEREMONY.md` §5); `LicenseIssuer` hard-split declined (below). |

Deviations from the blueprint, each with reason:

1. **Dev builds are fail-closed, not unmanaged-permissive.** §6's "preservation
   seam" (dev builds run with gates allowing + one loud event) was NOT built.
   As built: a build without a compiled-in anchor refuses every protected
   operation — `SspRuntimeLicense.CreateForService` throws
   `trust_anchor_missing`, `TryCreateForProvisioning` returns null with a loud
   diagnostic. Reason: the 33 pre-existing suites were preserved without it by
   giving the test harness an explicit gate seam (`UnlicensedTestGate`, test
   assembly only), so the permissive mode would have existed solely as a
   production bypass primitive. Recorded as build-time trust decision #1 in
   `docs/THREAT_MODEL.md`.
2. **`ActivationGate.cs` became `ISspLicenseGate.cs` + `SspRuntimeLicense.cs`.**
   Reason: the gate must own the usage counters and perform check-and-reserve
   atomically (P3 §6); an interface + admission token (`SspTunnelAdmission`)
   expresses that ownership without the runtime components ever touching the
   counters. Enforcement semantics match §G exactly.
3. **The trust anchor is not a source constant.** Blueprint §7.C said
   "compiled production anchor constant"; as built, `SspTrustAnchor.targets`
   provisions the anchor into the assembly at release build time
   (embedded-resource PEM + assembly-metadata fingerprint pin, `SSPTA001`–`SSPTA005`),
   and no build of this repository embeds one by default. Reason: a source
   constant would have committed key material to the tree and made the
   ceremony un-auditable; the MSBuild seam keeps the public key outside the
   repository until a release pipeline supplies it. Runtime re-verifies SPKI
   SHA-256 against the pin and fails closed on mismatch.
4. **`--install-license` + `SspLicenseInstaller`** were added beyond §7.C's
   `--license-status` (P4 scope), as the operator install path the authority
   runbook requires (validate-before-replace, atomic).
5. **`max_sessions` remains declared but unenforced** (reserved seam).
   Reason recorded in `LICENSING_LIMITS_AND_RESOURCE_SEMANTICS.md` §9: a
   cumulative total cannot be measured offline across restarts without a
   persisted per-license counter; enforcing it against a per-process total
   would silently change the limit's meaning. Deliberate.
6. **`LicenseIssuer` hard-split (P5, optional) declined.** Reason: the
   boundary is machine-enforced (`LicenseAuthoritySecurityIsolationTests`
   scans every shipped source tree and every shipped assembly), the issuer
   holds no key, and a split would break the verbatim-vendoring invariant for
   no safety gain. Decision recorded in `docs/THREAT_MODEL.md` §6.
7. **Event-log taxonomy (P5).** `SspSecurityEventSink` now writes Windows
   Application-log entries under stable event ids 4601–4611 with
   operator-meaningful severities (`LicensingEventLogTaxonomy`); file/console
   line format unchanged. Pinned by `SspSecurityEventSinkTaxonomyTests`.

Verification status: as of PR #20 the full solution builds and the complete
test suites pass (581 tests, production-embed build, Windows host). This
session adds four taxonomy tests; no production behavior changes.

Remaining, deliberately outside this repository: execute the release key
ceremony on the real authority key (runbook:
`TRUST_ANCHOR_KEY_CEREMONY.md`), run release builds with
`SspRequireTrustAnchor=true`, and rotate per the runbook. Multi-anchor/key-id
rotation and online revocation remain documented future library changes.
