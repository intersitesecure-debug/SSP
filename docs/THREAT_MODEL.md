# SSP Licensing Threat Model — P5 Sign-off Record

**Status:** P5 hardening & readiness. This document is the threat-model sign-off
the implementation plan (`SSP_ACTIVATION_ARCHITECTURE_AND_INTEGRATION_PLAN.md`,
P5) requires before SSP licensing is considered ready. Every mitigation named
below is machine-checked by an existing test in this repository; every component
name is a real type in the current source tree. No new mechanism is proposed
here — the model records what the code already enforces and what it deliberately
accepts.

Companions: `SSP_ACTIVATION_ARCHITECTURE_AND_INTEGRATION_PLAN.md` (blueprint +
as-built status), `P3_INTEGRATION_REPORT.md` (runtime gating detail),
`LICENSING_LIMITS_AND_RESOURCE_SEMANTICS.md` (limit semantics),
`docs/LICENSE_AUTHORITY.md` (authority operations),
`TRUST_ANCHOR_KEY_CEREMONY.md` (anchor provisioning + release signing).

---

## 1. Scope

This threat model covers the SSP licensing subsystem end to end:

* the vendored verification library `src/SSP.Activation` (`LicenseManager`,
  `LicenseValidator`, `LicenseEnforcement`, `DefaultLicensePolicy`,
  `LicenseTrustAnchor`, codec/canonicalization);
* the SSP-native adapters and gates in `src/SSP.Server/Activation/`
  (`SspTrustAnchor`, `SspActivationService`, `SspRuntimeLicense`,
  `ISspLicenseGate`, `SspLicenseStateStore`, `SspInstallationIdentityProvider`,
  `SspSecurityEventSink`, `SspLicensePaths`, `SspLicenseInstaller`);
* the enforcement seams in `SSP.Server` (`Program.cs`, `SspWindowsService`,
  `ServerGateway`, `ServerProtocol`, `SetupEngine`) and the provisioning seam in
  `SSP.ServiceBuilder`;
* the authority-side tool `tools/SSP.LicenseAuthority`;
* the release trust-anchor provisioning seam
  `src/SSP.Server/Activation/SspTrustAnchor.targets`.

Out of scope (unchanged by licensing, per the plan §9): the enrollment/tunnel
cryptography (`RsaCrypto`, AES-GCM, OTT lifecycle, session keys), the patch-slot
client mechanism, and the Windows service control contract. Licensing never
touches the wire protocol or the data plane; the client carries no licensing
code.

## 2. Assets and trust boundary

| Asset | Where it lives | Protected how |
| --- | --- | --- |
| Authority **private** RSA key (3072) | Offline ceremony host / HSM, outside the repository | Never in the repo, never in any build, never in CI secrets; `.gitignore` excludes `*authority*private*.pem`; `SspTrustAnchor.targets` refuses a PEM containing `PRIVATE KEY` (`SSPTA003`) |
| Authority **public** key (trust anchor) | Embedded in `SSP.Server.dll` at release build as resource `SSP.Server.Activation.AuthorityPublicKey.pem` | Build-time provisioning only (`SspAuthorityPublicKeyPemFile`); fingerprint pin (`SspAuthorityPublicKeySha256`) re-checked at runtime by `SspTrustAnchor.Create()`; `--trust-anchor-info` verifies the shipped binary |
| License artifact (`license.json`) | `{product root}\licensing\` | RSA-PSS-SHA256 over canonical JSON; atomic replace via `AtomicFile`; size-capped (256 KiB); plaintext **by design** (integrity, not confidentiality) |
| Anti-rollback floor (`.license-state.dat`) | Same directory, on `ProtectedFileStore.ProtectedFileNames` | DPAPI LocalMachine envelope on Windows (AES-GCM fallback elsewhere); can only *restrict* authorization, never grant it; corruption ⇒ `state_store_unavailable` ⇒ fail closed |
| Installation identity | Derived at runtime (`MachineGuid`) | Hashed + domain-separated (`SspLicensing.InstallationBindingPurposeTag`); raw value never leaves `SspInstallationIdentityProvider` |
| Runtime authorization state | Per server process, `LicenseManager` under its own lock | Single authority, no cached verdicts anywhere (`LicensingCompositionTests` reflection check); `Valid → LockedDown` is sticky, cleared only by a valid artifact |
| Usage counters (`_activeTunnels`/`_activeSessions`) | Per process, `SspRuntimeLicense` under `_admissionGate` | Atomic check-and-reserve in `AdmitTunnel()`; release exactly once via `SspTunnelAdmission.Dispose()` |

## 3. Actors

| Actor | Capabilities assumed |
| --- | --- |
| Licensing Authority | Holds the private key on an offline/HSM host; issues, renews, revokes |
| SSP operator | Installs artifacts (`--install-license`), reads status (`--license-status`), provisions services/clients |
| Customer machine user / local admin | Reads the machine's own files and registry; can attempt rollback, tamper, clock changes |
| Remote unauthenticated peer | TCP connections only — never reaches a licensed slot (admission is post-authentication) |
| Remote authenticated client | Normal protected traffic, bounded by the licensed limits |
| Build pipeline | Supplies the *public* anchor at release time; can never supply the private key |

## 4. Threat catalogue

Each row: threat → surface → mitigation → **machine-checked by**.

| # | Threat | Mitigation (as built) | Test evidence |
| --- | --- | --- | --- |
| T1 | Forged or tampered license artifact | `LicenseValidator` six-stage pipeline (parse → schema → signature → status → product → installation → time → anti-rollback); no fail-open exception paths | `tests/SSP.Activation.Tests/` (validator/security suites); `LicensingFailClosedMatrixTests` |
| T2 | Signature algorithm substitution | Allow-list registry: RSA-PSS-SHA256 only; unknown algorithm never verifies | `SignatureVerificationTests.UnknownAlgorithmWithValidSignature_IsStillRejected` |
| T3 | Wrong product / wrong installation / expiry / not-yet-valid / revoked artifact | Product id bound at composition (`SspLicensing.ProductId`); purpose-bound installation hash; time checks against `IClock` | `LicensingFailClosedMatrixTests`; `SspLicensingAndTrustAnchorTests`; `InstallationBindingTests` |
| T4 | **Rollback to an older artifact** | DPAPI state-store floor (`HighestAcceptedSequenceNumber`); superseded artifacts ⇒ `Superseded` ⇒ LockedDown | `FileLicenseStateStoreTests`; `SspLicenseStateStoreTests`; `LicensingFailClosedMatrixTests` (superseded row); `ConcurrencyTests` |
| T5 | State-store tampering / corruption | Fail-closed reads; store can only restrict; corruption ⇒ `state_store_unavailable` | `SspLicenseStateStoreTests`; `FileLicenseStateStoreTests` |
| T6 | Unlicensed protected service starts (EP1) | `SspRuntimeLicense.CreateForService` throws before any socket binds — in `Program.RunServiceModeAsync` and `SspWindowsService.OnStart`; SCM sees diagnosed ERROR 1064 | `ProductionServiceStart_FailsClosed_WhenNoTrustAnchorIsCompiledIn`; `SspActivationServiceTests`; `LicensingFailClosedMatrixTests` |
| T7 | Provisioning unlimited services/clients (EP0a/EP0b) | `SetupEngine.AuthorizeNewProtectedService` / `AuthorizeAdditionalClientAsync`; `SspRuntimeLicense.TryCreateForProvisioning` requires a Valid license; OTT is never minted on denial | `LicensingFailClosedMatrixTests`; `SspLicenseInstallerTests` |
| T8 | Over-enrollment past `max_clients` (EP2) | `ServerProtocol.HandleEnrollmentLockedAsync` checks `CanEnrollClient` after OTT/nonce verification, **before** Authentication-Code generation and OTT consumption, inside the per-service enrollment lock + `ServiceConfigFileLock` | `TunnelLicensingIntegrationTests`; `ConnectionIsolationLicensingTests` |
| T9 | Exhaust `max_concurrent_tunnels`/`max_concurrent_sessions` via races (EP3) | Single choke point (`ReceiveSessionKeyAsync`), atomic check+reserve in `AdmitTunnel()`, post-authentication, release exactly once | `TunnelLicensingIntegrationTests` (N→N+1→release); `ConcurrencyTests` |
| T10 | Bypass EP3 via the enrollment socket's session-key offer | The same choke point admits/denies that path; denial ⇒ `SessionKeyAck{Accepted=false}` **before** RSA-OAEP unwrap | `EnrollmentSocket_CannotOpenADataPlane_WhenTheFeatureIsNotLicensed` |
| T11 | Expiry/revocation invisible after start | One revalidation timer (`SspActivationService`, 30 min default), single loop, survives provider failures without failing open | `RevalidationTimer_DetectsExpiry_AtRuntime_AndPropagatesTheLockdown`; `LicensingCompositionTests` timer suite |
| T12 | Cached `isLicensed` bool bypasses a lockdown | Reflection test proves no runtime component caches a verdict; gates consult the manager on every call | `NoRuntimeComponent_CachesALicensingVerdict` |
| T13 | Feature spoof via application name | `SspLicensing.Features` is the only mapping; unknown names ⇒ feature `null` ⇒ feature check removed but **Valid-state and limit gates remain unconditional** | `SspLicensingAndTrustAnchorTests`; `LicensingFailClosedMatrixTests` |
| T14 | Deleted license recovers a lockdown | Deletion ⇒ `MissingLicense` ⇒ LockedDown (sticky); recovery only via a valid artifact | `DeletingTheLicense_NeverRecoversALockdown`; `Recovery_LockedDownThenValidNewerLicense_AllowsProtectedOperationsAgain` |
| T15 | Trust-anchor substitution at build time | `SSPTA001`–`SSPTA004` refuse missing/absent/private/malformed anchor input; runtime re-derives SPKI SHA-256 and enforces the ceremony pin | `SspTrustAnchorProvisioningTests` |
| T16 | Trust-anchor injection at runtime | No environment variable, config file, registry value or CLI switch can supply the anchor (`SSP_LICENSE_ROOT` redirects the *directory* only) | `SspTrustAnchorProvisioningTests` (env/file/key-drop probes) |
| T17 | Authority private key leaks into shipped binaries | Issuer type is unreachable from every shipped source tree; manifest-resource scan of `SSP.Server.dll` (lossless, both UTF-8 and UTF-16LE views) rejects complete private-key blocks | `LicenseAuthoritySecurityIsolationTests` |
| T18 | Issuance of a license over a tampered payload (`renew`) | `renew` verifies the existing signature against the supplied private key before re-issuing | `LicenseAuthorityIssueVerifyTests` |
| T19 | Weak or wrong key type used as anchor | RSA only, ≥2048-bit floor (3072 keygen), SPKI parse, no trailing data, fingerprint pin | `SspTrustAnchorProvisioningTests`; `TrustAnchorTests` |
| T20 | Secrets in security events | Events carry only type/state/reason/licenseId/detail; detail sanitization; sink never throws | `SecurityEvents_NeverContainKeyMaterialOrArtifactContent`; `SspSecurityEventSinkTests` |
| T21 | Event-log denials invisible to operators | Stable event-log taxonomy: severity classes + stable ids 4601–4611 (P5) | `SspSecurityEventSinkTaxonomyTests` (new) |
| T22 | Oversized artifact DoS | Codec caps artifact length (256 KiB); provider refuses oversized files, fail-closed | `LicenseArtifactCodecTests`; `LocalLicenseFileProviderTests` |
| T23 | Partial/corrupt license file mid-read | `AtomicFile` temp+move installs and provider reads; readers never observe partial artifacts | `LicenseFileWritesAreAtomic_NoPartialArtifactIsEverLeftReadable`; `SspLicenseInstallerTests` |
| T24 | Off-machine state reuse / identity drift | DPAPI LocalMachine envelope binds the floor to the machine; identity is derived from the machine's own registry | `SspLicenseStateStoreTests`; `InstallationBindingTests` |

## 5. Build-time trust decisions (recorded here, as the blueprint requires)

1. **Development/CI builds are fail-closed, not permissive.** This is a
   deliberate deviation from the blueprint's original "unmanaged-development"
   mode (recorded in the plan's as-built status): a build without an anchor has
   `SspTrustAnchor.IsCompiledIn == false`, `CreateForService` throws
   `trust_anchor_missing`, provisioning continues without limit checks but can
   never become operational. Test development uses *explicit* seams instead —
   `LicensedTestEnvironment` (ephemeral in-memory authority key + genuinely
   signed artifact) and `UnlicensedTestGate` (test assembly only).
2. **The anchor is a build artifact, never source.** Only
   `SspAuthorityPublicKeyPemFile` (a path outside the repository) can embed it;
   the fingerprint pin is recorded as assembly metadata and enforced at runtime.
   Release pipelines set `SspRequireTrustAnchor=true`, so an unanchored release
   build fails (`SSPTA001`).
3. **One authority, one anchor.** Multi-anchor/key-id rotation is a documented
   future library change; rotation is procedural (re-issue before the old build
   is retired). See `TRUST_ANCHOR_KEY_CEREMONY.md`.
4. **The state store can only restrict.** No persistence surface — not the state
   store, not configuration, not the environment — can create authorization.
5. **The private key is never a CI secret.** No build step reads one; the
   authority tool is never referenced by any shipped project
   (`LicenseAuthoritySecurityIsolationTests` reads the tool's csproj and fails
   the build on drift).

## 6. LicenseIssuer boundary — hard-split decision (P5, optional item)

The blueprint listed an optional hard-split of `LicenseIssuer` out of the
shipped library as a hardening item. **Decision: not performed; the boundary is
enforced by test instead.** Rationale (from the blueprint §N): the issuer holds
no key, generates none, requires a caller-owned `RSA` per call, and shares the
canonicalization implementation with the verifier. The capability boundary —
private key + issuance UX exclusively in `tools/SSP.LicenseAuthority` — is
machine-checked: no shipped source tree may name the issuer type, and shipped
assemblies are scanned for private-key material. A future split remains
possible without behavioural change; the reference audit rated it Low.

## 7. Security assumptions (copied forward from reference §14, extended with SSP specifics)

1. The authority private key is protected (HSM/vault) and never reaches customer
   hosts. SSP adds: the key is supplied per invocation to the offline tool from
   a path outside the repository; `keygen` never prints it.
2. The anchor is delivered through a build channel SSP trusts — the release key
   ceremony (a deployment constant, not user configuration).
3. `ExpectedProductId` is the build constant `SspLicensing.ProductId`;
   configuration cannot redefine which product's licenses are acceptable.
4. Hosts run SSP inside a process they control; memory-inspection/debugger
   bypass of a software-only licensing layer is out of scope.
5. The state store is tamper-*resistant* (DPAPI), not the root of trust; the
   signature is.
6. Event sinks are trusted local log targets; payloads are secret-free by
   construction of the library events.
7. The system clock is host-controlled; `notBefore`/`expiresAt` plus the
   anti-rollback floor mitigate, but do not eliminate, clock manipulation on
   air-gapped machines.
8. SSP is **offline**: no online revocation/activation channel exists (the
   `ILicenseRevocationChecker` seam is available but unused). Revocation is a
   signed re-issue.

## 8. Known limitations (copied forward from reference §15, extended with SSP specifics)

* **No key rotation / key id.** One compiled-in anchor per build; rotation is
  procedural (`TRUST_ANCHOR_KEY_CEREMONY.md` §5).
* **No online provider.** `LocalLicenseFileProvider` only; artifacts reach the
  machine through the operator (`--install-license`).
* **`max_sessions` is reserved, not enforced.** It is a cumulative total SSP
  cannot measure offline across restarts without persisting a per-license
  counter; it is deliberately left unconstrained rather than enforced
  incorrectly (`LICENSING_LIMITS_AND_RESOURCE_SEMANTICS.md` §9).
* **`max_services` inventory counts only the canonical services root.** A
  service provisioned outside it via an explicit `--service-dir` is not counted
  (`SspProtectedServiceInventory`), and I/O errors yield an inventory of 0 while
  every other gate still applies.
* **Concurrent counters are per process and reset on restart**;
  `max_concurrent_*` therefore bound per-running-process concurrency, not
  machine-wide instantaneous usage.
* **Lockdown is process-level** and only as strong as the host's consultation
  discipline; SSP's consultation discipline is enforced by the integration and
  reflection tests in §4.
* **Artifacts are plaintext signed JSON** (integrity, not confidentiality);
  payload fields such as customer name are readable by anyone holding the file.
* **Artifact size is bounded** (256 KiB cap, fail-closed) to blunt resource
  exhaustion.
* **Clock manipulation** is only partially mitigable offline (§7.7).
* **Feature/limit vocabularies are host conventions**: the library validates
  shape and normalization; `SspLicensing.Features`/`Limits` define what
  `rdp`/`ssh`/`web`/`sql` and the limit names mean for SSP, and
  `LicenseAuthoritySecurityIsolationTests.AuthorityProduct_MatchesSspLicensing`
  pins the authority tool to the same vocabulary.

## 9. Residual risks (accepted, with reasons)

| Risk | Why accepted |
| --- | --- |
| Local admin on the customer machine defeats software licensing (rollback OS, replace binaries, debug the process) | Software-only licensing protects against operational error and casual fraud, not a determined owner of the machine; reference audit §1 agrees. Mitigation is procedural (contract + Authenticode-signing of shipped binaries to raise the tamper bar, `TRUST_ANCHOR_KEY_CEREMONY.md`) |
| Clock rollback to replay an expired license window | Partially mitigated (floor + window checks); fully eliminating it needs trusted time, which an offline product cannot assume |
| DPAPI LocalMachine scope means any local process with the right context could read the floor | The floor can only *restrict*; confidentiality of it is irrelevant to the security property |
| Event-log writes are best-effort | A logging failure must never mask the licensing verdict; the fail-closed behavior does not depend on the log |

## 10. Sign-off

| Item | Record |
| --- | --- |
| Scope reviewed | §1–§9, source-evidence based, on branch `arena/01a06c90-ssp` (2026-09-04) |
| Enforcement seams verified | EP0a/EP0b (`SetupEngine`), EP1 (`CreateForService` in `Program.RunServiceModeAsync` + `SspWindowsService.OnStart`), EP2 (enrollment, pre-OTT), EP3 (single choke point, post-authentication), EP-T (one revalidation timer) |
| Machine-checked mitigations | §4 table: every row cites a test that exists in the repository and runs in the standard test suites |
| Dev/fail-closed posture | Intentional; no production trust anchor or private key exists in, or can enter, this repository (see §5 and `TRUST_ANCHOR_KEY_CEREMONY.md`) |
| P5 items disposition | Threat-model sign-off: **this document**. Event-log taxonomy review: `LicensingEventLogTaxonomy` + `SspSecurityEventSinkTaxonomyTests`. Authenticode guidance: `TRUST_ANCHOR_KEY_CEREMONY.md`. `LicenseIssuer` hard-split: declined, boundary machine-enforced (§6) |
| Remaining outside this repository | Execute the release key ceremony on the real authority key; run release builds with `SspRequireTrustAnchor=true`; rotation per the runbook |
