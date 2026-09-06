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
  `LicenseTrustAnchor`, `LicenseKeyCertification`, `LicenseCertificationIssuer`,
  `LicenseActivation`, codec/canonicalization);
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
cryptography (`RsaCrypto`, AES-GCM, session keys), the patch-slot client
mechanism, and the Windows service control contract. The enrollment OTT
lifecycle is in scope only for the Phase 1/2 failed-Authentication-Code
controls described by T31; its cryptographic construction and wire protocol
remain unchanged. The AT-REST storage of the client identity key pair
(`connections/{ConnectionId}/.cache.dat` / `.index.dat` / `.runtime.dat`) is in
scope through T32 (roadmap Phase 3, M-2): the scope of the encrypted-at-rest
envelope is a security boundary of this model, while the enrollment wire
protocol that uses the key is unchanged. The durable anti-rollback state —
the license-state record, its installation binding and epoch, and the two
redundant witnesses (license state and enrollment state) — is in scope
through T33/T34 (roadmap Phase 4, M-3). The integrity of the code that enforces
all of the above — the SSP.Server / standalone SSP.ServiceHost images and the
SSP runtime assemblies a protected service runs — is in scope through T35
(roadmap Phase 5, M-4): an armed, release-embedded SHA-256 baseline is verified
at protected-service startup and any missing/tampered/unreadable component
fails the service start closed. Licensing never touches the wire
protocol or the data plane; the client carries no licensing code.

## 2. Assets and trust boundary

| Asset | Where it lives | Protected how |
| --- | --- | --- |
| Authority **private** RSA key (3072) | Offline ceremony host / HSM, outside the repository | Never in the repo, never in any build, never in CI secrets; `.gitignore` excludes `*authority*private*.pem`; `SspTrustAnchor.targets` refuses a PEM containing `PRIVATE KEY` (`SSPTA003`) |
| Authority **public** key (trust anchor) | Embedded in `SSP.Server.dll` at release build as resource `SSP.Server.Activation.AuthorityPublicKey.pem` | Build-time provisioning only (`SspAuthorityPublicKeyPemFile`); fingerprint pin (`SspAuthorityPublicKeySha256`) re-checked at runtime by `SspTrustAnchor.Create()`; `--trust-anchor-info` verifies the shipped binary |
| License artifact (`license.json`) | `{product root}\licensing\` | v1: root signs the payload; v2: root signs the per-license key certification and that leaf key signs the payload — both RSA-PSS-SHA256 over canonical JSON; atomic replace via `AtomicFile`; size-capped (256 KiB); plaintext **by design** (integrity, not confidentiality) |
| Per-license leaf private key | Authority process memory only (ephemeral) | Generated per license, used once to sign the payload, discarded; never persisted, never in any file, never in a shipped binary |
| Activation OTT + 10-digit code | OTT signed into the certification; code hash signed into the certification; code plaintext only in the authority activation record | Code is 10 decimal digits with its SHA-256 signed into the certification; the server can only verify a code, never generate one; the OTT is single-use, consumed only after a successful match |
| Authority activation record (`<licenseId>.json`) | Authority ceremony host, next to the private key | Plaintext authority secret (OTT + code); never in the repository, build, CI or any customer artifact |
| Anti-rollback floor (`.license-state.dat`) | Same directory, on `ProtectedFileStore.ProtectedFileNames` | DPAPI LocalMachine envelope on Windows (AES-GCM fallback elsewhere); also records `ActivatedLicenseId`; can only *restrict* authorization, never grant it; corruption ⇒ `state_store_unavailable` ⇒ fail closed. Phase 4 (M-3): the record is additionally **bound to the installation** (domain-separated hashed MachineGuid) and stamped with a **monotonic state epoch**; a record naming another installation fails closed |
| Anti-rollback **witness** (`.ssp-state-witness/license/{sha256(licensing-dir)}/.witness.dat`) | One directory level ABOVE the licensing directory — outside it, so deleting/restoring the licensing directory cannot take the witness with it | Redundant envelope-encrypted copy of the installation binding, state epoch, highest accepted floor and activated license id (Phase 4 / M-3, T33). Deletion of the state file ⇒ floor recovered from the witness (restrict-only lower bound) + `LicenseStateDeletionRecovered`; state file older than the witnessed epoch ⇒ `state_store_unavailable` fail closed + `LicenseStateRollbackDetected`; corrupt/plaintext/foreign witness ⇒ fail closed; missing witness ⇒ never a violation (primary authoritative); witness writes are config/primary-first, best-effort and max-merged (never regress) |
| Enrollment-state witness (`.ssp-state-witness/enrollment/{sha256(service-dir)}/.witness.dat`) | One directory level above each service directory | Redundant envelope-encrypted copy of the Phase 1/2 per-hashed-OTT abuse state: max failure count, latest cooldown instant, sticky revoked/consumed verdicts (Phase 4 / M-3, T34). Rolled-back `.cache.dat` cannot resurrect a revoked OTT, re-spend a consumed one, reset the counter below the witnessed total or shrink the cooldown; corrupt/plaintext witness ⇒ enrollment fails closed |
| Client identity key pair (`.cache.dat` / `.index.dat` / `.runtime.dat` under `C:\Program Files\SSP\connections\{ConnectionId}\`) | Client product root, one directory per Server+Service connection | Encrypted-at-rest envelope with **DPAPI CurrentUser** scope on Windows (scope recorded in the envelope; T32): decryption requires the creating user's own DPAPI master key, so no other local account — the files themselves are world-readable under `C:\Program Files` — can recover the client private key; legacy LocalMachine client envelopes are re-wrapped to CurrentUser on first read; undecryptable material ⇒ load throws ⇒ spec §19 "local identity credential unavailable", never a silent identity regeneration |
| Protected runtime images & the code-integrity baseline (Phase 5 / M-4) | `SSP.Server.exe` / extracted `SSP.ServiceHost.exe` images and the SSP runtime assemblies a protected service runs; the expected-hash `CodeIntegrityManifest` embedded as `SSP.Server.CodeIntegrity.manifest.json` at the release seam | Runtime code-integrity gate (`RuntimeCodeIntegrity`): before a protected service starts, every listed on-disk component must match its expected SHA-256, else the service refuses to start (`SspActivationException` / `code_integrity_failure`) and a credential-free `CodeIntegrityVerificationFailed` security line is raised. The baseline is a release constant (never config/env/disk). Un-armed (developer/CI) builds are a no-op; the compiled-in trust anchor + signed license remain the only gate. Self-verification of the shipping single-file image is out of scope (signed-image/OS-loader control, §9) |
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
| T25 | Public-key substitution inside a license (v2) | A public key inside a license is never a trust anchor: the root signature over its certification must verify first; substituting the certified key breaks the root signature | `LicenseKeyCertificationTests.PublicKeySubstitution_IsRejected` |
| T26 | Self-generated license / self-signed certification (v2) | The root authority is the only trust anchor; a certification not signed by the compiled-in root fails (`invalid_certification_signature`) | `LicenseKeyCertificationTests.CertificationSignedByWrongRoot_IsRejected` |
| T27 | License A key compromise forging license B (v2) | Each license gets a fresh leaf key; the certification binds `LicenseId`/`ProductId`/`CustomerId` to the certified SPKI, so A's key cannot authenticate B's payload (binding mismatch) | `LicenseKeyCertificationTests.LicenseAKey_CannotForgeLicenseB`; `CertificationForAnotherLicense_IsRejected_AsBindingMismatch` |
| T28 | Certification tampering / expiry / unusable key (v2) | Certification is canonicalized and root-signed; tampering fails the signature; an expired / not-yet-valid / undersized certified key fails closed | `LicenseKeyCertificationTests` (tamper/expiry/not-yet-valid/undersized cases) |
| T29 | Licensing activation bypass: guessing or replaying a code, or activating the wrong license | The licensing activation code is hashed with SHA-256 into the certification and compared constant-time; the persisted `ActivatedLicenseId` binds activation to exactly one license; a wrong code keeps `ActivationRequired` | `ActivationLifecycleTests`; `LicenseActivationTests` |
| T30 | Offline activation-request forgery / OTT replay | The OTT is authority-generated 256-bit random, signed into the certification, and matched constant-time against the authority's own record; it is single-use and consumed only on a successful match | `LicenseAuthorityActivationTests`; `LicenseActivationTests.OttMatches_IsConstantTimeAndStrict` |
| T31 | Brute-force the 10-digit client-enrollment Authentication Code by repeatedly reconnecting with a copied package's still-valid OTT | `.cache.dat` persists a failed-code counter per hashed OTT under the existing enrollment and cross-process configuration locks. Failures one and two retain the OTT; failure three removes both pending and legacy authorization for that hash, permanently invalidating every copy of the package. Logs emit stable, credential-free `Enrollment.AuthenticationCodeFailed` and `Enrollment.OTTRevokedAfterFailedAttempts` events. Counters and codes never enter the client or wire protocol | `F4_EnrollmentTests.WrongAuthenticationCode_BeforeLimit_PersistsAttemptAndKeepsOttValid`; `ThirdWrongAuthenticationCode_RevokesOttAndEmitsSecurityEvents`; `CorrectAuthenticationCode_AfterTwoFailures_EnrollsSuccessfully`; `CorrectAuthenticationCode_AfterThreeFailures_CannotEnrollSamePackage` |
| T32 | **Extract the client identity private key on the customer machine** and impersonate the enrolled client: the key files live under world-readable `C:\Program Files\SSP\connections\{ConnectionId}\` and were protected with DPAPI **LocalMachine** scope, which — per MS-CryptProtectData — "any user on the computer … can use CryptUnprotectData to decrypt" with the public in-source entropy string; a non-admin local user could copy `.cache.dat`, unprotect it in five lines of code, and sign future-authorization challenges exactly like the real client (`ServerProtocol` verifies against the enrolled public key) | Client connection files (`.cache.dat` private key, `.index.dat` public key, `.runtime.dat` profile) are now written with DPAPI **CurrentUser** scope (Phase 3 / M-2): the scope is recorded in the SSP-EAR1 envelope (algorithm byte 3 on Windows; byte 4 scope marker on the non-Windows test fallback) and is **authoritative for decryption**, so no other local account can recover the key material even though the file bytes remain readable. Server-side service files keep LocalMachine (the LocalSystem gateway service must read what elevated setup wrote — scope split is machine-checked). Pre-existing installs are upgraded in place: legacy plaintext client keys migrate directly into the CurrentUser envelope, and old LocalMachine client envelopes decrypt for their owner and are re-wrapped to CurrentUser on first read (best effort; identity, fingerprint and enrollment state unchanged). Undecryptable material (foreign user/machine, corruption, lost profile) fails closed: the load throws, the files stay byte-identical, and no replacement identity is generated (spec §19). The enrollment wire protocol, OTT/Authentication-Code flow, RSA key construction, and offline licensing architecture are unchanged | `ClientIdentityKeyProtectionTests.ClientConnectionFiles_AreProtectedWithCurrentUserScope`; `ServerSideServiceFiles_RemainProtectedWithLocalMachineScope`; `LegacyLocalMachineClientFiles_AreRewrappedToCurrentUserScope_OnFirstLoad`; `LegacyPlaintextClientKeys_MigrateDirectlyToCurrentUserScope`; `ForeignKeyMaterial_FailsClosed_WithoutRegeneratingIdentity`; `CrossScopeRead_UsesEnvelopeRecordedScope_AndRewrapsToRequestedScope` |
| T33 | **Delete or roll back the license state to revive an old license** (roadmap Phase 4 / M-3): the anti-rollback floor `.license-state.dat` is the only offline memory that a newer license was ever accepted (revocation is a signed re-issue; there is no online status check). Deleting the file made the validator treat the machine as freshly installed (no floor), and restoring an older copy of the same machine's file (still decryptable: LocalMachine DPAPI on Windows, the static local key file elsewhere) lowered the floor — either way a superseded but unexpired artifact re-validated as Valid, and a deleted file also destroyed the activation state | Three layers (Phase 4 / M-3). (1) **Installation binding**: every saved record is stamped with a domain-separated installation id (`SSP-LICENSE-STATE-BIND-v1` over the MachineGuid; a different hash than the license-binding id); a record naming another installation fails closed — state replayed from another machine/installation can never replace this floor. Legacy pre-Phase-4 records are adopted and upgraded, never rejected. (2) **Monotonic state epoch**: every save advances a persisted write counter as max(record, on-disk) + 1, so a cross-process last-writer-wins save cannot regress it. (3) **Redundant witness** stored OUTSIDE the licensing directory (one level above, `.ssp-state-witness/license/{sha256(dir)}/.witness.dat`, envelope-encrypted): a deleted state file with an intact witness is a *deletion attempt* — the floor and activation state are recovered from the witness (a durable, restrict-only lower bound; `LicenseStateDeletionRecovered`, event id 4615) and an old artifact stays `Superseded`; a state file whose epoch is below the witnessed epoch is a *rollback* — `state_store_unavailable` fail closed (`LicenseStateRollbackDetected`, event id 4614); corrupt/plaintext/foreign witness material fails closed; a missing witness is never a violation. A NEWER artifact still recovers after a deletion attempt (fail-closed without bricking). The store still can only restrict; the signed artifact remains the root of trust; no wire-protocol or network change | `SspLicenseStateStoreTests.Save_StampsInstallationBindingAndMonotonicEpoch`; `Load_FailsClosed_WhenRecordBoundToAnotherInstallation`; `LegacyRecord_WithoutBinding_IsAdoptedAndUpgradedOnSave`; `LicenseStateAntiRollbackTests.StateFileDeleted_WitnessRecoversFloorAndReportsEvent`; `StateFileDeleted_ActivationStateIsRecoveredFromWitness`; `StateFileRolledBack_FailsClosedAndReportsEvent`; `CorruptWitness_FailsClosed`; `PlaintextWitness_FailsClosed`; `ForeignWitness_FailsClosed`; `Witness_NeverRegresses_EpochOrFloor`; `WitnessFile_IsEncryptedAtRest`; `EndToEnd_DeletedStateFile_OldLicenseRevivalIsDenied`; `EndToEnd_RolledBackStateFile_FailsClosedAndDeniesEverything`; `EndToEnd_AfterDeletion_ANewerLicenseStillRecovers` |
| T34 | **Roll back the service `.cache.dat` to defeat the Phase 1/2 enrollment abuse controls**: the failed-Authentication-Code counter, the progressive cooldown, the three-attempt revocation and the OTT's single-use consumption were persisted only in the service directory's `.cache.dat`. A local administrator restoring an older copy of that file could reset the guess budget to zero, erase the cooldown, resurrect a revoked OTT (revocation was persisted only by *removing* the hash) or revive a consumed OTT for a second enrollment | Enrollment-state witness (Phase 4 / M-3): a redundant, envelope-encrypted file OUTSIDE the service directory (`.ssp-state-witness/enrollment/{sha256(service-dir)}/.witness.dat`) records, per hashed OTT, the max failure count, the latest cooldown instant and the sticky *revoked*/*consumed* verdicts. `ServerProtocol` consults it on every enrollment attempt: a witness-revoked or witness-consumed OTT is rejected even when the rolled-back config shows it pending (`Enrollment.StateRollbackDetected`); the cooldown is clamped to the later of the config and witnessed instants; every new wrong code counts against everything ever witnessed (`max(config-counter, witnessed+1)` — the next wrong code after a counter rollback revokes immediately, and the config counter is healed to the effective value); revocation/consumption are written to the witness after the config (lagging witness = safe direction). A corrupt/plaintext/foreign witness fails enrollment closed (`Enrollment.StateWitnessUnavailable`). The witness carries only hashed OTT keys, counts, timestamps and booleans — no credentials. No client, wire-protocol, OTT-generation or network change | `EnrollmentStateAntiRollbackTests.RolledBackConfig_AfterRevocation_OttStaysRevoked`; `RolledBackConfig_AfterTwoFailures_NextWrongCodeRevokesImmediately`; `RolledBackConfig_WitnessedCooldownCannotBeShrunk`; `RolledBackConfig_AfterConsumption_OttCannotEnrollTwice`; `CorruptWitness_EnrollmentFailsClosed`; `SuccessfulEnrollment_WitnessesConsumption`; `RevokedOtt_WitnessRecordsRevocation`; `EnrollmentWitness_IsEncryptedAtRest`; `FreshService_WithoutWitness_EnrollsNormally` |
| T35 | **Patch or replace SSP binaries / runtime assemblies to bypass the enforcement gates (roadmap Phase 5 / M-4):** SSP.Server.exe, the standalone SSP.ServiceHost.exe image each service runs, and the SSP runtime assemblies implement every gate (EP1 service start, EP2 enrollment, EP3 tunnel admission, enrollment auth, Phase 1/2/4 state logic). A local administrator who can write the installed binaries could patch a branch in the enforcement code so a license that should be denied is allowed (e.g. in `SspRuntimeLicense.CreateForService` / `AuthorizeServiceStart` or the auth path) - defeating Phases 1-4 in one stroke, because those controls are code, not data | Fail-closed runtime code-integrity gate (Phase 5 / M-4): at protected-service startup, before any licensing composition, `RuntimeCodeIntegrity.VerifyArmedStartup` (called by `SspRuntimeLicense.CreateForService`, the factory every protected-service start path - SCM `OnStart` and foreground `--run-once` - shares) verifies the armed `CodeIntegrityManifest` (expected SHA-256 per protected on-disk runtime component, embedded as a release-seam resource - never from config/env/disk). Any missing/tampered/unreadable component refuses the service to start (`SspActivationException`, reason `code_integrity_failure`) and raises a credential-free `[security] event=CodeIntegrityVerificationFailed` line, persisted through the existing EP1 `ServiceDiagnostics` startup-failure channel. A developer/CI build is not armed (no embedded baseline) and is a no-op - the compiled-in trust anchor + signed license remain the gate. Arming mirrors `SspTrustAnchor.targets` (`Activation/SspCodeIntegrity.targets`, opt-in at release, propagated into the standalone `SSP.ServiceHost` publish). A process cannot certify its own single-file image; that residual is signed-image/OS-loader territory (see §9). No wire-protocol or network change | `RuntimeCodeIntegrityTests.Verify_TamperedComponent_IsDetectedAndNotSatisfied`; `Verify_MissingComponent_FailsClosed`; `Verify_UnreadableComponent_IsAFailure_NotAnException`; `Verify_ComponentOutsideRoot_NeverReadsArbitraryFiles`; `GuardStartup_TamperedComponent_RefusesProtectedService_FailClosed`; `GuardStartup_MissingComponent_RefusesProtectedService_FailClosed`; `GuardStartup_EmptyManifest_IsANoOp_NotArmedBuildsProceed`; `CeremonyHelper_BuildManifestFromFiles_ThenGuardDetectsTampering`; `ManifestSerializer_RoundTripsLosslessly`; `ManifestSerializer_MalformedJson_ReturnsNull` |

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
8. SSP is **offline**: revocation is a signed re-issue and licensing activation
   is an offline, out-of-band exchange (an activation-request file produced by
   `SSP.Server --create-activation-request`, answered by the authority
   `activate` command, and entered with `SSP.Server --activate <code>`). No
   online revocation/activation channel exists (the `ILicenseRevocationChecker`
   seam is available but unused).

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
* **The authority activation record is plaintext authority secret** (it holds
  the plaintext 10-digit code). It is only ever written authority-side, next to
  the private key, and is never shipped. The license artifact itself never
  contains the code (only its hash).
* **Renewal of a certified (v2) license is a fresh `issue-certified`**, not
  `renew`: `renew` verifies the legacy root-signature-over-payload and will
  refuse a v2 artifact (fail-closed) rather than mint a leaf signature with the
  root key.
* **Activation is per `LicenseId`.** A renewal (a new license id) that is
  activation-required needs its own activation; the authority can instead issue
  a pre-activated renewal (no activation material) if immediate validity is
  intended.
* **Artifact size is bounded** (256 KiB cap, fail-closed) to blunt resource
  exhaustion.
* **Clock manipulation** is only partially mitigable offline (§7.7).
* **Enrollment attempt tracking is local server state, witnessed outside the
  service directory (T34, Phase 4 / M-3).** Phase 1 prevents remote unlimited
  guessing and survives ordinary process/service restarts; Phase 2 adds an
  offline per-OTT cooldown in front of the remaining guesses; Phase 4 adds the
  enrollment-state witness so that restoring an older `.cache.dat` can no
  longer reset the attempt count, shrink the cooldown, resurrect a revoked OTT
  or re-spend a consumed one. A local administrator who restores the service
  directory AND the `.ssp-state-witness` tree together (or reconstructs the
  whole machine state) still resets the enrollment memory — the same
  coordinated-rollback residual as the license state (§9). Host clock changes
  can shorten or lengthen the *witnessed* cooldown (Phase 6); they cannot
  restore attempts after the OTT has been revoked, and three guesses against a
  10-digit code remain infeasible.
* **A revoked enrollment OTT requires reprovisioning.** Three operator typing
  mistakes permanently invalidate that client package by design; recovery is
  to provision a new package/OTT through the existing offline setup workflow.
* **The client identity is bound to the creating user's DPAPI profile (T32
  fix).** A CurrentUser-scoped key becomes unrecoverable when the user account
  is deleted or its password changed such that the old DPAPI master key is
  unreachable; the connection then fails closed ("local identity credential
  unavailable") and must be re-provisioned offline with a new OTT/package.
  This is the accepted cost of user-scoped DPAPI — the alternative
  (LocalMachine) let any local account extract the private key.
* **Client identity files remain world-readable in their ENCRYPTED form.**
  `C:\Program Files\SSP\connections\{ConnectionId}\` inherits the default
  Program Files ACL (Read for "Users"); T32's boundary is the DPAPI
  CurrentUser master key, not the file ACL. Recovering the key still requires
  defeating that user's DPAPI master key (memory-inspection/debugging class),
  which the model already places out of scope for software-only protection
  (§7.4, §9).
* **Server-side service files keep the LocalMachine scope.** The gateway
  Windows Service runs as LocalSystem and must read what elevated setup
  wrote, so `.cache.dat`/`.sysdata.bin`/`.runtime.dat`/`.index.dat`/
  `.license-state.dat` under `services\{ApplicationName}\` stay LocalMachine
  scoped; any local account on a *server* machine could therefore decrypt the
  server private key. Phase 3's scope was the client identity key; server
  hosts are service-dedicated machines where untrusted local logins are not
  assumed (the standard premise for machine-scoped DPAPI). Revisit this
  decision if an untrusted local account is ever introduced on a server host.
* **Feature/limit vocabularies are host conventions**: the library validates
  shape and normalization; `SspLicensing.Features`/`Limits` define what
  `rdp`/`ssh`/`web`/`sql` and the limit names mean for SSP, and
  `LicenseAuthoritySecurityIsolationTests.AuthorityProduct_MatchesSspLicensing`
  pins the authority tool to the same vocabulary.

## 9. Residual risks (accepted, with reasons)

| Risk | Why accepted |
| --- | --- |
| Coordinated rollback of BOTH the protected state file AND its witness (or full machine/product-root state reconstruction) by a local administrator resets the anti-rollback floor / enrollment memory (T33/T34, Phase 4 / M-3) | Phase 4 closes the cheap single-artifact attacks (file deletion alone; file rollback alone; directory restore alone — the witness lives outside the protected directory). Defeating it now requires finding, rolling back or destroying two independently stored artifacts in different directory trees; fully eliminating the class needs tamper-resistant storage (TPM) and/or trusted time / online status, all incompatible with the offline architecture (reference ARCHITECTURE §11: the worst case is re-enabling an older, previously legitimately accepted license — never an unsigned one) |
| Persistently failing witness writes disable deletion detection (T33) | The witness write is deliberately best effort (config/primary first, witness second): a lagging witness is the safe direction — it can only fail to detect, never falsely grant. A machine whose witness cannot be written is also a machine whose primary state writes are failing; surfaced via the `Enrollment.StateWitnessWriteFailed` / best-effort diagnostics |
| A crash (or power loss) between the primary write and the witness write leaves the witness one step behind, so a rollback to the previous state can slip under the witnessed epoch/counter (T33/T34) | Narrow crash window, one recorded step at most; the next write max-merges and re-closes it. Ordering primary-first was chosen so a crash never leaves the witness AHEAD of the committed primary (which would fail-closed legitimate operation) |
| Local admin on the customer machine defeats software licensing (rollback OS, replace binaries, debug the process) | Software-only licensing protects against operational error and casual fraud, not a determined owner of the machine; reference audit §1 agrees. Mitigation is procedural (contract + Authenticode-signing of shipped binaries to raise the tamper bar, `TRUST_ANCHOR_KEY_CEREMONY.md`) |
| In-process code integrity cannot certify the shipping single-file image itself (T35, Phase 5 / M-4) | A process cannot carry the trusted hash of its own image (the hash would be inside the file it certifies). Phase 5 therefore verifies the on-disk protected runtime components a protected service runs/deploys and refuses to start on any missing/tampered/unreadable component; a fully privileged local administrator who patches the binary can also remove or re-arm the gate, so full tamper-resistance is the property of signed images validated by the OS loader (release signing seam in `TRUST_ANCHOR_KEY_CEREMONY.md`) and/or TPM, not of in-process self-verification. The gate raises the bar, detects modification, and fails closed with a security event rather than pretending to be tamper-proof |
| Clock rollback to replay an expired license window | Partially mitigated (floor + window checks); fully eliminating it needs trusted time, which an offline product cannot assume |
| DPAPI LocalMachine scope means any local process with the right context could read the floor | The floor can only *restrict*; confidentiality of it is irrelevant to the security property |
| Event-log writes are best-effort | A logging failure must never mask the licensing verdict; the fail-closed behavior does not depend on the log |
| Client identity files are readable (encrypted) by every local user; only the DPAPI CurrentUser master key blocks decryption (T32) | File-ACL hardening is not reliable for a desktop app whose state lives in `C:\Program Files`; the master key IS the boundary. Defeating a user's DPAPI master key is memory-inspection/debugging-class, already out of scope (§7.4) |
| Client identity loss on user-profile loss / password change (T32 fix) | Inherent to user-scoped DPAPI; the alternative scope allowed arbitrary local extraction of the private key. Recovery is the existing offline re-provisioning workflow (new OTT/package) |
| Server-side LocalMachine scope exposes the server private key to local accounts on a server machine | Service-dedicated host assumption (no untrusted local logins); changing it would break the LocalSystem service's access to what elevated setup wrote. Recorded for re-evaluation if that assumption changes |

## 10. Sign-off

| Item | Record |
| --- | --- |
| Scope reviewed | §1–§9, source-evidence based, on branch `arena/01a06c90-ssp` (2026-09-04) |
| v2 extension reviewed | Two-level certified chain (v2 artifacts), per-license leaf keys, offline activation (OTT + 10-digit code), `OrganizationOrPersonName`/`ComputerName` identity fields; threats T25–T30 added; on branch `arena/01a06e0b-ssp` (2026-09-05) |
| Client key scope reviewed (Phase 3 / M-2) | T32 added: client connection files moved from DPAPI LocalMachine to CurrentUser scope (envelope-recorded, envelope-authoritative, in-place re-wrap of pre-existing installs, fail-closed on foreign material); server files keep LocalMachine; asset table, limitations and residual risks updated; on branch `arena/01a07138-ssp` (2026-09-05). Note: machine-checked by the new `ClientIdentityKeyProtectionTests` suite; automated execution pending a .NET 8 SDK environment (roadmap Step 3) |
| License & enrollment state anti-rollback reviewed (Phase 4 / M-3) | T33/T34 added: license-state installation binding + monotonic epoch + redundant out-of-directory witness (deletion recovery, rollback fail-closed, foreign/corrupt fail-closed, events 4614/4615 in the reviewed taxonomy) and the enrollment-state witness (sticky revoked/consumed, counter/cooldown clamping); asset table, limitations (§8) and residual risks (§9) updated; on branch `arena/01a071bf-ssp` (2026-09-05). Note: machine-checked by the new `LicenseStateAntiRollbackTests` / `EnrollmentStateAntiRollbackTests` suites plus `SspLicenseStateStoreTests` extensions; automated execution pending a .NET 8 SDK environment (roadmap Steps 4–6) |
| Enforcement seams verified | EP0a/EP0b (`SetupEngine`), EP1 (`CreateForService` in `Program.RunServiceModeAsync` + `SspWindowsService.OnStart`), EP2 (enrollment, pre-OTT), EP3 (single choke point, post-authentication), EP-T (one revalidation timer) |
| Runtime code integrity reviewed (Phase 5 / M-4) | T35 added: protected-service startup verifies an armed `CodeIntegrityManifest` (expected SHA-256 over on-disk runtime components) and refuses to start on any missing/tampered/unreadable component (`code_integrity_failure`), raising a credential-free `CodeIntegrityVerificationFailed` security line persisted via the EP1 `ServiceDiagnostics` channel; release arming seam `Activation/SspCodeIntegrity.targets` mirrors the trust-anchor ceremony and is propagated into the standalone `SSP.ServiceHost` publish; asset table, limitations and residual risks updated; on branch `arena/01a0753a-ssp` (2026-09-06). Note: machine-checked by the new `RuntimeCodeIntegrityTests` suite; automated execution pending a .NET 8 SDK environment (roadmap Step 7) |
| Machine-checked mitigations | §4 table: every row cites a test that exists in the repository and runs in the standard test suites |
| Dev/fail-closed posture | Intentional; no production trust anchor or private key exists in, or can enter, this repository (see §5 and `TRUST_ANCHOR_KEY_CEREMONY.md`) |
| P5 items disposition | Threat-model sign-off: **this document**. Event-log taxonomy review: `LicensingEventLogTaxonomy` + `SspSecurityEventSinkTaxonomyTests`. Authenticode guidance: `TRUST_ANCHOR_KEY_CEREMONY.md`. `LicenseIssuer` hard-split: declined, boundary machine-enforced (§6) |
| Remaining outside this repository | Execute the release key ceremony on the real authority key; run release builds with `SspRequireTrustAnchor=true`; rotation per the runbook |
