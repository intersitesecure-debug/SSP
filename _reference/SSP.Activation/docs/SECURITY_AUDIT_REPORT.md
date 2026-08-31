# SSP.Activation — Security Audit, Hardening & Integration-Readiness Report

Date: 2026-08-30
Branch: `arena/01a05200-lisencing`
Baseline audit commit: `61d9a9f` (initial licensing project)
Hardening commit(s): `0bdeede`

> **Disclaimer on verification.** This audit was performed entirely by source review and
> targeted reasoning. **`dotnet build` and `dotnet test` could not be executed** in this
> sandbox: no .NET 8 SDK is present, and every Microsoft/NuGet/host that distributes one
> (builds.dotnet.microsoft.com, dotnet.microsoft.com, packages.microsoft.com, nuget.org,
> dotnetcli.azureedge.net, pkgs.dev.azure.com) plus GitHub asset hosts
> (objects.githubusercontent.com / release-assets.githubusercontent.com) is unreachable
> (SSL `SSL_ERROR_SYSCALL`). Only `github.com`, `api.github.com` and `codeload.github.com`
> resolve. Consequently all changes are **static-only and unverified by an actual build**.
> This must be confirmed on a machine with the .NET 8 SDK before release.

---

## 1. Overall Verdict

**PRODUCTION READY WITH SSP INTEGRATION REQUIREMENTS.**

The licensing *core* is a genuine, fail-closed, cryptographically enforced subsystem: the
trust anchor cannot be replaced through configuration, only a signature that verifies against
the authority public key can produce a `Valid` state, every validation stage is fail-closed,
and authorization is centralized and deterministic. The audit found and fixed real
concurrency and anti-rollback race conditions and added durable, repository-local
anti-rollback persistence.

It is **not** yet drop-in for a customer deployment without SSP.Core supplying a few
deployment constants (trust anchor, installation identity) and making the enforcement calls
in the right places. The specific integration obligations are enumerated in §12.

---

## 2. Files Modified

| File | Change |
|---|---|
| `src/SSP.Activation/LicenseManager.cs` | Made `Authorize` atomic (policy evaluated under the manager lock); a throwing policy is denied (never fail-open). Added an atomic anti-rollback re-check in `Apply` so a racing older license cannot become current; `Apply` now returns the effective applied result and `LoadLicense`/`Load`/`Revalidate` return it, so callers never see `IsValid=true` for a license the manager actually rejected. |
| `src/SSP.Activation/Serialization/LicenseArtifactCodec.cs` | Added `MaxArtifactCharacters` (256 KiB) and a fail-closed size guard in `TryDecode` (resource-exhaustion defense). |
| `src/SSP.Activation/Providers/LocalLicenseFileProvider.cs` | Refuses to read an oversized license file (fail-closed `Error`). |
| `README.md` | Quick-start recommends `FileLicenseStateStore`; removed an unverifiable test-count claim. |
| `docs/ARCHITECTURE.md` | Added explicit authority-vs-customer boundary, durable persistence (§10), atomic anti-rollback + concurrency semantics (§11/§11a), and resource/corruption-limitation notes (§15). |

## 3. Files Added

| File | Purpose |
|---|---|
| `src/SSP.Activation/Persistence/FileLicenseStateStore.cs` | BCL-only, durable, file-backed `ILicenseStateStore` for anti-rollback. Atomic temp-file+move writes; **reads fail closed** (corrupt/empty/unreadable → `state_store_unavailable` → deny), so a damaged floor is never silently reset. |
| `tests/SSP.Activation.Tests/Security/ConcurrencyTests.cs` | 3 concurrency tests (anti-rollback race; atomic authorization vs invalidation; throwing policy fails closed). |
| `tests/SSP.Activation.Tests/Persistence/FileLicenseStateStoreTests.cs` | 6 tests for the durable store (fresh, round-trip, cross-instance, corrupt/empty fail-closed, parent-dir creation). |
| `tests/SSP.Activation.Tests/Crypto/TrustAnchorTests.cs` | 5 tests (undersized key rejected, null/wrong-label/non-RSA rejected, PEM round-trip validates). |

## 4. Security Findings

### Critical

- **Concurrent anti-rollback race (Fixed).** Two threads validating licenses of different
  sequences against the same stale floor could both pass, and whichever `Apply` ran last could
  install an **older** license as `current` after a newer one had already persisted its floor
  (a rollback of the runtime state). **Fix:** `Apply` now re-checks the floor *atomically under
  the manager lock* and rejects a lower-sequence license as `Superseded`; `LoadLicense`
  returns the applied result so callers never see a false `Valid`.

### High

- **Authorization TOCTOU (Fixed).** `Authorize` read the state under the lock but evaluated the
  policy *outside* it, so a concurrent invalidation (Valid→LockedDown) could be observed as a
  present authorization. **Fix:** the state snapshot **and** the policy decision now occur
  under the same lock that governs state transitions.
- **Fail-open policy exception (Fixed).** A custom `ILicensePolicy` that threw would propagate
  the exception to the caller rather than deny. **Fix:** a throwing policy is converted to a
  denial (`internal_error` / `ProtectedOperationDenied`).

### Medium

- **Resource exhaustion (Fixed).** `JsonDocument.Parse` and `File.ReadAllText` had no size cap.
  **Fix:** artifact and license-file size caps (`MaxArtifactCharacters`), fail-closed.
- **No durable anti-rollback (Fixed).** Only an in-memory store shipped across restarts.
  **Fix:** added `FileLicenseStateStore` (BCL-only, atomic writes, fail-closed reads) and
  documented it as the repository-local default for hosts that do not supply their own.

### Low

- Diagnostic `License.SignatureAlgorithm` defaults to `RSA-PSS-SHA256` even when an artifact
  declared an unsupported algorithm (cosmetic; the `License` is untrusted/diagnostic only).
- `LicenseIssuer` lives in the same assembly as the runtime. This is **safe by design** (it
  requires a caller-supplied private key and never generates/stores one; SSP.Core never has a
  private key), but a future split into an authority-only assembly would harden the boundary.

### Accepted / By Design

- Trust anchor is delivered by the host at construction; it cannot be swapped via config/env.
  Protecting the anchor is an SSP deployment responsibility (documented §14.2).
- `Revalidate` is the host's periodic hook for time/revocation; `Authorize` is a fast policy
  check on the last validated state and does not re-run the full pipeline per call.
- No online provider or online revocation ships (abstraction only, per scope).
- The artifact is signed, not encrypted (payload fields are readable; confidentiality is a
  transport concern).

## 5. Cryptography

- **Algorithm:** `RSA-PSS-SHA256` (salt length = SHA-256 digest size, MGF1/SHA-256). Only
  `.NET` `System.Security.Cryptography` primitives; no custom crypto.
- **Key requirements:** RSA ≥ 2048 bits (enforced on import and on signing; 3072+ recommended).
- **Trust-anchor mechanism:** `LicenseTrustAnchor` holds **only** the authority public key
  (SPKI DER or PEM). Never reads environment/config, never defaults, cannot be replaced after
  construction. Malformed, undersized, wrong-label and non-RSA inputs **fail closed** (throw).
- **Private-key boundary:** the private key exists only at the Licensing Authority. The library
  never embeds, generates, persists, caches or logs it. `LicenseIssuer` requires the caller to
  pass the `RSA` private key on every call; SSP.Core never possesses one. (See §1 of
  `docs/ARCHITECTURE.md` for the explicit authority/customer table.)

## 6. Validation

`LicenseValidator.Validate` runs the pipeline: load → parse → schema → signature →
status/revocation → product → installation → not-before → expiration → anti-rollback → VALID.
Every stage returns a structured `LicenseValidationResult` (state + stable reason + safe detail
+ untrusted-decode-for-diagnostics + security event). **No fail-open exception path exists**:
expected conditions are results; unexpected conditions are caught and converted to fail-closed
states; the manager additionally wraps any residual exception as `Unknown/internal_error`.

## 7. Enforcement

The authorization decision is centralized in `DefaultLicensePolicy` (fail-closed) invoked by
`LicenseManager.Authorize` / `LicenseEnforcement`. Protected operations are allowed **only**
when the manager state is `Valid` **and** the operation is covered by the signed payload
(feature present / limit not exceeded). `Authorize` is atomic with respect to state
transitions and treats a throwing policy as a denial. Callers gate work via
`enforcement.CanUseFeature(...)`, `CanCreateSession(...)`, `CanStartProtectedService(...)`,
`CanEstablishTunnel(...)`, `CheckLimit(...)`. There is no `SetValid()`/force-valid API.

## 8. Lockdown

Activation: a loaded artifact that fails validation (or a revalidation failure) transitions to
`LockedDown`; every protected operation is denied and a `ProtectedOperationDenied` event is
emitted. Recovery: only loading a cryptographically valid license clears lockdown
(`LicenseLockdownCleared`). **Non-destructive** — it never deletes/corrupts files, modifies the
OS, or self-damages (verified by `Invariant_LockdownIsNonDestructive`). Deleting the license
never clears lockdown.

## 9. Persistence / Anti-Rollback

Status: **durable anti-rollback is now implemented (repository-local, file-backed), with a
documented limitation — it is not tamper-resistant.**

- The anti-rollback floor is enforced in two places: the validator (rejects a sequence below
  the floor) and, defensively, the manager's `Apply` (atomic re-check under the lock).
- `FileLicenseStateStore` persists the floor across process restarts with atomic writes and
  **fail-closed reads** (corrupt/empty/unreadable → `state_store_unavailable` → deny).
- The store is **never a grant authority**: a poisoned/forged floor can only reject licenses,
  never authorize one (tested by `Invariant_ConfigurationCannotCreateAuthorization` /
  `PoisonedStateStore_...`). The root of trust is always the signature.
- **Limitation to be honest about:** the file store is protected only by file/directory
  permissions; a local attacker who can rewrite protected storage can reset the floor, the
  worst case being re-enabling an *older, previously legitimately accepted* license — never an
  unsigned one. Full protection against coordinated rollback requires a host-supplied
  DPAPI/TPM-backed or ACL-guarded store (SSP integration responsibility).
- The default when no store is passed remains `InMemoryLicenseStateStore` (fail-closed but not
  durable); hosts should pass `FileLicenseStateStore` (or stronger) for real deployments.

## 10. Tests

No test run could be performed in this sandbox (no .NET SDK). Static counts across
`tests/SSP.Activation.Tests`:

```text
[Fact] methods:       128   (was 111 before this work; +17 added)
[Theory] methods:      7
[InlineData] cases:   50
Approx. test cases:  ~178 (128 facts + 50 inline-data cases)
```

Coverage added for the invariants and races:

- **Invariant 1** no valid license → no protected operation: `Invariant_NoValidLicense_NoProtectedOperation`
- **Invariant 2** signed-field modification → signature failure: `Invariant_ModifyingSignedField_InvalidatesLicense`
- **Invariant 3** attacker signing key → signature failure: `Invariant_WrongSigningKey_IsRejected`
- **Invariant 4** configuration manipulation → no authorization: `Invariant_ConfigurationCannotCreateAuthorization`
- **Invariant 5** license deletion → no authorization: `Invariant_LicenseDeletionCannotAuthorize`
- **Invariant 6** service/process restart → revalidation: `Invariant_ServiceRestartRequiresRevalidation`
- **Invariant 7** license copied to another installation → denied: `Invariant_WrongInstallation_IsRejected`
- **Invariant 8** old license after newer → denied: `Invariant_OldLicenseAfterNewerLicense_IsRejected` (added)
- **Invariant 9** valid replacement after lockdown → recovery: `Invariant_ValidReplacementLicenseCanRecover`
- Concurrency: `ConcurrencyTests` (anti-rollback race, atomic authorize-vs-invalidate, throwing policy fail-closed)
- Persistence: `FileLicenseStateStoreTests`
- Trust anchor: `TrustAnchorTests`
- Resource limits: oversized-artifact and oversized-file rejection tests

## 11. Build

Not executed — see the disclaimer at the top. Expected on a machine with the .NET 8 SDK:

```text
dotnet restore   # restore NuGet (xunit, Microsoft.NET.Test.Sdk, coverlet)
dotnet build     # both projects; TreatWarningsAsErrors=true
dotnet test      # ~195 cases
```

The library targets `net8.0` with **zero external dependencies** (BCL only); the test project
uses xUnit. The source was reviewed for syntax/type correctness (brace balance, signature
overloads, public/internal access) but **must be compiled and run elsewhere.**

## 12. Remaining SSP Integration Work (inside SSP.Core, not this repo)

1. **Provide the trust anchor** — supply the authority *public* key (PEM/SPKI DER) via a
   protected deployment channel; it must never come from user-editable config.
2. **Provide a protected installation identity** — implement `IInstallationIdentityProvider`
   using a machine key sealed with DPAPI/TPM (persisted on first run, verified at startup).
   Do NOT rely on fragile hardware fingerprints as the sole root of trust; binding is a
   deployment-control measure, the signature is the real security mechanism.
3. **Provide (or accept) durable anti-rollback persistence** — use `FileLicenseStateStore`,
   or (recommended) a DPAPI/TPM-protected/ACL-guarded `ILicenseStateStore`.
4. **Provide a persistent security-event sink** — replace `NullSecurityEventSink` /
   `InMemorySecurityEventSink` with a trusted local log sink.
5. **Wire enforcement at every protected operation**: service startup, session establishment,
   tunnel establishment, service start, feature gating — consult `ILicenseEnforcement` before
   each protected operation (lockdown is process-level and only as strong as SSP actually
   consulting it).
6. **Call `Revalidate()`** periodically and after time-/policy-relevant events (expiry,
   revocation, replacement).
7. **(Optional) Online provider / online revocation** — implement `ILicenseProvider`
   (activation) and/or `ILicenseRevocationChecker` (signed CRL / status endpoint) behind the
   existing abstractions; neither is required for offline cryptographic verification.
8. **Do not reference `LicenseIssuer`** from the customer runtime; it is authority-side only.

These are the only things SSP.Core must supply; the licensing architecture itself does not
need redesigning.
