# SSP Security Corrections Roadmap

**Status:** Active — Phase 6 implementation, test source and documentation added (Step 8); build and full-suite execution blocked by the missing .NET SDK. Phase 6 is not Complete.
**Authority:** This document is the source of truth for SSP security hardening work.  
**Execution order:** Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6  
**Last updated:** 2026-09-06

## Operating rules

- Security corrections are implemented one step at a time. Do not implement all phases or all changes in one batch.
- Work must follow the execution order below; phases must not be skipped.
- After **every completed step**, update this document before starting the next step. The update must include:
  - the current status;
  - what changed;
  - affected files;
  - tests performed and their results; and
  - remaining risks and follow-up work.
- A phase may be marked **Complete** only after code review and automated tests have passed.
- The threat model must be updated after each completed phase.
- No private keys may appear in SSP.Server binaries, license files, logs, temporary files, or client packages.
- Do not weaken the existing RSA-PSS trust chain or bypass existing fail-closed behavior.
- Preserve the offline licensing architecture. No network dependency may be introduced for the corrections in this roadmap.

## Status legend

- **Not started** — no implementation work has been completed.
- **In progress** — the current step is being implemented or reviewed.
- **Blocked** — work cannot continue until the stated blocker is resolved.
- **Complete** — implementation, code review, automated tests, and threat-model update are complete.

## Progress summary

| Phase | Correction | Status | Code review | Automated tests | Threat model update |
|---|---|---|---|---|---|
| 1 | Enrollment Authentication Code Protection (M-1) | Complete | Complete (self-review) | Passed (658/658 post-merge) | Complete |
| 2 | Authentication Abuse Resistance (remaining M-1) | Complete | Complete (self-review) | Passed (658/658 post-merge) | Complete |
| 3 | Client Private Key Protection (M-2) | Complete | Complete (self-review) | Passed (658/658 post-merge) | Complete |
| 4 | License State Anti-Rollback Protection (M-3) | Complete — merged; full suite 685/685 passed | Complete (self-review) | Passed (685/685 post-merge) | Complete |
| 5 | Runtime Code Integrity Protection (M-4) | In progress — implementation complete (Step 7) | Complete (self-review) | Written (new `RuntimeCodeIntegrityTests`); execution blocked in current environment — `dotnet` unavailable | Complete |
| 6 | Clock Rollback Protection (M-6) | In progress — Step 8; validation blocked | Static self-review performed; compiler/runtime validation pending | Three new suites written; restore/build/all tests blocked (`dotnet` unavailable) | Updated (T36, migration/recovery and residuals) |

**Phase 6 baseline provenance:** the user reports Phases 1–5 merged with **697/697** tests passing. That is supplied baseline evidence, not a result reproduced in this workspace or a result for Phase 6. Earlier phase records are retained; this step does not reopen or reimplement those phases.

## Step-by-step change log

This log is append-only. Add one entry after each step; do not remove prior entries.

### Step 0 — Roadmap creation

- **Status:** Complete (roadmap only; no security implementation)
- **What changed:** Created this authoritative tracking document and recorded the required phased execution order, controls, acceptance criteria, and reporting fields.
- **Affected files:** `Security Correction.md`
- **Tests performed:** Verified the document exists at the project root and reviewed its phase ordering and required tracking fields. No product or security tests were run because no code was changed.
- **Remaining risks:** All security risks listed in Phases 1–6 remain open. Phase 1 must be completed before any later phase begins.

### Step 1 — Phase 1 implementation

- **Status:** Implementation complete; phase remains In progress because automated tests could not execute without the .NET SDK.
- **What changed:** Added durable, server-side failed Authentication Code counters per hashed OTT. Failures one and two preserve the OTT; the third removes both pending and backward-compatible legacy authorization for that hash, permanently preventing every copy of the same client package from enrolling. Added credential-free `Enrollment.AuthenticationCodeFailed` and `Enrollment.OTTRevokedAfterFailedAttempts` events and all five required test scenarios. No client or wire-protocol state changed.
- **Affected files:** `src/SSP.Core/Models/ServiceConfig.cs`; `src/SSP.Server/Runtime/ServerProtocol.cs`; `tests/SSP.Tests/F4_EnrollmentTests.cs`; `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed:** `dotnet test tests/SSP.Tests/SSP.Tests.csproj --filter FullyQualifiedName~SSP.Tests.F4_EnrollmentTests --no-restore` — **blocked before execution**: `/bin/bash: dotnet: command not found`. `git diff --check` — **passed** with no whitespace errors. Static source check confirmed the new persisted fields, both required event names, and net8.0 test target are present. Automated test status remains Blocked, not Passed.
- **Remaining risks:** The automated Phase 1 tests must be run in a .NET 8 SDK environment before this phase can be marked Complete. A local administrator capable of rolling back the protected service configuration may restore an earlier counter; roadmap Phase 4 addresses state anti-rollback. Three legitimate typing mistakes intentionally require offline reprovisioning with a new OTT/package. Phase 2 abuse-resistance review (entropy, delays, and rate limiting) remains Not started.

### Step 2 — Phase 2 implementation

- **Status:** Implementation complete; phase remains In progress because automated tests could not execute without the .NET SDK.
- **What changed:** Removed modulo bias from Authentication Code generation (`RandomNumberGenerator.GetInt32`). Added a persisted, per-hashed-OTT progressive cooldown (2s after failure 1, 10s after failure 2) that refuses to mint a new code and does not increment the Phase 1 counter. Added credential-free `Enrollment.AuthenticationCodeRateLimited`. Phase 1 three-attempt lockout is unchanged. No client, wire-protocol, or network dependency was added.
- **Affected files:** `src/SSP.Core/Crypto/TokenGenerator.cs`; `src/SSP.Core/Crypto/AuthenticationCodeAbusePolicy.cs`; `src/SSP.Core/Models/ServiceConfig.cs`; `src/SSP.Core/IO/ConfigStore.cs`; `src/SSP.Server/Runtime/ServerProtocol.cs`; `tests/SSP.Tests/F3_CryptoTests.cs`; `tests/SSP.Tests/F4_EnrollmentTests.cs`; `tests/SSP.Tests/AuthenticationCodeAbusePolicyTests.cs`; `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed:** `dotnet test tests/SSP.Tests/SSP.Tests.csproj --filter FullyQualifiedName~SSP.Tests.AuthenticationCodeAbusePolicyTests|FullyQualifiedName~SSP.Tests.F3_CryptoTests.AuthenticationCode|FullyQualifiedName~SSP.Tests.F4_EnrollmentTests --no-restore` — **blocked before execution**: `/bin/bash: dotnet: command not found`. Official `dotnet-install.sh` also failed (`SSL_ERROR_SYSCALL` to `dot.net`). `git diff --check` — **passed** with no whitespace errors. Static source check confirmed unbiased `GetInt32` generation, persisted retry-not-before fields, cooldown gate before code minting, and the rate-limit event name. Automated test status remains Blocked, not Passed.
- **Remaining risks:** Automated Phase 2 tests must be run in a .NET 8 SDK environment. Host clock changes can shorten or lengthen the cooldown (Phase 6). A local administrator can restore an earlier cooldown/counter via `.cache.dat` rollback (Phase 4). 10 decimal digits (~33 bits) remain the human-typed alphabet by design; three guesses plus cooldown keep remote brute force infeasible. Phases 3–6 remain Not started.

### Step 3 — Phase 3 implementation

- **Status:** Implementation complete; phase remains In progress because automated tests could not execute without the .NET SDK.
- **What changed:** Closed the M-2 local-impersonation path: the client identity files (`connections/{ConnectionId}/.cache.dat` private key, `.index.dat` public key, `.runtime.dat` profile) are now protected with DPAPI **CurrentUser** scope on Windows, recorded as new SSP-EAR1 envelope algorithm bytes (3 = Windows DPAPI CurrentUser, 4 = non-Windows AES-GCM CurrentUser marker), while every server-side service file (`.cache.dat`, `.sysdata.bin`, `.runtime.dat`, `.index.dat`, `.license-state.dat`) keeps the pre-existing **LocalMachine** scope the LocalSystem gateway service requires. Decryption always follows the scope recorded in the envelope (authoritative); the caller-requested scope only selects the scope of new/migrated writes. Pre-Phase-3 client files stay readable by their owner and are upgraded in place: legacy plaintext client keys migrate directly into the CurrentUser envelope, and existing LocalMachine client envelopes are best-effort re-wrapped to CurrentUser on first read — no re-enrollment, no identity change. Undecryptable material (foreign user/machine, corruption, lost user profile) fails closed through the existing spec §19 path: the load throws, files are left byte-identical, and no replacement identity is silently generated. Added the scope-determination constant `ClientInstallPaths.ClientConnectionProtectionScope`, optional `DataProtectionScope` parameters (default `LocalMachine`) on `ProtectedFileStore`/`PemStore`/`ClientConnectionState` (all existing server call sites compile and run unchanged), a `GetEnvelopeScope` diagnostic API, and six new security tests. No client, wire-protocol, OTT, Authentication-Code, or network behavior changed.
- **Affected files:** `src/SSP.Core/IO/ProtectedFileStore.cs`; `src/SSP.Core/IO/PemStore.cs`; `src/SSP.Core/IO/ClientInstallPaths.cs`; `src/SSP.Core/Models/ClientConfig.cs`; `src/SSP.Core/Models/ClientServiceBundle.cs`; `src/SSP.Client/Runtime/ClientRuntime.cs`; `tests/SSP.Tests/ClientIdentityKeyProtectionTests.cs` (new); `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed:** `dotnet test tests/SSP.Tests/SSP.Tests.csproj --filter FullyQualifiedName~SSP.Tests.ClientIdentityKeyProtectionTests --no-restore` — **blocked before execution**: `/bin/bash: dotnet: command not found`; `dot.net`, `builds.dotnet.microsoft.com`, `dotnet.microsoft.com` and `nuget.org` all unreachable from this environment (`SSL_ERROR_SYSCALL` / connection refused), so the SDK cannot be installed. `git diff --check` — **passed** with no whitespace errors. Static source verification confirmed: the CurrentUser scope constant and all six client-side `PemStore` call sites plus both `ClientConnectionState` defaults and the legacy-PEM migration pass it; the four envelope algorithm bytes (1/2 LocalMachine, 3/4 CurrentUser) and `GetEnvelopeScope` exist; envelope scope is authoritative for decryption; the re-wrap migration is best-effort while plaintext migration keeps its pre-existing contract; and no server-side file (`ConfigStore.cs`, `SspLicenseStateStore.cs`, `ServerProtocol.cs`, `SetupEngine.cs`, `Program.cs`, `SspWindowsService.cs`) was modified. All six new test methods are present and reference only existing APIs. Automated test status remains Blocked, not Passed.
- **Remaining risks:** The automated Phase 3 tests (and the full existing suite) must be run in a .NET 8 SDK environment before this phase can be marked Complete. DPAPI CurrentUser binds the client identity to the creating user's profile: if that user account is deleted or its password changed such that the old DPAPI master key is unreachable, the connection's identity is unrecoverable and the connection must be re-provisioned offline with a new OTT/package (accepted trade-off, documented in the threat model). A non-admin local user can still read the encrypted file bytes; extraction now additionally requires defeating the user-scoped DPAPI master key (memory-inspection/debugging class, accepted residual risk in the threat model). The same LocalMachine-scope exposure on the server-side `.sysdata.bin` (server private key) is out of Phase 3 scope and recorded as a remaining risk. Phase 4 (anti-rollback), Phase 5 (code integrity) and Phase 6 (clock) remain Not started.

### Step 4 — Phase 4 implementation (part 1): installation binding + monotonic state epoch

- **Status:** Implementation complete; automated validation blocked in the current environment (`dotnet` unavailable). Phase 4 remains In progress — the redundant witness (Step 5) and the enrollment-state application (Step 6) follow.
- **What changed:** `LicenseStateRecord` gained two optional, restrict-only fields: `InstallationId` (the domain-separated installation identity the persisted license state is bound to) and `StateEpoch` (a monotonic write counter). `SspLicenseStateStore.Save` stamps the binding (adopting legacy pre-Phase-4 records on their first save) and advances the epoch as `max(record, on-disk) + 1`, so a cross-process last-writer-wins save can never move the counter backwards. `SspLicenseStateStore.Load` fails closed (`InvalidDataException` → `state_store_unavailable` → deny) when a record names a *different* installation — replaying another machine's (or another installation's) state can no longer silently replace this installation's floor. `SspInstallationIdentityProvider` gained `GetLicenseStateBindingId()` (SHA-256 over the same MachineGuid with the new `SspLicensing.LicenseStateBindingPurposeTag`; null on hosts without a machine identity, mirroring the license-binding semantics), and the production composition (`SspActivationService.Create`) passes it into the store. The single-argument `SspLicenseStateStore(path)` constructor and every existing call site compile and behave unchanged except for the added stamps; unbound stores (no binding id configured) keep the exact pre-Phase-4 behaviour. Four new tests pin the stamping, the foreign-record fail-closed path, the unbound compatibility path, and the legacy adoption/upgrade path.
- **Affected files:** `src/SSP.Activation/Models/LicenseStateRecord.cs`; `src/SSP.Core/Activation/SspLicensing.cs`; `src/SSP.Server/Activation/SspInstallationIdentityProvider.cs`; `src/SSP.Server/Activation/SspLicenseStateStore.cs`; `src/SSP.Server/Activation/SspActivationService.cs`; `tests/SSP.Tests/Activation/SspLicenseStateStoreTests.cs`; `docs/THREAT_MODEL.md` (Step 4 notes); `Security Correction.md`.
- **Tests performed:** `dotnet test` — **blocked before execution**: `dotnet: command not found` in this environment (all .NET endpoints unreachable). `git diff --check` — passed. Static verification: constructor default parameters preserve every existing single-argument call site; the record's new fields are nullable/defaulted so legacy JSON deserializes unchanged; the epoch stamp is `Math.Max`-based and cannot regress; the binding check only fires when both the store and the record carry a binding. Automated test status remains Blocked in this environment; the new tests must run in the .NET 8 SDK environment (Step 4 test names: `Save_StampsInstallationBindingAndMonotonicEpoch`, `Load_FailsClosed_WhenRecordBoundToAnotherInstallation`, `Load_WithoutConfiguredBinding_AcceptsAnyRecord`, `LegacyRecord_WithoutBinding_IsAdoptedAndUpgradedOnSave`).
- **Remaining risks:** Binding alone does not detect deletion or rollback of the state *file* (a rolled-back copy of this installation's own record still carries this installation's binding) — that is Step 5's witness. Clock-based rollback detection remains excluded (Phase 6).

### Step 5 — Phase 4 implementation (part 2): redundant witness with deletion recovery and rollback detection

- **Status:** Implementation complete; automated validation blocked in the current environment (`dotnet` unavailable). Phase 4 remains In progress — the enrollment-state application (Step 6) follows.
- **What changed:** A redundant, envelope-encrypted **witness** of the monotonic license-state values (installation binding, state epoch, highest accepted floor, last-accepted and activated license ids) is now maintained OUTSIDE the licensing directory, one level above it (`.ssp-state-witness/license/{sha256(directory)}/.witness.dat`; helper `SspStateWitnessPaths` in SSP.Core.IO, file name registered in `ProtectedFileStore` so every witness is encrypted at rest). `SspLicenseStateStore.Load` now: (a) reads the witness first and fails closed when it is corrupt, undecryptable, plaintext or bound to a different installation; (b) treats a **missing state file with an intact witness as a deletion attempt** — the floor and activation state are recovered from the witness (a durable lower bound; it can only restrict), `LicenseStateDeletionRecovered` is reported, and the machine is NOT treated as freshly installed; (c) treats a **state file whose epoch is lower than the witnessed epoch as a rollback** — the load fails closed and `LicenseStateRollbackDetected` is reported. `Save` writes the primary first and then max-merges the witness (never regressing epoch or floor); the witness write is best effort because a lagging witness is the safe direction. Two new credential-free event types (`LicenseStateRollbackDetected` = 14, `LicenseStateDeletionRecovered` = 15, both Warning in the reviewed event-log taxonomy, ids 4614/4615) carry the detections; the taxonomy tests were extended accordingly. The production composition passes the event sink, clock and canonical witness path into the store, and `--license-status`/`DescribeStatus` reports the witness path. A missing witness is never a violation (the primary stays authoritative and the next save re-establishes it). Fourteen new tests pin deletion recovery (floor + activation state, twice), rollback fail-closed (unit + end-to-end), the corrupt/plaintext/foreign-witness fail-closed paths, witness monotonicity, witness encryption at rest, fresh-install behaviour, missing-witness-is-no-violation, path-derivation consistency, and the three end-to-end scenarios (deleted-state revival denied; rolled-back state fails closed and denies a tunnel; a NEWER license still recovers after a deletion attempt — fail-closed without bricking).
- **Affected files:** `src/SSP.Core/IO/ProtectedFileStore.cs`; `src/SSP.Core/IO/StateWitnessPaths.cs` (new); `src/SSP.Server/Activation/SspLicenseStateWitness.cs` (new); `src/SSP.Server/Activation/SspLicenseStateStore.cs`; `src/SSP.Server/Activation/SspLicensePaths.cs`; `src/SSP.Server/Activation/SspActivationService.cs`; `src/SSP.Activation/Models/LicenseSecurityEvent.cs`; `src/SSP.Server/Activation/SspSecurityEventSink.cs`; `tests/SSP.Tests/Activation/LicenseStateAntiRollbackTests.cs` (new); `tests/SSP.Tests/Activation/SspSecurityEventSinkTaxonomyTests.cs`; `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed:** `dotnet test` — **blocked before execution**: `dotnet: command not found` in this environment. `git diff --check` — passed. Static verification: every existing single-argument `SspLicenseStateStore(path)` call site compiles unchanged (all new parameters are optional); the witness file name is in `ProtectedFileNames` so witnesses are encrypted at rest on every platform; the epoch/rollback rule is strict-inequality only (equal epochs with different floors — the legitimate cross-process race — never trip detection); deletion recovery returns a restrict-only lower bound and the signed artifact remains the root of trust; the two new enum members are covered by the exhaustive taxonomy switch and the vocabulary pin (13→15). Automated test status remains Blocked in this environment; the new tests must run in the .NET 8 SDK environment.
- **Remaining risks:** A local administrator who restores/reconstructs BOTH the licensing directory AND the witness tree (or the whole machine/product-root state) still resets the floor — the documented coordinated-rollback residual (software-only, offline; needs TPM/trusted time to eliminate). The witness write is best effort: a persistently failing witness write disables deletion detection without any other effect. Cross-process last-writer-wins races can transiently under-report the floor until the next save max-merges (pre-existing class, unchanged). Clock-based rollback detection remains excluded (Phase 6).


### Step 6 — Phase 4 implementation (part 3): enrollment-state anti-rollback (Phase 1/2 state)

- **Status:** Implementation complete; automated validation blocked in the current environment (`dotnet` unavailable). This completes the Phase 4 implementation; the phase can be marked Complete after code review and automated execution in a .NET 8 SDK environment.
- **What changed:** The same witness pattern is applied to the enrollment abuse state the Phase 1/2 controls persist in the service `.cache.dat` — the file Steps 1 and 2 explicitly deferred to Phase 4. A new enrollment witness (`.ssp-state-witness/enrollment/{sha256(service-dir)}/.witness.dat`, encrypted at rest, outside the service directory) durably remembers, per hashed OTT: the highest failed-Authentication-Code count, the latest cooldown instant, and the sticky *revoked* and *consumed* verdicts. `ServerProtocol` now: (a) loads the witness on every enrollment attempt and fails closed (rejection + `Enrollment.StateWitnessUnavailable`) when it is corrupt, undecryptable, plaintext or foreign; (b) rejects an OTT the witness records as revoked or consumed — restoring an old `.cache.dat` can no longer resurrect a revoked OTT or re-spend a consumed one (`Enrollment.StateRollbackDetected`); (c) clamps the Phase 2 cooldown to the later of the config and witnessed retry instants — a rollback cannot shrink the cooldown; (d) counts every new wrong code against everything ever witnessed (`effective = max(config-counter, witnessed+1)`), so a rolled-back counter revokes on the very next wrong code instead of buying fresh guesses, and heals the config counter to the effective value; (e) records revocation/consumption in the witness after `.cache.dat` is persisted (config first, witness second — a crash leaves the witness lagging, which is the safe direction; witness writes are best effort with a `Enrollment.StateWitnessWriteFailed` diagnostic). The `EnrollmentCooldown` test helper now applies its simulated clock change to the witness as well, so the Phase 2 cooldown tests keep testing exactly what they tested before (elapsed time), no more. Nine new tests simulate the attack the way an administrator would perform it — a byte copy of `.cache.dat` written back over the current file — and pin: revocation is final, the next wrong code after a counter rollback revokes immediately, the witnessed cooldown cannot be shrunk, a consumed OTT cannot enroll twice, a corrupt witness fails enrollment closed, consumption/revocation are witnessed, the witness is encrypted at rest, and a fresh service without a witness enrolls normally (no false positives).
- **Affected files:** `src/SSP.Server/Runtime/EnrollmentStateWitness.cs` (new); `src/SSP.Server/Runtime/ServerProtocol.cs`; `tests/SSP.Tests/EnrollmentStateAntiRollbackTests.cs` (new); `tests/SSP.Tests/Helpers/EnrollmentCooldown.cs` (witness-aware simulated clock change); `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed:** `dotnet test` — **blocked before execution**: `dotnet: command not found` in this environment. `git diff --check` — passed. Static verification: the effective-count formula `max(config-counter, witnessed+1)` was re-derived against the normal, crashed-witness-lag and post-rollback sequences (normal flow values are identical to pre-Phase-4 in every non-rollback case, so the Phase 1/2 F4 assertions hold unchanged: failure 1 → 1, failure 2 → 2, failure 3 → revoked; after a counter rollback to 0 with 2 witnessed failures, the next wrong code yields max(1, 3) = 3 → revoked); the pre-check runs after the OTT/config match and before signature verification, code generation and the EP2 licensing gate (no licensing-state leak, no behavior change for unknown OTTs); the witness stores only hashed OTT keys, counts, ISO timestamps and booleans (no OTT plaintext, code, key or fingerprint — same credential-free class as the Phase 1/2 events). Automated test status remains Blocked in this environment.
- **Remaining risks:** An administrator who restores BOTH the service directory AND the witness tree defeats the enrollment memory too (the same coordinated-rollback residual as the license state). A crash between the config and witness writes leaves the witness one step behind (safe direction; the next failure max-merges). Host-clock changes still shift cooldowns (Phase 6).

### Step 8 — Phase 6 implementation: protected local UTC checkpoint

- **Status:** In progress; implementation, tests and documentation written. Build/full-suite execution is blocked, so this is **not** a completion or release sign-off.
- **What changed:** Added versioned monotonic local UTC history to the license state and existing protected witness; strict rollback detection; required checkpoint persistence before authorization; live checks at authorization and activation as well as validation; single-sample certification/payload window checks; safe Warning events 4616/4617. A local synchronous file lease covers read/sample/merge/write/readback so time-only saves preserve concurrent renewal/activation bookkeeping. Offline operation, RSA-PSS, signed artifact formats and earlier-phase enrollment/code-integrity mechanisms are unchanged.
- **Affected files:** The activation manager, validator, time helper, state/reason/event models; native license store, witness, file lease and event taxonomy; three new clock-rollback test files and taxonomy assertions; this roadmap and `docs/THREAT_MODEL.md`. Exact paths and coverage appear in the Phase 6 Step 8 record below.
- **Tests performed:** `git diff --check` passed. Tree-sitter C# syntax parsing of all 14 changed/new C# files found no syntax errors (not compilation). Full-solution restore, build, unfiltered tests and the normal embedded build each stopped before execution with `dotnet: command not found` (exit 127). No .NET test result is claimed. Official SDK/NuGet HTTPS attempts also failed with `SSL_ERROR_SYSCALL`; a .NET SDK and restored packages remain required.
- **Code review:** Static self-review of lock ordering, migration, one-sample window checks, readback, persist-before-Valid, partial writes, event privacy and prior-phase boundaries. Compiler, analyzer and runtime validation remain pending.
- **Threat model update:** T36 added; time-state assets, admission checks, migration/recovery, strict-write availability cost and offline residuals recorded.
- **Remaining risks:** Local time history is not trusted absolute UTC. First-use/unobserved/frozen time and coordinated loss/rollback of all history remain limitations; legitimate backward corrections and large forward jumps can deny service. Both protected writes are required for licensing, but two file writes are not a power-loss-atomic transaction. See the Phase 6 record and threat model §7.1/§9.

---

# Phase 1 — Enrollment Authentication Code Protection (M-1)

**Goal:** Prevent brute-force attempts against the 10-digit Authentication Code used during client enrollment.

**Phase status:** Complete — merged; the full suite (658/658, including the Phase 1 tests) passed on the merge branch in a .NET 8 SDK environment
**Current step:** None (phase complete)
**Code review:** Complete (self-review)
**Automated tests:** Passed (658/658 post-merge validation)
**Threat model update:** Complete

### Required implementation

- Add server-side failed Authentication Code attempt tracking per OTT.
- Never store attempt counters or plaintext codes inside the client binary.
- After 3 failed Authentication Code attempts:
  - permanently revoke the OTT;
  - invalidate the pending enrollment;
  - prevent the same client package from enrolling again; and
  - return a permanent enrollment failure state.

### Required security events

- `Enrollment.AuthenticationCodeFailed`
- `Enrollment.OTTRevokedAfterFailedAttempts`

### Required tests

- First wrong code: OTT remains valid.
- Second wrong code: OTT remains valid.
- Third wrong code: OTT becomes invalid.
- Correct code after two failures: enrollment succeeds.
- Correct code after three failures: enrollment fails.

### Step completion record

#### Step 1 — Persisted failure limit and OTT revocation

- **Status:** Implementation complete; Phase 1 remains In progress pending automated execution.
- **What changed:** Persisted failed-code attempts per hashed OTT; revoked the OTT and pending enrollment on failure three; added the two required credential-free events and the five required behavioral scenarios.
- **Affected files:** `src/SSP.Core/Models/ServiceConfig.cs`; `src/SSP.Server/Runtime/ServerProtocol.cs`; `tests/SSP.Tests/F4_EnrollmentTests.cs`; `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed and results:** Filtered `F4_EnrollmentTests` command attempted but blocked because `dotnet` is not installed; `git diff --check` passed.
- **Code review:** Self-review complete; verified lock ordering, hash-only identification, revocation of duplicate legacy/pending slots, secret-free events, and no client/protocol changes.
- **Threat model update:** Complete — T31 and residual local rollback/operator lockout risks documented.
- **Remaining risks:** Run automated tests under .NET 8; Phase 4 anti-rollback and Phase 2 abuse-resistance controls remain future work.

---

# Phase 2 — Authentication Abuse Resistance (remaining M-1)

**Goal:** Review and improve Authentication Code resistance while remaining fully offline.

**Phase status:** Complete — merged; the full suite (658/658, including the Phase 2 tests) passed on the merge branch in a .NET 8 SDK environment
**Current step:** None (phase complete)
**Code review:** Complete (self-review)
**Automated tests:** Passed (658/658 post-merge validation)
**Threat model update:** Complete

### Review scope

- Authentication Code entropy.
- Brute-force resistance.
- Rate limiting.
- Progressive delay after failed attempts.
- Lockout strategy.

### Requirements

- The solution must remain offline.
- No network dependency may be introduced.
- Add automated tests for each security change.

### Step completion record

#### Step 2 — Unbiased codes and per-OTT progressive cooldown

- **Status:** Implementation complete; Phase 2 remains In progress pending automated execution.
- **What changed:** Authentication Codes are generated with unbiased CSPRNG decimal digits (first digit uniform 1–9, remaining digits uniform 0–9). After each of the first two wrong submissions the server persists a per-hashed-OTT retry-not-before timestamp (2s then 10s). A reconnect before that instant is rejected with the existing `verification failed` enrollment result, without minting or displaying a new code and without incrementing the failure counter. `Enrollment.AuthenticationCodeRateLimited` is logged without credentials. The Phase 1 three-attempt permanent OTT revocation is unchanged. The 10-digit human protocol, RSA-PSS trust chain, and offline licensing architecture are unchanged.
- **Affected files:** `src/SSP.Core/Crypto/TokenGenerator.cs`; `src/SSP.Core/Crypto/AuthenticationCodeAbusePolicy.cs`; `src/SSP.Core/Models/ServiceConfig.cs`; `src/SSP.Core/IO/ConfigStore.cs`; `src/SSP.Server/Runtime/ServerProtocol.cs`; `tests/SSP.Tests/F3_CryptoTests.cs`; `tests/SSP.Tests/F4_EnrollmentTests.cs`; `tests/SSP.Tests/AuthenticationCodeAbusePolicyTests.cs`; `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed and results:** Filtered Authentication Code / F4 / policy tests attempted but blocked because `dotnet` is not installed; `dotnet-install.sh` failed with `SSL_ERROR_SYSCALL` to `dot.net`; `git diff --check` passed.
- **Code review:** Self-review complete; verified cooldown is keyed per hashed OTT, checked after OTT proof and before code generation, fail-closed on unparsable timestamps, no wire/client/network changes, secret-free events.
- **Threat model update:** Complete — T31 extended with cooldown, unbiased digits, and `Enrollment.AuthenticationCodeRateLimited`; clock/rollback residuals documented.
- **Remaining risks:** Run automated tests under .NET 8; Phase 4 anti-rollback, Phase 6 clock protection, and Phases 3/5 remain future work. Three legitimate typing mistakes still require offline reprovisioning.

---

# Phase 3 — Client Private Key Protection (M-2)

**Goal:** Reduce local impersonation risk while preserving the current enrollment architecture.

**Phase status:** Complete — merged; the full suite (658/658, including the six Phase 3 tests) passed on the merge branch in a .NET 8 SDK environment
**Current step:** None (phase complete)
**Code review:** Complete (self-review)
**Automated tests:** Passed (658/658 post-merge validation)
**Threat model update:** Complete

### Review and implementation scope

- Review the current use of DPAPI `LocalMachine` scope.
- Analyze whether a local user without administrator privileges can extract or misuse client identity keys.
- Implement stronger protection if required.
- Ensure client identity private keys cannot be easily reused.
- Preserve the current enrollment architecture.

### Findings of the review (Step 3)

- The client identity files (`connections/{ConnectionId}/.cache.dat` = the client's 3072-bit RSA private key, `.index.dat` = public key, `.runtime.dat` = profile) live under `C:\Program Files\SSP`, whose default ACL grants Read to every local user, and no code sets restrictive ACLs (`PemStore.TryRestrictFilePermissions` is an explicit no-op on Windows).
- The files were protected with DPAPI `LocalMachine` scope (`ProtectedFileStore.Protect` → `ProtectedData.Protect(..., DataProtectionScope.LocalMachine)`) with a public, in-source optional-entropy string. Per MS-CryptProtectData, LocalMachine-scoped data "can be decrypted by any user on the computer" — so any non-admin local user could copy `.cache.dat`, call `ProtectedData.Unprotect` with the same scope/entropy, and recover the full client private key.
- Impact: with the private key an attacker process on the same machine signs the future-authorization challenge exactly like the real client (`ClientProtocol` signs the nonce/challenge; `ServerProtocol` verifies against the enrolled client public key) and impersonates the enrolled connection — a complete defeat of the enrollment identity guarantee.
- The `LocalMachine` scope is nevertheless required for the **server-side** service files: setup writes them elevated and the gateway Windows Service runs as LocalSystem and must read them. The client, in contrast, is a desktop application: the same interactive user both creates the identity and reads it back, and no other identity ever needs those files. Hence: client files move to CurrentUser scope; server files keep LocalMachine.

### Required tests

- Unauthorized local access cannot recover usable client identity keys.
- Add automated security tests for every implemented protection.

### Step completion record

#### Step 3 — DPAPI CurrentUser scope for client identity files, LocalMachine preserved for server files

- **Status:** Implementation complete; Phase 3 remains In progress pending automated execution.
- **What changed:** Client connection files are now written with DPAPI CurrentUser scope (envelope algorithm byte 3 on Windows; byte 4 scope marker on the non-Windows AES-GCM test fallback), and that scope is recorded in the envelope and authoritative for decryption. Server-side service files keep the LocalMachine scope (bytes 1/2) and all their call sites are byte- and behavior-identical (new parameters are optional, defaulting to LocalMachine). Migration: legacy plaintext client keys migrate directly into the CurrentUser envelope on first read; existing LocalMachine client envelopes remain decryptable by their owner and are re-wrapped to CurrentUser on first read (best effort — a re-wrap failure never masks a successful read; the pre-existing plaintext-migration contract, including its error propagation, is unchanged). Fail-closed: undecryptable client material (another user's/machine's envelope, corruption, lost user profile) makes the load throw through the existing spec §19 "local identity credential unavailable" path, leaves the files byte-identical, and never regenerates the identity. New `GetEnvelopeScope` diagnostic API; scope constant `ClientInstallPaths.ClientConnectionProtectionScope`; six new security tests pin the client-CurrentUser/server-LocalMachine split, the in-place re-wrap, the plaintext→CurrentUser migration, the foreign-key fail-closed behavior, and the envelope-authoritative-scope semantics. No client package, wire-protocol, OTT, Authentication-Code, licensing, or network behavior changed.
- **Affected files:** `src/SSP.Core/IO/ProtectedFileStore.cs`; `src/SSP.Core/IO/PemStore.cs`; `src/SSP.Core/IO/ClientInstallPaths.cs`; `src/SSP.Core/Models/ClientConfig.cs`; `src/SSP.Core/Models/ClientServiceBundle.cs`; `src/SSP.Client/Runtime/ClientRuntime.cs`; `tests/SSP.Tests/ClientIdentityKeyProtectionTests.cs` (new); `docs/THREAT_MODEL.md`; `Security Correction.md`.
- **Tests performed and results:** Filtered `ClientIdentityKeyProtectionTests` command attempted but blocked because `dotnet` is not installed and the SDK cannot be downloaded (all .NET endpoints unreachable); `git diff --check` passed; static source verification confirmed all scope wiring, the four envelope algorithm bytes, envelope-authoritative decryption, best-effort re-wrap, unchanged server-side files, and the presence of all six new tests (names listed in the change log Step 3). Automated test status remains Blocked, not Passed.
- **Code review:** Self-review complete; verified that (a) every client-side read/write of `.cache.dat`/`.index.dat`/`.runtime.dat` (initial generation, legacy migration, reload after enrollment, profile load/save) uses the CurrentUser scope; (b) no server-side store or service path changed scope; (c) decryption can never be forced into the wrong DPAPI scope because the envelope byte decides; (d) the re-wrap cannot create authorization or overwrite surviving credentials — it only re-encrypts already-validated content; (e) no private key material is introduced into SSP.Server binaries, license files, logs, temporary files, or client packages.
- **Threat model update:** Complete — T32 added (client identity key extraction by an unprivileged local user) with the mitigation and test evidence; asset table, known limitations, and residual risks updated.
- **Remaining risks:** Run the automated suite under .NET 8 (this phase and Phases 1–2). User-profile loss/password change makes a CurrentUser-protected identity unrecoverable → offline re-provisioning with a new OTT/package (accepted trade-off). The encrypted file bytes remain readable by other local accounts; defeating the user's DPAPI master key is in the memory-inspection/debugging class of accepted residual risk. The server-side LocalMachine scope of `.sysdata.bin` remains (out of Phase 3 scope; recorded as a remaining risk). Phase 4 anti-rollback, Phase 5 code integrity, and Phase 6 clock protection remain future work.

#### Step 3a — Build fix: make the Step 3 test file compile, plus one best-effort re-wrap defect it exposed

- **Status:** Complete for the build blockers; Phase 3 remains In progress until the suite is executed on a machine with the .NET 8 SDK.
- **What changed:** `tests/SSP.Tests/ClientIdentityKeyProtectionTests.cs` was written in Step 3 in an environment without `dotnet` and had never been compiled, so `dotnet build` / `dotnet test` failed the whole solution with three errors in that one file. They were API-misuse bugs in the test helpers, not defects in the protection they assert:
  1. `CS1503` (lines 402 and 411) at the two scope helpers — `Assert.Equal(DataProtectionScope.CurrentUser, ProtectedFileStore.GetEnvelopeScope(bytes), $"...")` (and the `LocalMachine` twin). xunit 2.5.3 has **no** `Assert.Equal` overload that takes a user message: its third parameter is a comparer (`IEqualityComparer<T>` or `Func<T, T, bool>`), which is exactly what the compiler tried to bind the string to. Both helpers now delegate to one `AssertEnvelopeScope(expected, path, what)` that carries the message through `Assert.True` and additionally renders the scope the envelope actually records, so a failure is at least as diagnosable as before.
  2. `CS1501` (line 467) in `BuildForeignKeyEnvelope` — `"SSP-EAR1"u8.CopyTo(envelope, 0)`. A UTF-8 literal is a `ReadOnlySpan<byte>`, whose `CopyTo` takes only the destination span (no start offset), unlike the `byte[]` copy the neighbouring lines use. It is now `magic.CopyTo(envelope.AsSpan(0, magic.Length))`, and the envelope offsets are derived from `magic.Length` instead of the hard-coded `9` / `8`, mirroring `ProtectedFileStore.BuildEnvelope`.
  Reading those helpers against the code they assert also exposed one real defect in the Step 3 production code, fixed here:
  3. `ProtectedFileStore.MigratePlaintextAsync` wrapped its *best-effort* scope re-wrap (remark 2 of its own contract) in `try { return WriteTextAsync(...); } catch { }`. A try around a **returned** Task only observes synchronous throws, so every asynchronous failure of the re-write — an `IOException` from `AtomicFile`, a file still held by an antivirus scanner, a DPAPI failure — escaped to the awaiting caller (`PemStore.LoadPrivateKeyAsync` / `LoadPublicKeyAsync`, `ClientConnectionState.TryLoad`) and turned an already successful read of a working legacy client identity into a hard failure, contradicting "a write failure must never mask the read". The re-wrap now runs through `await`-ed `TryRewrapEnvelopeAsync`, which swallows write failures while still propagating cancellation requested through the caller's own token. The plaintext-migration branch (remark 1) keeps its pre-Phase-3 error propagation untouched, and no scope, envelope byte, or fail-closed decision changed.
  No dependency version and no asserted property changed: the six Phase 3 tests still pin exactly the same six behaviours, and the byte layout of the foreign-envelope fixture is unchanged (magic | algorithm byte 2 | nonce | tag | ciphertext).
- **Affected files:** `tests/SSP.Tests/ClientIdentityKeyProtectionTests.cs` (test-only fixes); `src/SSP.Core/IO/ProtectedFileStore.cs` (best-effort re-wrap made asynchronous-safe, `+TryRewrapEnvelopeAsync`); `BUILD.md` (the `xunit` row now records the `Assert.Equal` comparer/message signature so the same mistake is not reintroduced); `Security Correction.md`.
- **Tests performed and results:** Still **Blocked**, not Passed — `dotnet: command not found` in this environment and every SDK/feed endpoint is unreachable (`dot.net`, `builds.dotnet.microsoft.com`, `api.nuget.org` → `SSL_ERROR_SYSCALL`), so neither `dotnet build` nor `dotnet test` could be executed here. Verified statically instead: the edited file is brace/paren/bracket balanced; a repo-wide scan for `Assert.Equal`/`Assert.NotEqual` calls with a third argument finds no other message-style call site (the only remaining 3-argument `Assert.Equal` is inside a doc comment, and `Assert.NotEqual(a, b, StringComparer.OrdinalIgnoreCase)` in `tests/SSP.Tests/Activation/Runtime/LicensingCompositionTests.cs` is a genuine overload); `grep 'u8\.CopyTo'` shows the fixed line was the only occurrence in the repository; `ReadOnlySpan<T>.CopyTo(Span<T>)` and `MemoryExtensions.AsSpan(byte[], int, int)` are the same net8.0 APIs `ProtectedFileStore` already uses (`bytes.AsSpan(0, Magic.Length)`); every package version in `BUILD.md` §2 is untouched, so the offline restore contract still holds; and all six tests were traced line by line against `ProtectedFileStore`, `PemStore`, `ClientRuntime`, `ClientConnectionState`, `ServiceConfigStore`, `AuthorisedUsersStore` and `SspLicenseStateStore`, confirming the asserted scopes match the code paths on Windows (envelope bytes 1/3, DPAPI) and on the non-Windows fallback (bytes 2/4), and that the foreign-key fixture's byte-2 envelope routes to the AES-GCM decryptor on **every** platform so it throws exactly `CryptographicException` as the test requires. The `ProtectedFileStore` change is a no-op on every path where the re-wrap write succeeds (which is the case in all six tests, so their assertions are unaffected) and only differs when that write fails asynchronously — the situation the method's own contract already required to be silent. `CA1031` ("do not catch general exception types") is *not* enabled by default in the .NET SDK analysis mode this repository uses, which the pre-existing bare `catch { /* best effort */ }` blocks in this very file already demonstrate, so the broad catch adds no warning.
- **Code review:** Self-review of the diff — both helper names and signatures are unchanged, so all 22 call sites in the file are untouched; the failure messages keep their original text and gain the recorded scope; the `CA1416` pragma pair still brackets the whole file, which is what keeps the `DataProtectionScope` references analyzer-clean on non-Windows hosts.
- **Threat model update:** Not required — no protection, scope, or fail-closed behaviour changed (T32 and its evidence stand as recorded in Step 3).
- **Remaining risks:** The authoritative check is now a plain `dotnet build` + `dotnet test` on the .NET 8 SDK machine (see `BUILD.md` §3–4); until it has run, Phases 1–3 keep their Blocked automated-test status. Nothing in this step can weaken a protection — it only made the tests that pin those protections compile.

---

# Phase 4 — License State Anti-Rollback Protection (M-3)

**Goal:** Prevent deletion, rollback, or revival of old license state.

**Phase status:** Implementation complete (Steps 4–6); automated validation pending a .NET 8 SDK environment  
**Current step:** Step 6 — implementation complete, awaiting automated validation  
**Code review:** Steps 4–6 complete (self-review)  
**Automated tests:** Written for Steps 4–6 (27 new tests: 4 + 14 + 9); execution blocked in the current environment (`dotnet` unavailable)  
**Threat model update:** Steps 4–6 complete

### Required implementation

- Bind license state to installation identity.
- Detect rollback attempts.
- Fail closed when state integrity is violated.
- Protect against state deletion, state rollback, and old license revival.

### Required tests

- Add automated tests covering deletion, rollback, old license revival, installation binding, integrity failure, and fail-closed behavior.

### Step completion record

#### Step 4 — Installation binding + monotonic state epoch

- **Status:** Implementation complete; automated execution pending a .NET 8 SDK environment.
- **What changed:** `LicenseStateRecord` gained `InstallationId` (domain-separated installation binding of the persisted license state) and `StateEpoch` (monotonic write counter). The store stamps both on save (adopting legacy records) and fails closed on load when a record names a different installation. Production composition passes `SspInstallationIdentityProvider.GetLicenseStateBindingId()` (new; `SSP-LICENSE-STATE-BIND-v1` domain separation) into the store. Unbound stores keep the exact pre-Phase-4 behaviour.
- **Affected files:** `src/SSP.Activation/Models/LicenseStateRecord.cs`; `src/SSP.Core/Activation/SspLicensing.cs`; `src/SSP.Server/Activation/SspInstallationIdentityProvider.cs`; `src/SSP.Server/Activation/SspLicenseStateStore.cs`; `src/SSP.Server/Activation/SspActivationService.cs`; `tests/SSP.Tests/Activation/SspLicenseStateStoreTests.cs`.
- **Tests performed and results:** Blocked in this environment (`dotnet: command not found`); four new tests written (`Save_StampsInstallationBindingAndMonotonicEpoch`, `Load_FailsClosed_WhenRecordBoundToAnotherInstallation`, `Load_WithoutConfiguredBinding_AcceptsAnyRecord`, `LegacyRecord_WithoutBinding_IsAdoptedAndUpgradedOnSave`); `git diff --check` passed; static verification of call-site compatibility and legacy deserialization performed.
- **Code review:** Self-review complete — binding check fires only when both sides carry a binding; epoch is `max(record, on-disk) + 1` and cannot regress; the store can still only restrict authorization; no wire-protocol, client, network, or RSA-PSS change.
- **Threat model update:** Complete for Step 4 (binding + epoch noted); the full T-entry for M-3 is added with Step 5 when the detection controls land.
- **Remaining risks:** File deletion and same-installation file rollback are still undetected — Step 5 adds the redundant witness; enrollment-counter rollback (`.cache.dat`) is Step 6.

#### Step 5 — Redundant witness: deletion recovery + rollback detection

- **Status:** Implementation complete; automated execution pending a .NET 8 SDK environment.
- **What changed:** A redundant envelope-encrypted witness of the monotonic license-state values is maintained OUTSIDE the licensing directory (`.ssp-state-witness/license/{hash}/.witness.dat`). A deleted state file with an intact witness recovers the floor and activation state from the witness (restrict-only lower bound; `LicenseStateDeletionRecovered` event); a state file older than the witnessed epoch fails closed (`LicenseStateRollbackDetected` event); corrupt/plaintext/foreign witness material fails closed; a missing witness is never a violation. `Save` writes primary-then-witness with max-merge monotonicity; the witness write is best effort. New event types 14/15 (both Warning) extend the reviewed taxonomy; `--license-status` shows the witness path.
- **Affected files:** `src/SSP.Core/IO/ProtectedFileStore.cs`; `src/SSP.Core/IO/StateWitnessPaths.cs` (new); `src/SSP.Server/Activation/SspLicenseStateWitness.cs` (new); `src/SSP.Server/Activation/SspLicenseStateStore.cs`; `src/SSP.Server/Activation/SspLicensePaths.cs`; `src/SSP.Server/Activation/SspActivationService.cs`; `src/SSP.Activation/Models/LicenseSecurityEvent.cs`; `src/SSP.Server/Activation/SspSecurityEventSink.cs`; `tests/SSP.Tests/Activation/LicenseStateAntiRollbackTests.cs` (new); `tests/SSP.Tests/Activation/SspSecurityEventSinkTaxonomyTests.cs`.
- **Tests performed and results:** Blocked in this environment (`dotnet: command not found`); 14 new tests written (see the Step 5 change-log entry for the covered scenarios); `git diff --check` passed; static verification performed.
- **Code review:** Self-review complete — the witness can only restrict (missing witness never a violation; recovered values are a durable lower bound; max-merge writes never regress); the rollback rule is strict-epoch-only so legitimate cross-process races cannot false-positive; no wire-protocol, client, network, or RSA-PSS change; no private key material anywhere new.
- **Threat model update:** Complete for Step 5 — T33 (license state deletion/rollback/revival, M-3) added with the licensing controls; asset table, limitations and residual risks updated (the enrollment half of T33/M-3 lands with Step 6).
- **Remaining risks:** Coordinated rollback of BOTH primary and witness (or full machine-state reconstruction) by a local administrator remains possible — accepted residual. Persistently failing witness writes disable deletion detection only. Clock-based detection excluded (Phase 6).

#### Step 6 — Enrollment-state anti-rollback (Phase 1/2 counters, cooldowns, revocations, consumption)

- **Status:** Implementation complete; automated execution pending a .NET 8 SDK environment.
- **What changed:** Enrollment witness (per hashed OTT: max failure count, latest cooldown instant, sticky revoked/consumed) stored outside the service directory, encrypted at rest. `ServerProtocol` rejects witness-revoked/consumed OTTs even when a rolled-back `.cache.dat` shows them pending; clamps the cooldown to the witnessed instant; counts new failures against the witnessed total (`max(config, witnessed+1)`, healing the config); records revocation/consumption in the witness after the config is persisted. New credential-free events `Enrollment.StateRollbackDetected` and `Enrollment.StateWitnessUnavailable` (+ best-effort `Enrollment.StateWitnessWriteFailed` diagnostic). The `EnrollmentCooldown` test helper applies its simulated clock change to the witness as well.
- **Affected files:** `src/SSP.Server/Runtime/EnrollmentStateWitness.cs` (new); `src/SSP.Server/Runtime/ServerProtocol.cs`; `tests/SSP.Tests/EnrollmentStateAntiRollbackTests.cs` (new); `tests/SSP.Tests/Helpers/EnrollmentCooldown.cs`.
- **Tests performed and results:** Blocked in this environment (`dotnet: command not found`); nine new tests written (revocation final; next wrong code after counter rollback revokes immediately; witnessed cooldown cannot be shrunk; consumed OTT cannot enroll twice; corrupt witness fails closed; consumption/revocation witnessed; witness encrypted at rest; fresh service enrolls normally); `git diff --check` passed; effective-count formula re-derived against normal/lag/rollback sequences.
- **Code review:** Self-review complete — the witness can only restrict (clamps are upward-only; verdicts are sticky; nothing authorizes); config-before-witness ordering on every write; pre-check leaks no licensing or witness state (same "One-Time Token rejected." as an unknown OTT); no client, wire-protocol, OTT-generation, licensing or network change; no credentials in the witness or events.
- **Threat model update:** Complete for Step 6 — T34 (enrollment state rollback) added; the §8 "Enrollment attempt tracking is local server state" limitation rewritten to reflect the witness; residual risks updated.
- **Remaining risks:** Coordinated rollback of both the service directory and the witness tree by a local administrator (accepted residual); crash-window witness lag of one write (safe direction); host-clock changes still shift cooldowns (Phase 6).

---

# Phase 5 — Runtime Code Integrity Protection (M-4)

**Goal:** Detect tampering and refuse execution rather than relying only on multiple enforcement gates.

**Phase status:** Implementation complete (Step 7); automated validation pending a .NET 8 SDK environment
**Current step:** Step 7 — implementation complete, awaiting automated validation
**Code review:** Step 7 complete (self-review)
**Automated tests:** Written for Step 7 (new `tests/SSP.Tests/RuntimeCodeIntegrityTests.cs`); execution blocked in the current environment (`dotnet` unavailable)
**Threat model update:** Complete (T35 + M-4)

### Review and design scope

Review appropriate integrity protection for local-administrator tampering with:

- `SSP.Server.exe`
- `SSP.ServiceHost.exe`
- runtime assemblies

Evaluate:

- signed binaries;
- embedded hashes;
- startup integrity verification; and
- service image validation.

### Required tests

- Modified binaries are detected.
- Protected services refuse execution.
- Add automated tests for each implemented integrity control.

### Step completion record

#### Step 7 — Runtime code-integrity gate (manifest + streaming verifier + fail-closed startup enforcement)

- **Status:** Implementation complete; automated execution pending a .NET 8 SDK environment. Phase 5 remains In progress until the new suite executes there.
- **What changed:** Added a fail-closed runtime code-integrity subsystem (M-4). A `CodeIntegrityManifest` (expected lowercase-hex SHA-256 per protected component) and a `CodeIntegrityVerifier` (streaming hash, deterministic `Ok/Missing/Tampered/Unreadable` outcomes, `IsSatisfied` only when every component verifies) live in SSP.Core (BCL only). `RuntimeCodeIntegrity` (SSP.Server) is the armed startup gate: it loads the release baseline from the embedded manifest resource, and `SspRuntimeLicense.CreateForService` calls `VerifyArmedStartup` before any licensing composition, so **both** protected-service start paths — the SCM path (`SspWindowsService.OnStart`) and the foreground `--run-once` path (`Program.RunServiceModeAsync`) — refuse to start when a protected on-disk runtime component is missing, tampered, or unreadable. On failure it raises a credential-free `[security] event=CodeIntegrityVerificationFailed` line and throws `SspActivationException` (reason `code_integrity_failure`); the existing EP1 failure channel (`ServiceDiagnostics` startup log + Windows Application log) persists it. A build that is **not armed** (no embedded manifest — the default for every developer/CI/test build) is an explicit no-op: the compiled-in trust anchor + signed license remain the only gate, so existing behaviour and the 685-suite unaffected. Arming is a release ceremony seam mirroring `SspTrustAnchor.targets`: `Activation/SspCodeIntegrity.targets` (imported by `SSP.Server.csproj`) embeds an operator-supplied JSON manifest under `SSP.CodeIntegrity.manifest.json`, enforces it with `-p:SspRequireCodeIntegrity=true`, and propagates `SspCodeIntegrityPublishArgs` into the standalone `SSP.ServiceHost` publish so the extracted per-service host image carries the same baseline. `RuntimeCodeIntegrity.BuildManifestFromFiles` computes a baseline over pristine files (release/ceremony helper, also pinned by tests). Fail-closed reason constants (`code_integrity_failure`, `code_integrity_manifest_invalid`) were added to `SspActivationException`. No client package, wire-protocol, RSA-PSS, licensing, or network change; offline operation preserved.
- **Affected files:** `src/SSP.Core/CodeIntegrity/CodeIntegrityManifest.cs` (new); `src/SSP.Core/CodeIntegrity/CodeIntegrityVerifier.cs` (new); `src/SSP.Server/Activation/RuntimeCodeIntegrity.cs` (new); `src/SSP.Server/Activation/SspCodeIntegrity.targets` (new); `src/SSP.Server/SSP.Server.csproj`; `src/SSP.Server/Activation/SspRuntimeLicense.cs`; `src/SSP.Server/Activation/ISspLicenseGate.cs` (reason constants); `tests/SSP.Tests/RuntimeCodeIntegrityTests.cs` (new); `docs/THREAT_MODEL.md`; `BUILD.md`; `Security Correction.md`.
- **Tests performed and results:** `dotnet test` — **blocked before execution**: `dotnet: command not found` in this environment and every .NET SDK/feed endpoint is unreachable, so neither `dotnet build` nor `dotnet test` could run here. `git diff --check` — **passed** with no whitespace errors. Static source verification: brace/paren balance across all new/edited files; each new name resolves to a defined type/namespace (`SSP.Core.CodeIntegrity` public, consumed by `SSP.Server`; `RuntimeCodeIntegrity` internal visible to `SSP.Tests` via the existing `InternalsVisibleTo`); `SSP.Server`/`SSP.Core`/`SSP.Tests` do **not** set `TreatWarningsAsErrors` (only `SSP.Activation`/`SSP.Activation.Tests` do, and neither is touched), so the risk of an analyzer/escalated-warning break is limited to compile errors, which are checked by API/namespace trace; the JSON (de)serializer is implemented on `Utf8JsonWriter`/`JsonDocument` (no serializer DTO-instantiation ambiguity). New test names (13): `Verify_PristineComponents_IsSatisfied`, `Verify_TamperedComponent_IsDetectedAndNotSatisfied`, `Verify_MissingComponent_FailsClosed`, `Verify_ComponentOutsideRoot_NeverReadsArbitraryFiles`, `Verify_UnreadableComponent_IsAFailure_NotAnException`, `ManifestSerializer_RoundTripsLosslessly`, `ManifestSerializer_MalformedJson_ReturnsNull`, `GuardStartup_Pristine_DoesNotThrow`, `GuardStartup_TamperedComponent_RefusesProtectedService_FailClosed`, `GuardStartup_MissingComponent_RefusesProtectedService_FailClosed`, `GuardStartup_EmptyManifest_IsANoOp_NotArmedBuildsProceed`, `CeremonyHelper_BuildManifestFromFiles_ThenGuardDetectsTampering`. Automated test status remains Blocked in this environment; the new suite must run on the .NET 8 SDK host alongside the existing 685.
- **Code review:** Self-review complete — the verifier never throws for a missing/unreadable/tampered file (each becomes a failed outcome, so a tampered component can never accidentally let a caller continue); the aggregate `IsSatisfied` is satisfiable only when the manifest is non-empty and every component is Ok; path containment prevents a malformed manifest from reading files outside the verification root; an un-armed build is byte-for-byte a no-op (only an embedded release baseline arms the gate), so no existing test/start path changes; the gate runs before any licensing composition in the single factory every protected-service start path shares; events carry no credentials and the security line + the EP1 `ServiceDiagnostics` channel persist the refusal; no private key, wire-protocol, network, or RSA-PSS change.
- **Threat model update:** Complete — T35 (patch `SSP.Server`/`SSP.ServiceHost`/runtime assemblies to bypass enforcement; M-4) added with the mitigation and test evidence; asset table, §8 known limitations and §9 residual risks updated (in particular: in-process self-verification cannot certify the shipping single-file image itself — that remains the signed-image/OS-loader control).
- **Remaining risks:** The new suite must execute under .NET 8 (this phase and prior phases). Fundamental residual (documented in the threat model §9): a fully privileged local administrator who patches the running binary can also remove or re-arm the integrity gate, so in-process integrity detects tampering and fails closed but is not tamper-proof against a determined root — fully closing that class needs Authenticode/signed images validated by the OS loader (the release signing seam) and/or TPM. Arming is operator-performed at the release ceremony (like the trust anchor); a dev/CI build ships un-armed by design and relies on the existing licensing fail-closed gate. Provisioning (SETUP MODE) uses `TryCreateForProvisioning`, which is not separately integrity-gated in this step (it runs no protected service); the EP0a/EP1 start path is gated. Phase 6 (clock) remains Not started.

---

# Phase 6 — Clock Rollback Protection (M-6)

**Goal:** Prevent system clock rollback from bypassing expiration validation.

**Phase status:** In progress — implementation written; automated validation blocked
**Current step:** Step 8 — full build and all tests must execute before completion
**Code review:** Static self-review performed; compiler/analyzer/runtime validation pending
**Automated tests:** Written; execution blocked (`dotnet` unavailable, exit 127)
**Threat model update:** Updated for Phase 6 (T36 and explicit limitations); no completion sign-off yet

### Required implementation

- Protect the last validated time.
- Detect clock rollback.
- Fail closed on rollback.
- Preserve normal operation for a valid license.

### Required tests

- Expired license with normal clock fails.
- Expired license after clock rollback fails.
- Valid license continues working normally.

### Step completion record

#### Step 8 — Monotonic UTC history, mandatory protected witness and live enforcement

- **Status:** Implementation/test source/docs added on `arena/01a07576-ssp`; **not Complete**, because no compiler or .NET test has executed here.
- **What changed:**
  - `ClockStateVersion = 1` and `LastObservedUtc` distinguish initialized history from legacy records (version 0). The lower bound is the maximum of the primary, witness, legacy `LastValidatedUtc` and remembered in-process time. A UTC observation below that bound fails closed (`clock_rollback_detected`); equality and UTC-equivalent offset changes are allowed. There is no tolerance/grace period.
  - Both signed validity windows use the same captured UTC after the RSA-PSS signatures and bindings pass. An observation of expiration or not-yet-valid time is persisted as **restrictive time only**, not license acceptance or activation. An expired artifact cannot become valid by rewinding after its expiration was checkpointed.
  - Validation, pre-publication `Apply`, pending activation and every authorization of a currently valid license use the shared guard. Acceptance/checkpoint writes finish before publishing Valid. New service/enrollment/feature/session/tunnel decisions do not wait for the periodic timer to detect time failure; policy evaluation requires the manager to remain Valid, so a later failed/missing reload cannot hide a time denial by changing its diagnostic reason. Already-admitted tunnels retain the existing release semantics.
  - The optional `ILicenseTimeStateLock` seam leaves `ILicenseStateStore` unchanged. SSP's reentrant `.license-state.dat.lock` lease serializes the complete read/sample/merge/save/readback across store instances/processes; its five-second acquisition bound uses elapsed time, not UTC. The empty lock file is never deleted. Replacement stores without this seam are synchronized only when callers share the same instance.
  - The existing out-of-directory, envelope-encrypted witness now retains the version/time fields, including recovery when the primary is missing. Time is max-merged independently of sequence/epoch. Initialized state/witness metadata must be complete and supported; initialized plaintext state, corrupt/unreadable/foreign history and critical write/readback failures deny.
  - **Persistence compatibility boundary:** valid legacy state (with or without a validation timestamp) still migrates without losing sequence, installation binding or activation. Saves now validate existing history even for legacy callers: unreadable bytes could contain initialized time, so the old corrupt-state overwrite/best-effort epoch read must not erase that evidence. This is required to preserve the new time floor, not a redesign of the Phase 4 binding/epoch/sequence rules. Legacy sequence-only witness writes and the enrollment witness keep their existing best-effort policy; licensing time checkpoints require **both** protected writes. A missing witness is recoverable only if its repair succeeds before authorization.
  - `ClockRollbackDetected = 16` / `TimeIntegrityUnavailable = 17` append Warning event IDs **4616/4617**; existing IDs are unchanged. Reasons distinguish rollback, a throwing clock (`time_integrity_unavailable`) and state/lease/persistence failure (`state_store_unavailable`). Diagnostics contain only identifiers, timestamps, reason codes and exception type names; reporting cannot mask the denial or retry a failing clock.
- **Affected production files:**
  - `src/SSP.Activation/Models/LicenseStateRecord.cs`
  - `src/SSP.Activation/Models/LicenseReasons.cs`
  - `src/SSP.Activation/Models/LicenseSecurityEvent.cs`
  - `src/SSP.Activation/Validation/LicenseTimeIntegrity.cs` (new)
  - `src/SSP.Activation/Validation/LicenseValidator.cs`
  - `src/SSP.Activation/LicenseManager.cs`
  - `src/SSP.Server/Activation/SspLicenseStateFileLock.cs` (new)
  - `src/SSP.Server/Activation/SspLicenseStateStore.cs`
  - `src/SSP.Server/Activation/SspLicenseStateWitness.cs`
  - `src/SSP.Server/Activation/SspSecurityEventSink.cs`
- **Affected tests/docs:**
  - `tests/SSP.Activation.Tests/Security/ClockRollbackTests.cs` (new)
  - `tests/SSP.Tests/Activation/ClockRollbackStateTests.cs` (new)
  - `tests/SSP.Tests/Activation/Runtime/ClockRollbackEnforcementTests.cs` (new)
  - `tests/SSP.Tests/Activation/SspSecurityEventSinkTaxonomyTests.cs`
  - `Security Correction.md`; `docs/THREAT_MODEL.md`
- **Code review:** Static self-review performed, including the existing production composition, runtime choke points, protected-file writer and prior security tests. No issuer/trust-anchor, key scope, enrollment abuse policy, wire protocol, code-integrity gate, project dependency or network configuration was changed. Automated validation remains mandatory.
- **Threat model update:** T36 plus updates to T3/T11/T33, state assets, clock assumptions, recovery and residual risks in `docs/THREAT_MODEL.md`. The historical `_reference/SSP.Activation/docs/SECURITY_AUDIT_REPORT.md` was consulted, not edited; M-6 here is the roadmap identifier, not an invented numbered audit finding.

**Test source added (all execution pending):**

| Coverage | Source |
| --- | --- |
| Forward/equal UTC, offset equivalence, inclusive not-before, exclusive expiry, same-license checkpoint refresh, one sample for both windows | `ClockRollbackTests` |
| First-load and previously valid expiration cannot be revived; file-backed fresh-manager restart; legacy history; invalid versions; remembered time after clock/write failure | `ClockRollbackTests` |
| Clock exceptions; load/save/discarded or unexpectedly advanced readback failure; failure or rollback between validation and Apply; delayed successful validation cannot clear lockdown; events/privacy and logging failure | `ClockRollbackTests` |
| Encrypted/max-merged copies; independent witness time; primary deletion and fresh composition; missing-witness repair; migration with/without timestamps; malformed/plaintext/foreign/replayed history | `ClockRollbackStateTests` |
| Actual primary/witness write faults (blocked atomic `.tmp` paths), missing-witness repair failure, unavailable lease, distinct-instance concurrency, delayed time writer vs renewal/activation | `ClockRollbackStateTests` |
| Cross-process exclusive lease (filtered child testhost, no production test switch or additional dependency) | `ClockRollbackStateTests.FileLease_IsExclusiveAcrossProcesses` |
| Every admission facade immediately denies; independent certification/payload expiry; pending activation and activation-write failure; startup/timer/recovery; non-destructive denial | `ClockRollbackEnforcementTests` |
| Real authenticated handshake denies new slots while an existing admission is retained; real enrollment denial issues no code and preserves the Phase 1/2/4 enrollment state | `ClockRollbackEnforcementTests` |
| All 17 event types and stable Warning IDs 4616/4617 | `SspSecurityEventSinkTaxonomyTests` |

**Validation attempts and actual results (2026-09-06):**

| Command/check | Result |
| --- | --- |
| `git diff --check` | Passed; no whitespace errors |
| Tree-sitter C# parse of changed/new production and test sources | No syntax parse errors in 14 files; **not** a C# build, analyzer run or test result |
| `dotnet restore SSP.sln -p:SSP_SKIP_EMBED=true` | Blocked before restore: `dotnet: command not found`, exit 127 |
| `dotnet build SSP.sln --no-restore -p:SSP_SKIP_EMBED=true` | Blocked before compilation: same missing SDK, exit 127 |
| `dotnet test SSP.sln --no-build --no-restore -p:SSP_SKIP_EMBED=true` (no filter) | Blocked before discovery/execution: same missing SDK, exit 127; **no pass count** |
| `dotnet build SSP.sln` (normal embedded build) | Blocked before compilation: same missing SDK, exit 127 |

**Remaining risks and required follow-up:**

- Run restore, the whole-solution build and **all tests**, not just the new suites, with .NET 8; resolve every compiler/analyzer/test failure before marking Phase 6 Complete. Validate the Windows DPAPI path and the normal production embedded build with its runtime packs. `SSP_SKIP_EMBED=true` is the existing test workflow, never a shipping artifact.
- The supplied **697/697** baseline has not been reproduced here and is not a Phase 6 result. SDK/download availability is an environment blocker, not evidence that the new code passes.
- This is protected **local history**, not authoritative UTC. No history on first install, an expiration never observed/checkpointed, frozen/nonregressing manipulated time, coordinated restoration/deletion of all state/witness history, and privileged OS/process/code tampering remain outside the guarantee.
- Any backward UTC correction is deliberately restrictive. An accidental large forward jump can raise the floor and deny until UTC reaches it again. Correct the clock and restore state-store availability, then fully revalidate a currently valid signed artifact; do not reset/delete the checkpoint or weaken the signed validity windows to recover.
- Mandatory writes add local I/O/lock latency and make storage/lease availability necessary for new admissions. A failed write retains observed time in the guard that saw it; another/fresh guard cannot reconstruct an observation which reached neither durable copy, including after process/power loss. Primary-first/witness-second writes are not one power-loss-atomic transaction; partial writes fail the current call, and retained copies restrict subsequent validation. Coordinated rollback of all surviving evidence remains possible for the host owner.
- Phase 2 cooldown calculations are unchanged. The licensing gate precedes code generation and denies observed licensing time rollback; this phase does not replace the separate enrollment clock or claim to make it authoritative. Already-admitted tunnels are not forcibly terminated, and per-packet time checking is not introduced.

---

## General security acceptance checklist

Use this checklist for every phase and record evidence in the step completion record:

- [ ] No private keys appear in SSP.Server binaries.
- [ ] No private keys appear in license files.
- [ ] No private keys appear in logs.
- [ ] No private keys appear in temporary files.
- [ ] No private keys appear in client packages.
- [ ] Existing RSA-PSS trust chain is preserved.
- [ ] Existing fail-closed behavior is preserved.
- [ ] Offline licensing architecture is preserved.
- [ ] Automated tests cover the security change.
- [ ] Code review is complete.
- [ ] Threat model documentation is updated.
- [ ] Remaining risks are documented.
