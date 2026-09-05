# SSP Security Corrections Roadmap

**Status:** Active — Phase 3 implemented; automated validation blocked because the .NET SDK is unavailable in the current environment
**Authority:** This document is the source of truth for SSP security hardening work.  
**Execution order:** Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6  
**Last updated:** 2026-09-05

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
| 1 | Enrollment Authentication Code Protection (M-1) | In progress | Complete (self-review) | Blocked — `dotnet` unavailable | Complete |
| 2 | Authentication Abuse Resistance (remaining M-1) | In progress | Complete (self-review) | Blocked — `dotnet` unavailable | Complete |
| 3 | Client Private Key Protection (M-2) | In progress | Complete (self-review) | Blocked — `dotnet` unavailable | Complete |
| 4 | License State Anti-Rollback Protection (M-3) | Not started | Not started | Not started | Not started |
| 5 | Runtime Code Integrity Protection (M-4) | Not started | Not started | Not started | Not started |
| 6 | Clock Rollback Protection (M-6) | Not started | Not started | Not started | Not started |

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

---

# Phase 1 — Enrollment Authentication Code Protection (M-1)

**Goal:** Prevent brute-force attempts against the 10-digit Authentication Code used during client enrollment.

**Phase status:** In progress — implementation complete; automated validation blocked
**Current step:** Step 1 — awaiting execution in a .NET 8 SDK environment
**Code review:** Complete (self-review)
**Automated tests:** Blocked — `dotnet` is unavailable in the current environment
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

**Phase status:** In progress — implementation complete; automated validation blocked
**Current step:** Step 2 — awaiting execution in a .NET 8 SDK environment
**Code review:** Complete (self-review)
**Automated tests:** Blocked — `dotnet` is unavailable in the current environment
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

**Phase status:** In progress — implementation complete; automated validation blocked
**Current step:** Step 3 — awaiting execution in a .NET 8 SDK environment
**Code review:** Complete (self-review)
**Automated tests:** Blocked — `dotnet` is unavailable in the current environment
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

---

# Phase 4 — License State Anti-Rollback Protection (M-3)

**Goal:** Prevent deletion, rollback, or revival of old license state.

**Phase status:** Not started  
**Current step:** None  
**Code review:** Not started  
**Automated tests:** Not started  
**Threat model update:** Not started

### Required implementation

- Bind license state to installation identity.
- Detect rollback attempts.
- Fail closed when state integrity is violated.
- Protect against state deletion, state rollback, and old license revival.

### Required tests

- Add automated tests covering deletion, rollback, old license revival, installation binding, integrity failure, and fail-closed behavior.

### Step completion record

For each Phase 4 step, add a subsection here containing:

- **Status:**
- **What changed:**
- **Affected files:**
- **Tests performed and results:**
- **Code review:**
- **Threat model update:**
- **Remaining risks:**

---

# Phase 5 — Runtime Code Integrity Protection (M-4)

**Goal:** Detect tampering and refuse execution rather than relying only on multiple enforcement gates.

**Phase status:** Not started  
**Current step:** None  
**Code review:** Not started  
**Automated tests:** Not started  
**Threat model update:** Not started

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

For each Phase 5 step, add a subsection here containing:

- **Status:**
- **What changed:**
- **Affected files:**
- **Tests performed and results:**
- **Code review:**
- **Threat model update:**
- **Remaining risks:**

---

# Phase 6 — Clock Rollback Protection (M-6)

**Goal:** Prevent system clock rollback from bypassing expiration validation.

**Phase status:** Not started  
**Current step:** None  
**Code review:** Not started  
**Automated tests:** Not started  
**Threat model update:** Not started

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

For each Phase 6 step, add a subsection here containing:

- **Status:**
- **What changed:**
- **Affected files:**
- **Tests performed and results:**
- **Code review:**
- **Threat model update:**
- **Remaining risks:**

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
