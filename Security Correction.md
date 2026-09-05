# SSP Security Corrections Roadmap

**Status:** Active — roadmap established; no security correction has been implemented yet  
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
| 1 | Enrollment Authentication Code Protection (M-1) | Not started | Not started | Not started | Not started |
| 2 | Authentication Abuse Resistance (remaining M-1) | Not started | Not started | Not started | Not started |
| 3 | Client Private Key Protection (M-2) | Not started | Not started | Not started | Not started |
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

<!-- Add Step 1, Step 2, ... below this line. -->

---

# Phase 1 — Enrollment Authentication Code Protection (M-1)

**Goal:** Prevent brute-force attempts against the 10-digit Authentication Code used during client enrollment.

**Phase status:** Not started  
**Current step:** None  
**Code review:** Not started  
**Automated tests:** Not started  
**Threat model update:** Not started

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

For each Phase 1 step, add a subsection here containing:

- **Status:**
- **What changed:**
- **Affected files:**
- **Tests performed and results:**
- **Code review:**
- **Threat model update:**
- **Remaining risks:**

---

# Phase 2 — Authentication Abuse Resistance (remaining M-1)

**Goal:** Review and improve Authentication Code resistance while remaining fully offline.

**Phase status:** Not started  
**Current step:** None  
**Code review:** Not started  
**Automated tests:** Not started  
**Threat model update:** Not started

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

For each Phase 2 step, add a subsection here containing:

- **Status:**
- **What changed:**
- **Affected files:**
- **Tests performed and results:**
- **Code review:**
- **Threat model update:**
- **Remaining risks:**

---

# Phase 3 — Client Private Key Protection (M-2)

**Goal:** Reduce local impersonation risk while preserving the current enrollment architecture.

**Phase status:** Not started  
**Current step:** None  
**Code review:** Not started  
**Automated tests:** Not started  
**Threat model update:** Not started

### Review and implementation scope

- Review the current use of DPAPI `LocalMachine` scope.
- Analyze whether a local user without administrator privileges can extract or misuse client identity keys.
- Implement stronger protection if required.
- Ensure client identity private keys cannot be easily reused.
- Preserve the current enrollment architecture.

### Required tests

- Unauthorized local access cannot recover usable client identity keys.
- Add automated security tests for every implemented protection.

### Step completion record

For each Phase 3 step, add a subsection here containing:

- **Status:**
- **What changed:**
- **Affected files:**
- **Tests performed and results:**
- **Code review:**
- **Threat model update:**
- **Remaining risks:**

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
