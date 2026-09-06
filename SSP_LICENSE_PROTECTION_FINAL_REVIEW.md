# SSP License Protection — Final Architecture Review

**Scope:** Final review of:

- `SSP_LICENSE_PROTECTION_ARCHITECTURE_DECISION.md`
- `SSP_LICENSE_PROTECTION_IMPLEMENTATION_PLAN.md`

**Review basis:** source inspection of the current repository plus the two
reviewed documents. The repository does not have a .NET SDK available in this
environment, so all findings are source-evidence based; no build or automated
test run was performed.

**Configuration compliance:** no source code, tests, build files or
configuration were modified; no pull request was created. This review is a
deliverable document only.

---

## Review summary

| # | Checkpoint | Verdict |
| --- | --- | --- |
| 1 | Unlock Secret / wrapped service key compatible with SSP protocol | **PASS** (one implementation nuance to correct) |
| 2 | Migration from existing `.sysdata.bin` is safe | **PASS WITH CAVEAT** (terminology + audit of migration path required) |
| 3 | Computer ID binding is sufficient and recoverable | **PASS WITH EXCEPTION** (full-clone residual remains; recovery must be explicit) |
| 4 | Customer activation workflow is complete | **PASS** (clarify pre-license Computer ID step) |
| 5 | Vendor license authority workflow is complete | **PASS** (move/reissue should be concrete before release) |
| 6 | Customer UI workflow is covered | **PASS** (SSP's customer licensing surface is CLI; no GUI exists to cover) |
| 7 | Installer impact is covered | **PASS** (base installer unchanged; release manifest must be updated) |
| 8 | No security regressions introduced | **PASS WITH CONDITION** (Level 1 fallback and migration path are the only regressions to avoid) |
| 9 | Backward compatible or migration required | **PASS AS DESIGNED** (protocol/license backward compatible; one-time key migration required) |

Overall: **approve for implementation planning**, with four required corrections
before the implementation pull request:

1. Correct terminology and read path for existing `.sysdata.bin`.
2. Make the current storage layer used for `.sysdata.bin` explicit
   (`PemStore` → `ProtectedFileStore`), not a custom `ProtectedFileStore`
   bypass.
3. Add a concrete pre-license `Computer ID` generation/display path and
   a machine-unlock key creation path.
4. Add explicit unlock-loss and move/reissue support steps.

---

## 1. Is the Unlock Secret / wrapped Server Private Key design compatible with the current SSP protocol?

**Verdict: PASS.**

### Evidence

- `src/SSP.Server/Runtime/ServerProtocol.cs` requires an `RSA` private key in
  its constructor (`ServerProtocol(config, serverPrivateKey, ...)`) and uses it
  for:
  - `RsaCrypto.Sign(_serverPrivateKey, serverNonce)` when sending
    `ServerNonceMessage`;
  - `RsaCrypto.DecryptOaep(_serverPrivateKey, wrapped)` in
    `ReceiveSessionKeyAsync`.
- `src/SSP.Server/Runtime/ServerGateway.cs` ultimately creates
  `TunnelCodec(sessionKey)` and uses `RsaCrypto`/`AesGcmCrypto` indirectly
  through `ServerProtocol`. It does not read or produce the private key format.
- `src/SSP.Client/Runtime/ClientProtocol.cs` verifies the server nonce against
  the embedded `ServerPublicKeyPem` and wraps its AES session key with
  `RsaCrypto.EncryptOaep(serverRsa, ...)`.
- `src/SSP.Server/Setup/SetupEngine.cs`, `Program.RunServiceModeAsync`, and
  `SspWindowsService.OnStart` are the only places that currently create/load the
  private key. `Program.RunServiceModeAsync` already calls
  `SspRuntimeLicense.CreateForService()` before
  `PemStore.LoadPrivateKeyAsync()` and before `ServerGateway` is constructed.

### What makes it compatible

- The protocol never sees the wrapping envelope. `ServerProtocol` and
  `ServerGateway` still receive a fully imported `RSA` instance after
  `SspServiceKeyStore.Load` succeeds.
- No `Messages.cs` type, message type, frame, wire field, enrollment message,
  or tunnel codec changes are needed.
- The authority-issued `UnlockSecret` is only used at rest. It never travels on
  the wire and never replaces the existing `ServerNonce` signing or RSA-OAEP
  session key path.
- `SspServiceKeyStore` is a load-time key provider. It is a natural fit for
  `Program.RunServiceModeAsync` and the standalone `SSP.ServiceHost` image,
  which both forward to the same `SSP.Server` service-start path.

### Implementation nuance to correct before PR

The plan says `SspServiceKeyStore.Load` should:

> “Read `.sysdata.bin` through `ProtectedFileStore`.”

That is technically true, but it bypasses the existing semantic layer.
The current production path is:

```
PemStore.LoadPrivateKeyAsync(path)
  -> ProtectedFileStore.ReadTextAsync(path, LocalMachine)
     -> AtomicFile/DPAPI envelope
     -> plaintext PEM string
```

`PemStore.LoadPrivateKeyAsync` also performs the existing plaintext→encrypted
migration and Unix permission restriction. The implementation plan should say:

- `SspServiceKeyStore.Load` calls `PemStore.LoadPrivateKeyAsync` first so DPAPI
  reading, legacy plaintext migration and file hardening are preserved;
- then it detects whether the returned text is the new JSON wrapper or a
  legacy PEM;
- if JSON, it AES-GCM-decrypts using the UnlockSecret;
- if PEM, it treats the file as a legacy service key and migrates through the
  same `SspServiceKeyStore.Write` path.

This is a plan-level correction, not a protocol change.

---

## 2. Is migration from existing `.sysdata.bin` safe?

**Verdict: PASS WITH CAVEAT.**

### Evidence

- `ServiceConfig.ServerPrivateKeyPath` defaults to `.sysdata.bin`.
- `SetupEngine.RunNewApplicationAsync` writes it with
  `PemStore.SavePrivateKeyAsync(privPath, privPem)`.
- `Program.RunServiceModeAsync` loads it with
  `PemStore.LoadPrivateKeyAsync(privPath)`.
- `ProtectedFileStore.ProtectedFileNames` includes `.sysdata.bin`, so the file
  is stored in the SSP-EAR1 envelope (DPAPI LocalMachine on Windows, AES-GCM
  fallback off-Windows).

### Why it is safe

- The wrapped file is still written through `ProtectedFileStore`, so the
  DPAPI/SSP-EAR1 layer is retained. An attacker who cannot decrypt `.sysdata.bin`
  today still cannot read the wrapped form.
- `AtomicFile` writes are temp+replace, so a failed migration is unlikely to
  leave a partially rewritten `.sysdata.bin`.
- The plan fails closed if migration cannot complete.
- The plan preserves `.runtime.dat` and the public key fingerprint, so existing
  enrolled clients should keep validating the same server identity.

### Required caveat/correction

1. **Terminology.** Current `.sysdata.bin` is not “plaintext” on disk in the
   current codebase; it is a PEM-protected inside a DPAPI envelope. It is best
   described as a “legacy PEM inside the existing encrypted-at-rest envelope.”
   The migration target is “wrapped service-key envelope inside the same
   encrypted-at-rest envelope.”
2. **Migration must use `PemStore`, not a direct `ProtectedFileStore` call.**
   `PemStore.LoadPrivateKeyAsync` is responsible for the existing
   plaintext→encrypted and permission hardening behavior. Bypassing it would
   be a real migration regression for older installs.
3. **Test before release.** Add a migration test that starts with a real
   legacy DPAPI-protected `.sysdata.bin`, verifies the PEM imports, verifies
   the public key fingerprint is unchanged, rewraps, and then starts a service.
4. **Do not delete the old key before the new one is durably written.** Use
   AtomicFile semantics and verify the wrapped file after write; a failed
   write must leave the original file intact.
5. **Migration should be idempotent.** A process should be able to retry
   migration without detecting a false “corrupt” state after a previous
   partial/aborted attempt.

---

## 3. Is Computer ID binding sufficient and recoverable?

**Verdict: PASS WITH EXCEPTION.**

### Evidence

- `SspInstallationIdentityProvider` (`src/SSP.Server/Activation/SspInstallationIdentityProvider.cs`)
  reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` and returns
  `SHA-256(MachineGuid + "SSP-LICENSE-INSTALL-v1")`.
- The raw MachineGuid is never exposed in logs, license files or events.
- Existing licensing already uses this value as `payload.InstallationId`.
- The license-state store separately derives
  `SHA-256(MachineGuid + "SSP-LICENSE-STATE-BIND-v1")`.

### Why it is sufficient

- It survives ordinary reboots and hardware churn.
- It is not affected by changing MAC addresses, disk serials, NICs, or VM
  cloning in the common case.
- It is already a signed license field, so the unlock artifact can bind to the
  exact same value without inventing a second identity space.
- It is recoverable through vendor support: a changed MachineGuid means a new
  installation identity and a re-issued license/unlock artifact.

### Why it is not absolute

- A full machine image restore that reproduces the same MachineGuid, same
  licensing directory, and same machine-unlock private key remains a
  coordinated clone. This is the same residual already accepted for the
  software-only license gate.
- The plan adds a machine-unlock RSA keypair. The machine private key is stored
  in the licensing directory and protected by DPAPI LocalMachine. A copy of
  every relevant file plus the same machine/account state could still reproduce
  the whole protected installation.
- This is an accepted software-only residual, not a new defect. The
  architecture should state it explicitly in the final release notes.

### Required clarification for recoverability

- The plan should explicitly list unlock-private-key loss recovery:
  - `--license-status` must report that the machine unlock private key is
    missing, not just that the Unlock Secret is unavailable.
  - Vendor support must be able to reissue unlock material for either the same
    MachineGuid (same machine) or a new Computer ID (OS reinstall).
  - If the machine unlock key was lost while the MachineGuid is unchanged, the
    vendor should take a new machine unlock public key in a new request and
    either revoke/consume the old activation record or issue a replacement
    unlock record.
- The plan already mentions support re-issuance in the risks section; it should
  be lifted into the operator/support workflow.

---

## 4. Is the customer activation workflow complete?

**Verdict: PASS.**

The reviewed documents cover the full workflow:

1. Install SSP.
2. Resolve Computer ID.
3. Send Computer ID to vendor.
4. Vendor issues machine-bound license.
5. Import license file in SSP Customer UI.
6. Create activation request.
7. Vendor sends 10-digit code and activation-unlock artifact.
8. Import activation-unlock artifact.
9. Enter activation code.
10. SSP becomes fully activated.

### Gap to close before implementation

- The existing `--create-activation-request` command currently requires a
  loaded activation-required license: `SspActivationService.CreateActivationRequest`
  returns null unless `LastValidationResult.State == ActivationRequired`.
- In the desired commercial workflow, the customer often needs Computer ID
  **before** the vendor can issue the machine-bound license.
- This is already possible through `SSP.Server --license-status`: it prints
  `Installation id` even before a license is installed, because
  `DescribeStatus()` reads the identity provider.
- The implementation plan should make this explicit:
  - add/retain `--license-status` as the pre-license Computer ID source, or
  - add a dedicated `--show-computer-id`/`--create-installation-identity`
    command that also creates the machine-unlock keypair.
- The activation request should still be produced after the license is
  installed. The pre-license artifact is only the Computer ID (and optionally
  the machine-unlock public key needed for Level 2).

### Other completeness notes

- The plan's transcript correctly shows installation, request, import,
  activation code, and Valid transition.
- The transcript should also show the pre-license `--license-status` step.
- Level 1 (code-only) should be documented as non-default and a support-only
  fallback.

---

## 5. Is the vendor license authority workflow complete?

**Verdict: PASS.**

The plan covers the critical authority operations:

- `issue-certified` already produces a machine-bound activation-required
  license.
- New `activate --request <file> --activation-record <path> --unlock-output
  <path>`:
  - consumes the OTT single-use;
  - reads the customer's machine-unlock public key from the request;
  - generates a high-entropy UnlockSecret;
  - encrypts it to the machine public key (RSA-OAEP-SHA256);
  - signs the activation-unlock artifact with the authority root key;
  - writes `activation-unlock.json` and prints the code.
- Activation records are extended with UnlockId, sequence, UnlockSecret, and
  machine key fingerprint.
- The authority tool remains isolated from shipped projects, and no authority
  secret enters the repository/build/CI.

### Gaps to resolve before release

1. **Move/reissue command.** The architecture mentions
   “deactivate/move/reissue,” but the implementation plan does not specify a
   command or record schema transition for moving a license to a new Computer
   ID. Add either:
   - `activate --request ... --move-from <old-license|old-unlock>`, or
   - `activation-record` operations for “revoke current unlock” and “emit
     replacement unlock.”
2. **Activation record versioning.** The current record format uses immutable
   `init` fields plus `MarkConsumed`. Adding UnlockSecret fields must preserve
   readability of old records. The plan says `PropertyNameCaseInsensitive`
   handles format drift, but the plan should explicitly pin backward
   compatibility for old records.
3. **Unlock artifact revocation/rotation.** A signed `revoked` license
   renewal should make the old unlock artifact unusable even if the customer
   still holds it. The plan should require that `sequenceNumber` on the
   unlock artifact is compared against the license sequence floor and/or that
   the license id/status is re-checked before use.
4. **Audit.** The plan should record authority-side audit events for
   issue/activate/reissue without exposing the UnlockSecret or code.

---

## 6. Is the customer UI workflow covered?

**Verdict: PASS.**

### What exists

- SSP's licensing surface is primarily CLI:
  `--license-status`, `--install-license`,
  `--create-activation-request`, `--activate`, `--trust-anchor-info`.
- `AuthenticationCodeDialog` (`src/SSP.Server/UI`) is for **client
  enrollment** authentication codes, not licensing activation. It should not
  be reused for licensing.
- There is no production licensing GUI in the repository. The relevant customer
  interface is `SspActivationService.DescribeStatus()` plus the CLI commands.

### What the reviewed documents cover

- Architecture §13 describes:
  - status lines for unlock availability;
  - setup-screen gating;
  - support-bundle guidance;
  - “do not expose secrets” rules.
- Implementation plan §5 gives a CLI transcript.
- Implementation plan Phase 11 gives status fields and secret-free event
  requirements.

### Required note

If the product later introduces a customer GUI (not present today), the
customer-management console section must be extended to that GUI. For the
current codebase, the CLI workflow is the customer UI and is correctly
covered. The implementation plan should say this explicitly to avoid someone
implementing a GUI as part of this task.

---

## 7. Is installer impact covered?

**Verdict: PASS.**

### Evidence of low installer impact

- There is no installer project in this repository. `ServerInstallationBootstrapper`
  copies `SSP.Server.exe` to `Program Files\SSP` and creates a Desktop
  shortcut.
- `SetupEngine` provisions service directories under
  `{Program Files}\SSP\services\{Application}`.
- `WindowsServiceInstaller` registers/extracts the standalone
  `SSP.ServiceHost.exe` image per service.
- `SSP.ServiceHost` project references `SSP.Server`, so any new server-side
  activation/service-key code is automatically part of the standalone service
  host image.

### Covered by the documents

- No new large runtime artifact is required.
- Base install remains `SSP.Server.exe` + embedded client template + embedded
  service host.
- Setup/provisioning becomes activation-aware.
- Existing service keys migrate during service start/upgrade.
- `SSP.Server.exe` copying and the desktop shortcut path are unaffected.
- `SSP.ServiceHost` build should inherit the change through its project
  reference.

### Required addition before PR

- The implementation plan should explicitly state that the release
  code-integrity manifest (`SspCodeIntegrity.targets`,
  `RuntimeCodeIntegrity`) must include any new server runtime components and
  be regenerated in the release ceremony.
- The plan should call out that `WindowsServiceInstaller` needs no functional
  change, but the extracted `SSP.ServiceHost` image version must be
  re-published with the new server code.
- If a service directory already exists during the upgrade, service start must
  not require deleting or recreating the directory.

---

## 8. Are there any security regressions introduced?

**Verdict: PASS WITH CONDITION.**

### No regression relative to current security posture

- The server private key is already encrypted at rest through
  `ProtectedFileStore` (DPAPI LocalMachine). Wrapping it inside another
  AES-GCM envelope does not reduce confidentiality; it improves separation.
- The UnlockSecret and machine-unlock private key would reside under the same
  licensing directory and DPAPI LocalMachine protection as the existing
  license state and `.sysdata.bin`. They do not expose a new secret to a lower
  privilege boundary than the current server host.
- `SSP.Client` remains licensing-free.
- No wire-protocol change means no new remotely reachable oracle or attack
  surface.
- New artifacts are signature-verified and machine-bound.

### Potential regressions to avoid

1. **Level 1 code-only fallback.** If shipped as the default, the 10-digit
   code becomes the main secret source. This is materially weaker than Option
   A. The plan already says Level 2 is recommended and Level 1 is a fallback;
   implementation must make that a build/product policy, not a runtime
   operator toggle.
2. **Bypassing `PemStore` in the migration path.** Direct
   `ProtectedFileStore` reads, without `PemStore.LoadPrivateKeyAsync`, would
   skip legacy plaintext→encrypted migration and Unix file permission
   hardening. This could leave an older install in a weaker state.
3. **Unlock artifact shipped with license.** If the UnlockSecret were placed in
   the initial license artifact, the “missing before activation” property
   would fail. The plan correctly keeps it in a separate artifact.
4. **Plaintext migration of legacy `.sysdata.bin`.** If a migration runs
   before the UnlockSecret is present, the plan must not allow a lower-bound
   path that keeps a legacy PEM usable without unlock. The plan’s rule “do not
   fall back to plaintext” is correct, but should be hardened with a test that
   sets an activated state plus no UnlockSecret and still refuses service.
5. **Event-log leak.** The plan lists `UnlockSecret`, private keys, signature
   bytes and raw MachineGuid as forbidden. The implementation must not print
   the machine unlock public key either, unless explicitly required by a
   support workflow.
6. **Code-integrity manifest drift.** If release self-verification does not
   include the new activation/unlock source files or service key store, a
   patched binary could bypass the unlock gate. Phase 14 covers this, but it
   must be a release blocker.

---

## 9. Are all changes backward compatible or is migration required?

**Verdict: PASS AS DESIGNED. Migration is required, but it is contained.**

### Backward-compatible by design

- Wire protocol: unchanged.
- Client enrollment: unchanged.
- Client package format/patch-slot mechanism: unchanged.
- Existing signed v1/v2 license artifacts: unchanged.
- Existing vendored `SSP.Activation` license validation: unchanged if the
  implementation uses an SSP-native unlock model instead of modifying the
  vendored artifact.
- Existing `--install-license`, `--create-activation-request`, `--activate`,
  `--license-status`, `--trust-anchor-info` commands continue to exist.
- Existing license state and anti-rollback records remain readable.
- Existing `SSP.ServiceHost`/single-file image mechanism remains.

### Migration required

1. **Service-key format migration.** Existing activated installations must
   migrate a legacy PEM `.sysdata.bin` into the wrapped service-key envelope.
2. **Unlock state initialization.** Activated installs need a UnlockSecret and
   unlock state; installs that were previously activated under the pre-Option-A
   system cannot generate a UnlockSecret from a license alone. They must either
   receive a Level 2 unlock artifact or use the explicitly weaker Level 1
   code-derived fallback.
3. **Machine-unlock key generation.** New installs must generate the unlock
   keypair before the first activation request.
4. **Authority records.** Existing activation records are valid for Level 1 but
   do not contain Level 2 unlock material. The authority CLI must support both
   old and new records.

### Rollback posture

- Rollback to the old binary is possible only before service-key migration has
  actually taken place, or with a backup of the original `.sysdata.bin`.
- The plan's current rollback strategy says production releases should not have
  a runtime switch that permits legacy plaintext keys; that is correct.
- A rollback build should be an explicit unarmed development/recovery build,
  not a customer-configurable switch.

---

## Required corrections before the implementation pull request

1. Fix the `.sysdata.bin` read path in `SspServiceKeyStore`:
   - call `PemStore.LoadPrivateKeyAsync` first;
   - detect JSON vs legacy PEM;
   - only then apply the new wrapping layer.
2. Fix terminology in both documents:
   - existing on-disk `.sysdata.bin` is a **legacy PEM inside the existing
     SSP-EAR1/DPAPI envelope**, not a plaintext key file.
3. Ask for/add a concrete **pre-license Computer ID** and **machine-unlock
   key generation/display** step in the customer workflow.
4. Make **unlock-loss and move/reissue support flow** explicit in the customer
   and authority sections.
5. Require Level 2 as the default and treat Level 1 as an explicit support-only
   fallback.
6. Make the **release code-integrity manifest update** a release blocker and
   mention `SSP.ServiceHost` re-publish explicitly.
7. Make the **revocation/interaction between license status and unlock
   artifact sequence** explicit.

---

## Conclusion

The current architecture decision and implementation plan are sound for the
requested Option A mechanism and are compatible with the actual SSP protocol,
source layout, offline activation model, existing trust anchor, and current
server-key load path. The design satisfies the business requirement that a
small critical capability is absent before activation.

The two documents should be approved as the basis for implementation after the
seven focused corrections above are incorporated into the implementation plan.
Those corrections are implementation-depth clarifications, not a fundamental
redesign.

No code was changed, no pull request was created, and no implementation was
performed.
