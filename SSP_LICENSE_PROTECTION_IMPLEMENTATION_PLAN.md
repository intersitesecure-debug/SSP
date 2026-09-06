# SSP License Protection — Implementation Plan For Option A

**Status:** Implementation plan only. No source code, tests, build files,
configuration, or repository artifacts were modified by this task.

**Approved architecture:** `SSP_LICENSE_PROTECTION_ARCHITECTURE_DECISION.md` —
Option A, a machine-bound activation-unlock artifact that supplies an
authority-issued **Unlock Secret** required to unwrap the per-service server
private key.

**Companions:** `SSP_LICENSE_PROTECTION_ARCHITECTURE_DECISION.md`,
`docs/LICENSE_ACTIVATION_ARCHITECTURE.md`, `docs/LICENSE_AUTHORITY.md`,
`docs/THREAT_MODEL.md`, `SSP_ACTIVATION_ARCHITECTURE_AND_INTEGRATION_PLAN.md`,
`LICENSING_LIMITS_AND_RESOURCE_SEMANTICS.md`,
`TRUST_ANCHOR_KEY_CEREMONY.md`, `Security Correction.md`,
`BUILD.md`.

---

## 1. Implementation goals

1. The critical capability must not exist before activation.
2. The protected service must not be able to sign `ServerNonce` or unwrap an
   RSA-OAEP session key without the activation-unlock capability.
3. The activation-unlock capability must be machine-bound.
4. The existing wire protocol, tunnel, client enrollment, AES-GCM session
   path, `RsaCrypto`, `AesGcmCrypto`, and `SSP.Client` must remain unchanged.
5. The existing signed-license gate and anti-rollback state remain the outer
   authorization layer.
6. The commercial workflow stays offline: import license → create activation
   request → receive code + activation-unlock payload → enter code → fully
   activated.
7. Existing valid/activated installations migrate without re-provisioning.

---

## 2. Architecture recap

### 2.1 Existing SSP path that will be protected

In `src/SSP.Server/Runtime/ServerProtocol.cs`:

- `HandleAsync()` sends `ServerNonceMessage` and signs the nonce with the
  per-service RSA private key.
- `ReceiveSessionKeyAsync()` decrypts `SessionKeyOfferMessage` using
  `RsaCrypto.DecryptOaep(_serverPrivateKey, wrapped)`.
- `ServerGateway` then creates `TunnelCodec(sessionKey)` and bridges traffic.

Therefore the per-service server private key is the smallest single
cryptographic dependency that enables protected service operation.

### 2.2 Option A target design

```
[Authority]
  issue-certified (license artifact)
      + activation OTT + 10-digit code hash
      + activation-unlock (generated at activate time)
  activate --request runs:
      consume OTT
      generate/derandom 10-digit code
      generate high-entropy UnlockSecret (AES-256, random)
      encrypt UnlockSecret to customer machine unlock public key
      sign activation-unlock payload with authority root key

[Customer SSP]
  --create-activation-request
      produce existing ActivationRequest + machine unlock public key
  --import-activation-unlock <file>
      verify authority signature, machine binding, license/product/customer
      bindings and activation-code hash relation
  --activate <code>
      verify activation code hash (constant time)
      decrypt UnlockSecret using machine unlock private key (when public-key
        transport used)
      persist UnlockSecret in encrypted Unlock state store + witness
      transition to Valid
  SetupEngine
      generate per-service RSA key pair
      wrap .sysdata.bin with K_service = HKDF(UnlockSecret,
          salt=serviceDir+application, info="SSP-SERVICE-KEY-WRAP-v1")
  Program.RunServiceModeAsync / SspWindowsService.OnStart
      SspRuntimeLicense.CreateForService -> Valid
      SspServiceKeyStore.Load(serviceDir) -> wrapped key -> RSA
      ServerGateway / ServerProtocol unchanged
```

### 2.3 What remains unchanged

- `src/SSP.Core/Protocol/Messages.cs`
- `src/SSP.Core/Protocol/TunnelCodec.cs`
- `src/SSP.Core/Crypto/RsaCrypto.cs` — still used for signing, verification,
  RSA-OAEP, PEM, fingerprints.
- `src/SSP.Core/Crypto/AesGcmCrypto.cs` — reused for the service-key envelope.
- `src/SSP.Server/Runtime/ServerProtocol.cs`
- `src/SSP.Server/Runtime/ServerGateway.cs`
- `src/SSP.Client/**`
- Client patch-slot mechanism and embedded `ClientConfig`.

---

## 3. Phased implementation plan

Implementation should proceed in the order below. Each phase ends with a
buildable tree and targeted tests. No phase should depend on a later phase.

### Phase 0 — Schema freeze and ceremony decisions

Outcome: a written, reviewable schema and trust decision.

Actions:

1. Define the activation-unlock artifact schema.
2. Decide whether the authority reuses the root authority key (recommended) or
   a separate activation-unlock key. Reusing the same key keeps
   `SspTrustAnchor` as the only root of trust.
3. Decide transport mode:
   - **Level 2 (recommended):** authority encrypts a random high-entropy
     Unlock Secret to the machine's unlock public key produced by SSP. The
     10-digit code is a human/order factor, not the sole secret.
   - **Level 1 (compatibility fallback):** derive the Unlock Secret from
     `HKDF(InstallationId, activationCode, info)`. This is weaker; preserve
     only for deployments that cannot carry the unlock artifact.
4. Decide whether `ActivationRequest` is modified in the vendored library or
   wrapped by an SSP-native request model. **Recommendation:** keep the
   vendored `SSP.Activation` minimal; add optional fields only if additive
   and legacy-safe, otherwise use an SSP-native sidecar request schema.

### Phase 1 — SSP-native activation-unlock data model and codec

New code lives in `src/SSP.Server/Activation/`. No wire protocol change.

Files:

- `SspActivationUnlockPayload.cs`
- `SspActivationUnlockArtifact.cs`
- `SspActivationUnlockCodec.cs`
- `SspActivationUnlockConstants.cs`

Proposed artifact shape (draft, subject to review):

```json
{
  "format": "ssp-activation-unlock",
  "artifactVersion": 1,
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "payload": "<base64url(canonical JSON)>",
  "signature": "<base64url(RSA-PSS-SHA256)>"
}
```

Payload fields:

- `unlockId` — new GUID.
- `licenseId` — must match the installed license.
- `productId` — must equal `SspLicensing.ProductId`.
- `customerId` — match license payload.
- `installationId` — SSP Computer ID (MachineGuid-derived).
- `computerName` — optional administrative binding.
- `sequenceNumber` — monotonic authority sequence for the unlock artifact.
- `issuedAt`, `notBefore`, `expiresAt` — validity window.
- `activationCodeHash` — lowercase hex SHA-256 of the 10-digit code.
- `unlockTransport` — `"rsa-oaep"` (Level 2) or `"hkdf"` (Level 1).
- `recipientPublicKeyFingerprint` — SHA-256 SPKI of the machine unlock public
  key for Level 2.
- `wrappedUnlockSecret` — base64url RSA-OAEP-SHA256 ciphertext for Level 2,
  or an empty string for Level 1.
- `unlockSecretMetadata` — key size, version, wrap padding identifier.

Rules:

- Max artifact size: 256 KiB (mirror `LicenseArtifactCodec.MaxArtifactCharacters`).
- Canonical JSON: deterministic ordinals; use the same invariant rules as
  `LicenseCanonicalJson` / `LicenseKeyCertificationCanonicalJson`.
- Sign with `RSASignaturePadding.Pss`, SHA-256, MGF1/SHA-256, salt length =
  digest length.
- Unknown fields/versions fail closed.

### Phase 2 — SSP-native activation-unlock validator

New file: `SspActivationUnlockValidator.cs`.

Validation order (all fail closed):

1. Parse strict JSON.
2. Validate schema/format/version/algorithm.
3. Verify authority signature using the same compiled-in authority public key
   as `SspTrustAnchor`/`SspActivationService`.
4. Verify `productId`.
5. Verify `licenseId` matches the currently loaded activation-required
   license.
6. Verify `customerId` and optional `computerName`.
7. Verify `installationId` equals the current `InstallationId` from
   `SspInstallationIdentityProvider`.
8. Verify `activationCodeHash`.
9. Verify validity window using the same `IClock` sample and the existing
   clock-integrity rules (Phase 6 path).
10. Level 2: verify `recipientPublicKeyFingerprint` against the machine unlock
    keypair.
11. Verify `sequenceNumber` against the persisted unlock sequence floor.

On failure:

- Return a fail-closed result code such as `activation_unlock_invalid`,
  `activation_unlock_wrong_license`, `activation_unlock_wrong_machine`,
  `activation_unlock_expired`, `activation_unlock_signature_invalid`.
- Do **not** enter `Valid`.
- Emit a credential-free security event (see Phase 11).

### Phase 3 — Machine unlock identity

New file: `SspInstallationUnlockIdentity.cs` (and store).

Purpose:

- Generate an RSA-3072 `InstallationUnlock` keypair once per installation.
- Expose a stable `PublicKeyPem`, `PublicKeyFingerprint`, and an atomic
  write for the private key.

Storage:

- Private key path: `SspLicensePaths.UnlockIdentityPrivatePath` under the
  licensing directory, e.g.
  `{licensing}/.installation-unlock.key`.
- Register this file name in `ProtectedFileStore.ProtectedFileNames`.
- Windows: DPAPI LocalMachine (server-side, LocalSystem needs it).
- The private key is never sent to the authority, never enters logs/events,
  and never appears in a client package.
- The public key is included in the activation request.

Init point:

- On first `--create-activation-request`, `--license-status`, or setup run, if
  missing, generate it.
- Also generate it during activation-aware service provisioning if needed.

### Phase 4 — Activation request extension

Modify / extend:

- `src/SSP.Server/Activation/SspActivationService.cs`
  - `CreateActivationRequest()` returns the existing `ActivationRequest`
    plus optional machine unlock public key fields.
  - If the vendored `ActivationRequest` is extended, keep fields optional and
    preserve legacy codec behavior.
  - If a sidecar is preferred, add `SspActivationUnlockRequest` and write a
    second file `activation-unlock-request.json`.
- `src/SSP.Server/Program.cs`
  - `--create-activation-request` writes both the existing request and the
    unlock-request material atomically, then prints the destination paths.

Recommendation to minimize vendored change:

- Keep `ActivationRequest` in `SSP.Activation` unchanged.
- Add new optional fields to the SSP request sidecar:
  - `installationId`
  - `machineUnlockPublicKeyPem`
  - `machineUnlockPublicKeyFingerprint`
  - `unlockRequestId`

### Phase 5 — Import and activation of unlock material

New files:

- `SspActivationUnlockInstaller.cs`
- `SspUnlockSecretStore.cs`

`SspActivationUnlockInstaller` behavior:

1. Read the unlock artifact with size cap.
2. Run `SspActivationUnlockValidator`.
3. Pre-validate that the currently installed license is `ActivationRequired`.
4. Store the artifact atomically at
   `SspLicensePaths.ActivationUnlockFilePath`.
5. Do **not** transition to Valid; activation still requires the code.

`SspUnlockSecretStore` behavior:

- Persists the decrypted Unlock Secret under the encrypted primary file
  `.activation-unlock.dat` and a redundant out-of-directory witness
  `.ssp-state-witness/unlock/{hash}/.witness.dat`.
- Use `ProtectedFileStore` for both.
- Record:
  - `installationId`
  - `licenseId`
  - `unlockId`
  - `unlockSequence`
  - `stateEpoch` (monotonic)
  - `unlockSecret` (base64 or bytes)
  - `acquiredAtUtc`
- Load fails closed on corrupt/plaintext/foreign/unreadable state or witness.
- Never expose the secret in status/events/logs.
- The witness path uses a new purpose value `unlock` in
  `SspStateWitnessPaths`.

### Phase 6 — Activation transition

Modify:

- `src/SSP.Server/Activation/SspActivationService.cs`
  - Add `ImportActivationUnlock(string path)`.
  - Add `TryActivate(string code, string? unlockArtifactPath = null)`
    or a separate `ActivateWithUnlock`.
- `src/SSP.Server/Program.cs`
  - `--activate <code>` accepts `--activation-unlock <file>` and/or precedes
    with `--import-activation-unlock`.
  - For Level 2, require the unlock artifact to be imported before
    activation; for Level 1, allow code-only activation with explicit
    warning output.

Transition rules:

1. License state must be `ActivationRequired`.
2. Verify time integrity and both validity windows.
3. Verify `activationCodeHash` with constant-time comparison.
4. For Level 2, decrypt the wrapped Unlock Secret with the machine unlock
   private key.
5. Persist the Unlock Secret and activation state under one transaction,
   prior to publishing `Valid`.
6. Re-run the normal license validation pipeline; only then publish `Valid`.
7. If any step fails, remain `ActivationRequired` or fail closed.

### Phase 7 — Wrapped per-service server key

New file: `SspServiceKeyStore.cs`.

Envelope format (draft):

```json
{
  "format": "ssp-service-key",
  "version": 1,
  "serviceId": "<application name>",
  "serviceDirHash": "<sha256 first 32 hex>",
  "keyFingerprint": "<sha256 SPKI of public key>",
  "ciphertext": "<base64url AES-GCM ciphertext of PKCS#8 PEM>",
  "nonce": "<base64url 12 bytes>",
  "tag": "<base64url 16 bytes>",
  "wrappedAtUtc": "..."
}
```

Wrapping key derivation:

```
K_service = HKDF(
    ikm        = UnlockSecret (32 bytes),
    salt       = SHA-256(serviceDir || applicationName),
    info       = "SSP-SERVICE-KEY-WRAP-v1",
    length     = 32)
```

Read path:

1. Read `.sysdata.bin` through `ProtectedFileStore`.
2. If legacy PEM (existing install), and `UnlockSecret` is present, migrate
   to the new wrapped envelope.
3. If wrapped, validate `serviceId`, directory hash, key fingerprint, then
   AES-GCM decrypt using `AesGcmCrypto`.
4. Import with `RsaCrypto.ImportPrivateKeyPem`.
5. If the Unlock Secret is unavailable, or the envelope is corrupt or
   foreign, throw `SspActivationException` with a new reason like
   `service_key_unavailable` / `unlock_material_missing`. Do **not** fall
   back to plaintext.

Write path (`SetupEngine`):

1. Generate RSA pair with `RsaCrypto.GenerateKeyPair()`.
2. Export PKCS#8 private PEM.
3. Require Unlock Secret.
4. Derive `K_service`.
5. Encrypt with `AesGcmCrypto.Encrypt`.
6. Write JSON envelope through `ProtectedFileStore.WriteTextAsync` to
   `.sysdata.bin`.
7. Write `.runtime.dat` public key as today.

### Phase 8 — Service start path

Modify:

- `src/SSP.Server/Program.cs` — `RunServiceModeAsync`:
  - `SspRuntimeLicense.CreateForService(config, serviceDir)` runs first.
  - Replace `PemStore.LoadPrivateKeyAsync(privPath)` with
    `SspServiceKeyStore.Load(serviceDir, config, license.Activation)`.
  - Pass the resulting `RSA` to `ServerGateway` unchanged.
- `src/SSP.Server/ServiceHost/SspWindowsService.cs` — same path is reached
  through `Program.RunWindowsService`; no protocol change.

`SspRuntimeLicense.CreateForService` additions:

- After license validation is `Valid`, require the activation unlock state to
  be present.
- If not present, throw `SspActivationException` with reason
  `activation_unlock_missing`.
- This makes both SCM `OnStart` and `--run-once` fail closed.

### Phase 9 — Setup/provisioning gate

Modify:

- `src/SSP.Server/Setup/SetupEngine.cs`
  - `RunNewApplicationAsync` must not write a usable plaintext `.sysdata.bin`
    when activation/unlock is absent.
  - It should require `SspRuntimeLicense.TryCreateForProvisioning` to return
    a gate and the Unlock Secret to be available.
  - Use `SspServiceKeyStore.Write` for the private key.
- `src/SSP.Server/Program.cs` — `RunBatchSetupAsync` and
  `RunInteractiveSetupAsync` already obtain a provisioning license; extend
  the failure message to mention activation-unlock availability.

### Phase 10 — Migration of existing plaintext service keys

Policy:

- Existing activated installs:
  - On first service start after the upgrade, `SspServiceKeyStore.Load`
    detects a legacy PEM `.sysdata.bin`.
  - If the Unlock Secret is present, read the PEM, rewrap, write, then load.
  - If the rewrap fails, fail closed; do not delete or leave readable.
- Existing activation-required installs:
  - Refuse service start until activation and unlock material are present.
  - On activation, `SspServiceKeyStore` can rewrap the legacy key.
- Developer/test builds:
  - Existing explicit test seams remain; an unanchored/unarmed build is not
    a production mechanism and must not become a bypass path.

### Phase 11 — Security events and status

Add new stable events/types to `SspSecurityEventSink`/taxonomy:

- `ActivationUnlockImported`
- `ActivationUnlockRejected`
- `ActivationUnlockMissing`
- `ActivationUnlockVerificationFailed`
- `ActivationUnlockRollbackDetected`
- `ActivationUnlockDeletionRecovered`
- `ServiceKeyUnavailable`
- `ServiceKeyMigrated`

All events remain credential-free and never include:

- activation code
- Unlock Secret
- private key bytes
- signature bytes
- raw MachineGuid
- unwrapped service key PEM

`SspActivationService.DescribeStatus()` additions:

- `Activation unlock : not imported / imported / verified`
- `Unlock secret     : available / unavailable`
- `Protected key     : wrapped-unavailable / wrapped-ok`
- `Unlock file       : <path>`
- `Unlock state      : <path>`
- `Unlock witness    : <path>`

### Phase 12 — Authority tooling

Modify `tools/SSP.LicenseAuthority`:

- `ActivationRecord` extends with:
  - `UnlockId`
  - `UnlockSequenceNumber`
  - `UnlockSecret` (plaintext, authority-side only)
  - `InstallationUnlockPublicKeyFingerprint`
  - `IssuedAtUtc`
  - `Move/Replacement` metadata if required.
- `LicenseIssuance`/`Program.cs`:
  - `issue-certified` still creates activation material.
  - New `activate --request <file> --activation-record <path> [--unlock-output <path>]`
    action:
    - validates OTT (single use),
    - reads machine unlock public key from the request,
    - generates a high-entropy Unlock Secret,
    - encrypts it to the machine public key (RSA-OAEP-SHA256),
    - signs the activation-unlock artifact with the authority key,
    - writes `activation-unlock.json` (or prints instructions to save it),
    - prints the 10-digit code.
  - A `--code-only`/Level 1 fallback may be added for compatibility but must
    print a warning that it is weaker.
- `inspect`/`verify` extend with `--unlock` where useful, never printing the
  Unlock Secret or code.

Keep constraints:

- No authority private key in the repo/build/CI.
- No activation record or Unlock Secret in shipped artifacts.
- `LicenseAuthoritySecurityIsolationTests` must keep passing; the authority
  project must not reference `SSP.Server`, `SSP.Core`, `SSP.Client`, or any
  shipped runtime project.

### Phase 13 — Tests

Add a dedicated test suite, split across project files.

#### `tests/SSP.Tests/Activation/Unlock` or `tests/SSP.Tests/Activation/ActivationUnlock*`

- `SspActivationUnlockCodecTests`:
  - roundtrip
  - malformed JSON / unknown version / unknown algorithm / oversized file
- `SspActivationUnlockValidatorTests`:
  - valid authority signature
  - wrong product
  - wrong license id
  - wrong customer
  - wrong machine/Computer ID
  - wrong activation code hash
  - expired / not-yet-valid
  - wrong machine unlock public key fingerprint
  - tampered payload
  - signature made by a non-authority key
- `SspUnlockSecretStoreTests`:
  - persist/load
  - encrypted at rest
  - missing primary + witness recovery
  - primary epoch rollback detection
  - foreign/corrupt/plaintext witness fail closed
  - secret never in events/status output
- `SspServiceKeyStoreTests`:
  - wrap/unwrap roundtrip
  - legacy PEM migration
  - missing Unlock Secret fail closed
  - tampered ciphertext fail closed
  - wrong service dir/application fail closed
  - read without protected file fail closed
- `SspRuntimeLicenseActivationUnlockTests`:
  - `ActivationRequired` + no unlock -> service start denied
  - Valid license + missing unlock -> service start denied
  - Valid license + unlock -> service start allowed
  - unlock deleted after activation -> service start denied
- `SspLicenseInstallerUnlockTests`:
  - activation unlock import requires matching license state
  - imported unlock does not transition to Valid until code
  - code + wrong unlock fails
- `ProgramUnlockCliTests`:
  - `--create-activation-request` output includes/newly includes machine
    unlock key
  - `--import-activation-unlock` / `--activate` paths
  - `--license-status` unlock lines
- `SspActivationAuthorityUnlockTests`:
  - authority `activate` emits code + unlock artifact
  - OTT consumed only on success
  - unlock artifact rejects copied machine public key
  - unlock artifact rejects another license
  - activation record never leaks into customer artifact
- `LicenseAuthoritySecurityIsolationTests` extensions:
  - authority project has no ProjectReference to shipped runtime projects
  - no `UnlockSecret`/activation code in shipped-manifest scan
  - no `PRIVATE KEY` material in shipped binaries

#### Test fixtures

- `ActivationUnlockArtifactTestHelper`
- `TestAuthority` extension to also sign unlock artifacts
- `LicensedTestEnvironment` extension to provision Unlock Secret
- Fixed machines: deterministic `InstallationId`, deterministic machine unlock
  key

### Phase 14 — Build/CI integration

- Add an optional MSBuild/property seam if the activation-unlock artifact
  template must be generated in release ceremony workflows.
- The build must not require a real authority private key.
- `SSP_SKIP_EMBED` test builds remain unaffected.
- Code-integrity manifest generation (`RuntimeCodeIntegrity`,
  `SspCodeIntegrity.targets`) must include new runtime components if they
  become part of an armed release baseline.
- Document how release verification checks unlock artifacts without printing
  secrets.

### Phase 15 — Documentation and rollout

- Update `docs/LICENSE_ACTIVATION_ARCHITECTURE.md`.
- Update `docs/LICENSE_AUTHORITY.md`.
- Update `docs/THREAT_MODEL.md`.
- Update `TRUST_ANCHOR_KEY_CEREMONY.md` with activation-unlock ceremony.
- Add migration runbook in `BUILD.md` or a new operations runbook.
- Add support question/answer for:
  - missing unlock artifact
  - moved/replaced hardware
  - reissue after activation state loss
- Update `SSP_LICENSE_PROTECTION_ARCHITECTURE_DECISION.md` only if the design
  changes during implementation.

---

## 4. Exact file change matrix

### New SSP.Server activation files

```
src/SSP.Server/Activation/SspActivationUnlockConstants.cs
src/SSP.Server/Activation/SspActivationUnlockPayload.cs
src/SSP.Server/Activation/SspActivationUnlockArtifact.cs
src/SSP.Server/Activation/SspActivationUnlockCodec.cs
src/SSP.Server/Activation/SspActivationUnlockValidator.cs
src/SSP.Server/Activation/SspActivationUnlockInstaller.cs
src/SSP.Server/Activation/SspInstallationUnlockIdentity.cs
src/SSP.Server/Activation/SspInstallationUnlockIdentityStore.cs
src/SSP.Server/Activation/SspUnlockSecretStore.cs
src/SSP.Server/Activation/SspUnlockSecretWitness.cs (if not folded into store)
src/SSP.Server/Activation/SspServiceKeyStore.cs
src/SSP.Server/Activation/SspActivationUnlockEvents.cs
```

### Modified SSP files

```
src/SSP.Server/Activation/SspActivationService.cs
src/SSP.Server/Activation/SspRuntimeLicense.cs
src/SSP.Server/Activation/SspLicensePaths.cs
src/SSP.Server/Activation/SspSecurityEventSink.cs (if event taxonomy is in this file/adjacent)
src/SSP.Server/Activation/SspLicenseStateStore.cs (only if unlock state shares it; preferred: separate store)
src/SSP.Server/Program.cs
src/SSP.Server/Setup/SetupEngine.cs
src/SSP.Core/IO/ProtectedFileStore.cs (add protected file names)
src/SSP.Core/IO/StateWitnessPaths.cs (add unlock purpose)
```

### Modified authority tool files

```
tools/SSP.LicenseAuthority/ActivationRecord.cs
tools/SSP.LicenseAuthority/ActivationUnlockIssuance.cs (new)
tools/SSP.LicenseAuthority/Program.cs
tools/SSP.LicenseAuthority/LicenseIssuance.cs (add helpers, if needed)
tools/SSP.LicenseAuthority/AuthorityKeyMaterial.cs (validation helpers, not secrets)
```

### Existing file paths to preserve

```
src/SSP.Core/Protocol/Messages.cs
src/SSP.Core/Crypto/RsaCrypto.cs
src/SSP.Core/Crypto/AesGcmCrypto.cs
src/SSP.Server/Runtime/ServerProtocol.cs
src/SSP.Server/Runtime/ServerGateway.cs
src/SSP.Client/**
src/SSP.Core/Util/ClientTemplate.cs
src/SSP.Client/PatchSlot.cs
src/SSP.Client/ClientServicesResource.cs
```

---

## 5. CLI and operator flow

### New / changed commands

```text
# Status now includes unlock state
SSP.Server.exe --license-status

# Create activation request; Level 2 includes machine unlock public key
SSP.Server.exe --create-activation-request

# Import authority-issued unlock artifact (new command)
SSP.Server.exe --import-activation-unlock <activation-unlock.json>

# Activate; Level 2 requires imported unlock artifact
SSP.Server.exe --activate <10-digit-code>
```

Either phrase:

```text
SSP.Server.exe --activate <code> --activation-unlock <file>
```

or

```text
SSP.Server.exe --import-activation-unlock <file>
SSP.Server.exe --activate <code>
```

Both are acceptable; keep only one primary to avoid confusion. The plan
recommends `--import-activation-unlock` as a separate explicit operation
because it is a cryptographic import with its own validation.

### End-to-end operator transcript

```text
C:\> SSP.Server.exe --license-status
  State              : (no license)
  Activation unlock  : not imported
  Unlock secret      : unavailable

C:\> SSP.Server.exe --create-activation-request
  Activation request written: <...>\activation-request.json
  Activation unlock request : <...>\activation-unlock-request.json
  Computer ID: <hash>

<send both to vendor>

C:\> SSP.Server.exe --install-license D:\in\ssp-license.json
  State: ActivationRequired

C:\> SSP.Server.exe --import-activation-unlock D:\in\activation-unlock.json
  Activation unlock imported.
  State: ActivationRequired (activation code still required)

C:\> SSP.Server.exe --activate 1234567890
  License activated.
  State: Valid (Ok)
  Unlock secret: available
```

---

## 6. Security invariants

Implementation must enforce, and tests must pin:

1. `UnlockSecret` is **never** read from config/env/registry/CLI.
2. The activation unlock artifact is **never** accepted without a valid
   authority signature and machine binding.
3. A copied unlock artifact onto a different machine fails due to
   `installationId` and/or machine unlock public-key fingerprint mismatch.
4. The Unlock Secret is never emitted in status output, security events,
   console diagnostics, or event log.
5. `SspServiceKeyStore` never falls back to plaintext PEM.
6. A missing/corrupt unreadable unlock state or witness fails closed.
7. A rolled-back unlock state fails closed via monotonic epoch.
8. `SspRuntimeLicense.CreateForService` fails before any socket bind if
   licensing or unlock capability is unavailable.
9. The existing license state store remains able only to restrict, never to
   grant.
10. The installation identity remains the same; the raw MachineGuid is never
    exposed.

---

## 7. Rollback strategy

Per phase:

- **Phase 1–2 (codec/validator):** additive only; no runtime path depends on
  them until later. Rollback = delete/unreferenced new files.
- **Phase 3–4 (machine unlock identity):** additive; only used by new request
  CLI. Rollback = return to old request file.
- **Phase 5–6 (import/activation):** new commands optional; existing
  `--activate <code>` continues to work for Level 1 and pre-existing
  activation-required licenses. Rollback = disable new import path.
- **Phase 7–8 (wrapped service keys):** the highest-risk phase. Keep a
  controlled feature switch/code path that permits legacy plaintext keys **only
  in a temporary rollback build**, not in production release. In a regular
  production release, a rollback requires the old binary and a back-up of the
  original `.sysdata.bin` (or re-provisioning).
- **Phase 9–10 (setup/migration):** maintain a migration flag in the
  UnlockSecret store. If migration fails, fail closed and preserve original
  file; do not delete.
- **Authority tool:** new `activate --unlock-output` is additive.

Rollback must never produce a config flag that bypasses the unlock requirement
in a production build. Any rollback path should be an **unarmed/development
build**, not a runtime setting.

---

## 8. Acceptance criteria / definition of done

1. `dotnet build SSP.sln -p:SSP_SKIP_EMBED=true` succeeds in a .NET 8
   environment (and, when the release packs are available, the normal publish
   path succeeds).
2. `dotnet test` on `tests/SSP.Activation.Tests` and `tests/SSP.Tests`
   succeeds, including the new unlock tests.
3. An unactivated SSP with a valid activation-required license cannot start any
   protected service, even if the license is valid and the installation id
   matches.
4. After entering the correct 10-digit code with the correct authority-issued
   unlock artifact, SSP transitions to `Valid`, generates/wraps service keys,
   and services start normally.
5. Wrong code, wrong lock artifact, wrong machine, copied artifact, expired
   artifact, or missing Unlock Secret all fail closed.
6. The existing wire protocol and client behavior remain unchanged.
7. Copying `license.json` + `activation-unlock.json` + `.license-state.dat`
   to another computer without the matching MachineGuid/machine unlock private
   key does not activate or start a service.
8. Existing activated installations migrate their `.sysdata.bin` keys to the
   wrapped format once activation/unlock is present.
9. No private key, activation code, Unlock Secret, raw MachineGuid, or
   signature bytes appear in logs, UI, status, or security events.
10. `SSP.Client`, `SSP.ServiceBuilder`, and the client package contain no
    activation/unlock code and no reference to `SSP.Server/Activation`.

---

## 9. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Vendored `SSP.Activation` changes cause regression | Keep the vendored library as unchanged as possible; use SSP-native models where possible; add a hard compatibility test that old artifacts still verify. |
| Migration leaves a readable legacy key | Only ever migrate after the UnlockSecret is present; fail closed otherwise; keep migration atomic. |
| Level 1 code-only fallback is weak | Do not ship Level 1 as the default for commercial builds; require Level 2 where product policy permits. |
| Low entropy activation code used as wrap secret | Never use the 10-digit code as the sole source of key-wrapping entropy. |
| Authority response cannot transport the unlock artifact | Define an alternate vendor-console/download workflow; do not silently downgrade to code-only. |
| Machine unlock private key lost | Customer recovery is a new machine unlock identity + vendor re-issue; preserve a documented support path. |
| DPAPI LocalMachine private key readable by local admin | Existing accepted server-side residual; the UnlockSecret and wrapped service key still require the activation artifact and code. |
| UnlockSecret deleted/rolled back | Persist in encrypted primary + out-of-directory witness; fail closed on missing/corrupt; vendor reissue. |
| Vendor activation record leaked | Authority-side secret governance: outside repo/build/CI, encrypted/vault storage, HSM for private key. |
| Code-integrity manifest drift | Update the release manifest generation to include new SSP.Server activation components; keep unarmed builds no-op. |
| Performance impact | Unlock/service-key operations happen once at service start and setup; no per-packet cost. |

---

## 10. Implementation ordering checklist

- [ ] Phase 0: schema decision approved.
- [ ] Phase 1: codec + model files added, unit tests.
- [ ] Phase 2: validator added, negative tests.
- [ ] Phase 3: machine unlock identity added.
- [ ] Phase 4: activation request extension.
- [ ] Phase 5: unlock import + secret store.
- [ ] Phase 6: activation transition.
- [ ] Phase 7: service key store.
- [ ] Phase 8: service start path.
- [ ] Phase 9: setup gate.
- [ ] Phase 10: migration.
- [ ] Phase 11: events/status.
- [ ] Phase 12: authority tooling.
- [ ] Phase 13: test suite.
- [ ] Phase 14: build/CI integration.
- [ ] Phase 15: documentation and rollout.

---

**End of plan.** No code or repository files were modified.
