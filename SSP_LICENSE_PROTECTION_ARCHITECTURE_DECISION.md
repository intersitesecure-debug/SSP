# SSP License Protection Architecture Decision

**Status:** Architecture decision record (ADR). Read-only analysis; no source
code, tests, build files or configuration were modified. Recommendation is
made after source inspection of the current SSP codebase and its licensing
subsystem.

**Companion documents:** `docs/LICENSE_ACTIVATION_ARCHITECTURE.md`,
`docs/LICENSE_AUTHORITY.md`, `docs/THREAT_MODEL.md`,
`SSP_ACTIVATION_ARCHITECTURE_AND_INTEGRATION_PLAN.md`,
`LICENSING_LIMITS_AND_RESOURCE_SEMANTICS.md`,
`TRUST_ANCHOR_KEY_CEREMONY.md`, `Security Correction.md`.

---

## 1. Executive summary

SSP currently ships the complete product and uses a signed, machine-bound
license plus a runtime gate to decide which operations are allowed. The
product owner now wants a small but strategically critical component to be
**absent before activation** so that unlicensed SSP cannot provide its
protected service at all.

The four candidate options were analysed against the actual source:

| Option | Verdict |
| --- | --- |
| **A. Missing cryptographic unlock material** | **Recommended as the core mechanism.** |
| B. Missing assembly / plugin | Rejected as a standalone mechanism; may only be a packaging convenience. |
| C. Feature package model | Useful as an editions/admin layer, but not sufficient for the stated requirement. |
| D. Improve the current license gate only | Rejected as the sole mechanism because the complete software still exists and the gate remains code, not a missing capability. |

**Recommended architecture.**

Keep and harden the existing signed-license gate (Option D) as the outer
authorization layer. Add **Option A** as the inner, capability-based layer:
a **machine-bound, authority-signed activation-unlock artifact** supplies a
high-entropy **Unlock Secret** that is required to unwrap each protected
service's per-service server private key at rest. Before activation the
Unlock Secret does not exist, the per-service server key cannot be imported,
and neither `ServerNonce` signing nor RSA-OAEP session-key unwrapping can
happen. Consequently no protected service can be provided. After activation
the normal SSP protocol, tunnel, client enrollment and cryptography operate
unchanged.

The proposed mechanism does **not** change the wire protocol, the tunnel, the
enrollment flow, the AES-GCM session path, `ServerNonce`/challenge
signatures, or the existing RSA key algorithms. It changes where and how the
per-service server private key is stored and which authority-issued material
must be present before it can be loaded.

Feature-package editioning (Option C) can be layered on later with minimal
disruption; it is not needed for the primary goal.

---

## 2. Current architecture analysis

### 2.1 Product shape

The repository is .NET 8 and is split into:

- `src/SSP.Core` — shared crypto, protocol models, client/server paths, I/O
  helpers. Referenced by client and server.
- `src/SSP.Activation` — vendored, self-contained licensing subsystem.
- `src/SSP.Server` — setup, gateway, Windows service host, activation
  adapters, and the licensing composition root.
- `src/SSP.Client` — enrollment and tunnel client. Carries **no** licensing
  code (`SSP.Server/Activation` is not referenced from `SSP.Client`).
- `src/SSP.ServiceHost` — standalone single-file service image forwarding to
  `SSP.Server.Program`.
- `src/SSP.ServiceBuilder` — provisioning/automation tool.
- `tools/SSP.LicenseAuthority` — authority-side offline CLI, never shipped.

So the licensed value is server-side. Keeping licensing out of the client is
correct and should remain a hard boundary.

### 2.2 Licensing architecture

The current trust model is two-level:

```
Root Authority RSA-3072 public key (compiled into release binaries)
        │ signs with RSA-PSS-SHA256
        ▼
Per-license key certification (LicenseId, ProductId, CustomerId, validity,
        license-specific public key SPKI, optional activation OTT + code hash)
        │ certifies
        ▼
Per-license leaf RSA key (fresh per license, private key never persisted)
        │ signs
        ▼
License payload (customer, edition, features, limits, sequence, installation id)
```

Real types:

- `SspTrustAnchor` (`src/SSP.Server/Activation/SspTrustAnchor.cs`) — release
  embedded `LicenseTrustAnchor`; fail-closed if absent or unusable.
- `SspActivationService` (`src/SSP.Server/Activation/SspActivationService.cs`)
  — the single composition root; wires `LicenseManager`,
  `LicenseEnforcement`, `LocalLicenseFileProvider`, `SspLicenseStateStore`,
  `SspInstallationIdentityProvider`, `SspSecurityEventSink`, clock and policy.
- `SspRuntimeLicense` (`src/SSP.Server/Activation/SspRuntimeLicense.cs`) — the
  production `ISspLicenseGate`; enforces service start (`EP1`), feature and
  limit checks, and runtime tunnel/session admission (`EP3`).
- `SspLicenseStateStore` / witness — DPAPI-encrypted anti-rollback state with
  sequence floor, activation id, installation binding, monotonic epoch and a
  redundant out-of-directory witness.
- `tools/SSP.LicenseAuthority` — `issue`, `issue-certified`, `renew`,
  `inspect`, `verify`, and `activate` (single-use OTT + 10-digit activation
  code issuance).

### 2.3 SSP protocol and where the real cryptographic dependency is

The current SSP server-to-client identity path is:

1. `ServerGateway.AcceptLoopAsync` accepts a TCP connection.
2. `ServerProtocol.HandleAsync` generates a random `ServerNonce`, signs it
   with the per-service RSA **private key** (`_serverPrivateKey`) and sends
   `ServerNonceMessage`.
3. `ClientProtocol` verifies the server nonce signature against the
   `ServerPublicKeyPem` embedded in the client package.
4. The client either enrolls (`EnrollmentBundleMessage`) or presents a
   challenge response (`ChallengeResponseMessage`).
5. `ServerProtocol.ReceiveSessionKeyAsync` receives an RSA-OAEP-wrapped
   AES-256 session key and decrypts it with `RsaCrypto.DecryptOaep(
   _serverPrivateKey, wrapped)`.
6. `ServerGateway` builds a `TunnelCodec(sessionKey)` and bridges to
   `127.0.0.1:LocalApplicationPort`.

Therefore **the per-service server private key is currently the single
cryptographic element that enables both server identity and session-key
decryption.** If that key cannot be imported, the protocol cannot proceed:
the client rejects the server challenge and the server cannot unwrap the
session key. This is exactly the kind of small critical element that can be
protected with a missing capability.

Current key layout:

- Server private key: `.sysdata.bin` in the service directory.
- Server public key: `.runtime.dat` in the service directory.
- Setup engine (`SetupEngine.RunNewApplicationAsync`) generates the RSA pair
  with `RsaCrypto.GenerateKeyPair()` and persists both keys with
  `PemStore.SavePrivateKeyAsync` / `SavePublicKeyAsync`.
- Service start (`Program.RunServiceModeAsync`) imports the key with
  `PemStore.LoadPrivateKeyAsync` after the licensing gate has passed.

---

## 3. Current licensing limitations

The current system is strong for what it is, but it is still a *license gate*,
not a *missing-capability* mechanism.

1. **The complete software exists before activation.** All SSP assemblies,
   protocol code, tunnel code, and key-generation logic are present in the
   shipped binary. Activation only flips a persisted authorization state and
   evaluates signed feature/limit/validity data.
2. **The protected service key exists before activation.** Setup currently
   generates and stores a fully usable plaintext server private key. A local
   administrator with file access can use `ServerGateway`/`ServerProtocol`
   only after a license gate passes, but the cryptographic path is still
   complete offline.
3. **The enforcement is code, not capability.** `SspRuntimeLicense` and
   `ServerProtocol` decide whether to call the protected path. An attacker
   who can modify the binary can make a denial turn into a grant. The
   runtime code-integrity gate (`RuntimeCodeIntegrity`,
   `CodeIntegrityVerifier`) raises the bar and detects tampering, but a
   fully privileged local administrator can still re-arm/remove it (source:
   `docs/THREAT_MODEL.md`, T35, §9).
4. **A copied license artifact can still be examined.** Signed artifacts are
   plaintext by design (integrity only). They are machine-bound through
   `payload.InstallationId` and the DPAPI state store, but an attacker with a
   copied artifact and the target machine's identity material can attempt
   local activation-code guessing. The 10-digit code gives about 10^10
   candidates, which is a meaningful weakness if the code is the only
   cryptographic secret.
5. **No missing key material separates "installed" from "operational".** The
   product already installs to an operational-able state; licensing only
   removes permission. That is normal for many products, but it is not the
   stronger commercial posture being requested.
6. **The revoke/renew/expiry model is offline-signed.** This is appropriate
   for the product and should remain.

---

## 4. Security objectives

For the proposed protection mechanism, in priority order:

1. **Protected service must not be provisionable or startable without an
   activated license.**
2. **A small, real cryptographic capability must not exist before
   activation** — not merely a permission flag.
3. **Computer ID binding must prevent a license/unlock bundle from being
   copied to another machine** and used there.
4. **Copying the license file alone must not activate anything.**
5. **The activation code should never be the sole high-entropy secret** if a
   local adversary can brute-force the license file offline.
6. **The existing SSP protocol, tunnel, enrollment, and crypto algorithms
   must remain unchanged.**
7. **Offline activation/revocation must remain possible.**
8. **A valid, already-activated installation must continue to operate
   normally; recovery after hardware changes must be supportable.**
9. **A local administrator must not be able to switch licensing on by
   editing configuration, environment variables, registry values, or
   files.**
10. **Fail-closed:** missing/corrupt/unusable unlock material must refuse the
    protected service rather than falling back to plaintext keys.

---

## 5. Threat model

Actors relevant to this architecture decision:

| Actor | Capabilities |
| --- | --- |
| Vendor Licensing Authority | Holds root private key and activation records; can issue or revoke activation material. |
| Customer administrator / operator | Runs SSP UI/CLI, installs license, enters code. |
| Local user on the SSP server | Can read files and registry, run processes, inspect logs. |
| Local administrator on the SSP server | Can modify files, registry, services, and installed binaries; can reset/roll back data; can inspect process memory. |
| Remote unauthenticated peer | Can only reach the gateway TCP port; cannot pass the protocol authentication. |
| Remote authenticated client | Normal usage, bounded by licensed limits. |

Threats to address:

- **T-A1. Unlicensed protected service becomes operational.** Mitigated by
  the missing Unlock Secret + wrapped service key.
- **T-A2. License file copied to another machine.** Mitigated by
  Computer-Id binding and machine-bound unlock material.
- **T-A3. Configuration/environment bypass.** No config/environment can
  supply the unlock secret.
- **T-A4. State-store rollback to an older activation.** Mitigated by the
  existing monotonic anti-rollback state and witness, extended to unlock
  material.
- **T-A5. Offline brute-force of the 10-digit activation code.** Mitigated by
  using an additional high-entropy, machine-bound unlock payload delivered in
  the activation response; the code alone is not sufficient.
- **T-A6. Binary patching to bypass the gate.** Mitigated by Authenticode and
  the existing `RuntimeCodeIntegrity` start gate; fully privileged local
  tampering remains a residual risk and is explicitly accepted for
  software-only protection.
- **T-A7. Extraction of the existing local server private key from an
  older/plaintext install.** Mitigated by migrating/rewrapping old keys and
  requiring unlock material before load; plaintext migration is supported
  only through a controlled upgrade path.
- **T-A8. Denial of service from loss of unlock material.** Recovery path is
  vendor re-issuance from the same activation record, or a legitimate
  activation move.

Accepted residual risks:

- A local administrator who controls the machine and has time can patch the
  SSP binary or tamper with the OS/DPAPI/registry to circumvent any
  software-only mechanism. Software protection is a commercial/operational
  control, not a trusted-hardware boundary.
- Complete coordinated rollback of the machine (same MachineGuid, same
  program files, same boot image) is out of scope; only hardware/OS-level
  attestation can fully close it.

---

## 6. Comparison of all approaches

### 6.1 Option A — Missing cryptographic unlock material

**Core idea:** A critical cryptographic element does not exist before
activation. After activation the vendor supplies a signed, machine-bound
unlock artifact that makes the existing protocol capability usable.

**SSP-specific realization:** Before activation, per-service server private
keys are stored wrapped under a key derived from the activation Unlock
Secret. The Unlock Secret is authority-issued and machine-bound. Without it,
`ServerProtocol` cannot sign `ServerNonce` and cannot unwrap the RSA-OAEP
session key; therefore the protected service has no identity and no way to
establish a tunnel.

Security answers:

1. **Can a local administrator bypass it?** Not by configuration/flag
   changes. Bypass requires modifying the binary or recovering the unlock
   secret. The existing runtime code-integrity gate detects tampering and
   refuses startup. A fully privileged local administrator can still attack
   the process/memory/OS trust chain; that is accepted.
2. **Can a license file be copied to another machine?** A copied license
   artifact fails the Computer-Id/InstallationId binding. If the copied
   item includes the unlock artifact, it is encrypted/hashed to the original
   machine binding and also fails. Copying the entire original registry
   identity and files is a coordinated machine reconstruction, not a simple
   file copy.
3. **Can an attacker patch the binary?** Yes in principle; no software-only
   scheme prevents it. Mitigations are Authenticode signing plus the
   `RuntimeCodeIntegrity` manifest, which fail closed on known tampering.
4. **Can the mechanism be bound to Computer ID?** Yes, strongly. The
   authority records the Computer ID/InstallationId in the unlock artifact
   and the artifact is encrypted/wrapped to machine-bound material.
5. **How does recovery work after hardware replacement?** If the OS
   installation and MachineGuid survive the hardware change, the Computer ID
   stays the same. If the OS/identity is recreated, the new InstallationId
   differs; the vendor re-issues a machine-bound license and unlock artifact.
6. **How does customer support work?** Support uses `--license-status`,
   `--create-activation-request`, and the vendor's activation record. The
   operator can request a reissue, a move, or a replacement without exposing
   private key material.
7. **How does installer design change?** Minimal for the base install: still
   `SSP.Server.exe` + `SSP.ServiceHost` + embedded client templates. Setup
   becomes activation-aware: no usable service key is created until the
   unlock secret is present; existing keys are wrapped on migration.
8. **How does vendor licensing console change?** It must record Computer ID,
   issue the unlock artifact, bind it to license/customer/installation,
   track activation, code issuance, moves, and reissues.
9. **How does customer management UI change?** `--license-status`,
   `--create-activation-request`, `--activate`, plus a new visible
   `UnlockSecretAvailable`/`ProtectedServiceKeyWrapped` state. Setup/provision
   should explain "activation required before protected services can be
   created".

Verdict: **Recommended.** Strongest support for the "missing critical
component" business requirement, compatible with the existing trust anchor
and offline workflow, and does not require protocol redesign.

### 6.2 Option B — Missing assembly / plugin

**Core idea:** Ship a product with a small DLL/component absent; install it
and verify a signature after activation.

Security answers:

1. **Local admin bypass?** Yes, easily if the DLL is a normal file. It can be
   copied from another activated machine or from a locally activated one.
   It is only weak protection unless the DLL itself is machine-bound
   encrypted — at which point it becomes Option A.
2. **License file copied?** A separate DLL is not meaningfully machine-bound
   unless encrypted and tied to Computer ID.
3. **Patch binary?** DLLs can be swapped/replaced and signatures removed; the
   same patching concern remains.
4. **Computer ID binding?** Possible, but adds complex plugin packaging and
   requires embedding encrypted plugin data.
5. **Recovery?** Reissuing a plugin is like reissuing a license; less smooth
   because plugin identities and versions are harder to manage.
6. **Support?** More complex because component versions and deployment
   failures become support issues.
7. **Installer?** SSP is currently single-file with embedded
   `SSP.Client`/`SSP.ServiceHost` images. Adding a separate runtime DLL
   contradicts that design and increases failure modes.
8. **Vendor console?** Must manage plugin packages/versions, not just
   entitlement.
9. **Customer UI?** Must handle plugin install/version state.

Verdict: **Rejected as the primary mechanism** for SSP. It does not remove
the critical capability in a cryptographically meaningful way, adds deployment
complexity, and conflicts with the single-file architecture. It may later be
used simply as an edition packaging vehicle (Option C), not as the protection
boundary.

### 6.3 Option C — Feature package model

**Core idea:** Separate capability packages; the license controls package
availability.

Security answers:

1. **Local admin bypass?** Same as D: it is still a gate over installed
   software; an admin can provision/copy packages if the gate is patched.
2. **License file copied?** Machine binding can be used, but package
   availability alone is still a license flag.
3. **Patch binary?** Yes, same class of risk.
4. **Computer ID binding?** Possible.
5. **Recovery?** Good for edition changes and upgrades.
6. **Support?** Good if packages are versioned cleanly.
7. **Installer?** More complex, additional packages.
8. **Vendor console?** Strong fit for edition management and upgrade paths.
9. **Customer UI?** Strong fit for self-service edition/package visibility.

Verdict: **Good as a future enterprise/editioning layer, not sufficient for
the primary requirement.** Packages are still software that exists or can be
installed; their availability is controlled by a gate. Use Option A for the
critical element and Option C later for tier/edition management.

### 6.4 Option D — Improve the current license gate only

**Core idea:** Keep the current model; harden validation/enforcement.

Security answers:

1. **Local admin bypass?** The gate is code; a determined admin can patch it.
   Machine-bound license and DPAPI state help, but do not require a missing
   cryptographic element.
2. **License file copied?** Current `InstallationId` and DPAPI state prevent
   trivial copying; still susceptible to coordinated cloning.
3. **Patch binary?** Yes; this is the main limitation.
4. **Computer ID binding?** Already present.
5. **Recovery?** Good, existing flows.
6. **Support?** Good.
7. **Installer?** Essentially unchanged.
8. **Vendor console?** Good, existing console already supports issuance.
9. **Customer UI?** Already has status/install/activate.

Verdict: **Retain as the outer compliance layer, but do not make it the sole
protection.** The business requirement explicitly asks for a component that
does not exist before activation; a gate alone does not satisfy that.

---

## 7. Recommended architecture

### Core principle

Use a **capability-gated cryptographic unlock** rather than only an
entitlement gate:

- The complete SSP code is still installed, as the requirement allows, but the
  **cryptographic capability needed to operate a protected service** is
  absent before activation.
- The capability is delivered as an authority-signed, machine-bound
  **activation-unlock artifact**.
- The capability is used to unwrap the per-service server private key.
- Without it, the server cannot authenticate itself to clients nor unwrap
  the session key, so the protected service cannot provide its service.

### Components to add

Additions are SSP-specific. The vendored `SSP.Activation` library should be
changed as little as possible; where possible, new SSP-specific types and a
smallly extended activation/issuance path should live outside the vendored
core.

| New type / file area | Responsibility |
| --- | --- |
| `SspActivationUnlockArtifact` (model) | Signed unlock payload: license id, product id, customer id, installation/Computer ID, code hash, sequence, unlock id. |
| `SspActivationUnlockCodec` | Strict canonical JSON + size cap + schema validation (mirrors `LicenseArtifactCodec`). |
| `SspActivationUnlockValidator` | Verifies authority signature, product/license/Computer-ID binding, sequence and activation-code hash; never leaks secrets. |
| `SspUnlockSecretStore` | Durable encrypted storage of the derived/released Unlock Secret, reusing `ProtectedFileStore` and the existing out-of-directory witness pattern. |
| `SspServiceKeyStore` | Wraps/unwraps per-service `.sysdata.bin` under a service-specific wrapping key derived from the Unlock Secret. |
| `SspActivationService` extension | `CreateActivationRequest` includes Computer ID + machine unwrap key; new `TryActivateWithUnlock` transition publishes `Valid` only after unlock verification. |
| `SspRuntimeLicense` extension | Verifies unlock material is present before `AuthorizeServiceStart`; loads service key only through `SspServiceKeyStore`. |
| `tools/SSP.LicenseAuthority` extension | `issue-certified` + `activate` produce the signed unlock artifact and write it to an activation record. |

### Data at rest

- `license.json` remains the signed, plaintext license artifact.
- `activation-unlock.json` is the new authority-signed, machine-bound unlock
  artifact. It is delivered with the activation response, not the initial
  product.
- `.sysdata.bin` for **new** service setups becomes a wrapped key file. The
  wrapper is AES-256-GCM using a key derived from the Unlock Secret and the
  service identity:
  `K_service = HKDF(unlockSecret, salt=serviceDir/applicationName,
  info="SSP-SERVICE-KEY-WRAP-v1")`.
- Public key `.runtime.dat` remains plaintext for client package embedding.
- The activation code remains a 10-digit human factor; the **Unlock Secret is
  high entropy** and is delivered only in the activation response. The code
  is never the only cryptographic secret.

### Why this is the best fit

1. **It uses the smallest truly critical element.** In SSP, the per-service
   server private key is already the thing that proves server identity and
   decrypts the session key. Protecting it protects the service.
2. **No protocol redesign.** `ServerProtocol`, `ServerGateway`,
   `Messages.cs`, `TunnelCodec`, `AesGcmCrypto`, `RsaCrypto`, and client
   enrollment remain unchanged.
3. **No client change.** `SSP.Client` and `SSP.ServiceBuilder` remain
   licensing-free.
4. **The existing trust anchor is reused.** The unlock artifact is signed by
   the same authority public key already embedded in `SspTrustAnchor`.
5. **The existing activation UX is preserved.** `--install-license`,
   `--create-activation-request`, `--activate <code>`, and the
   `tools/SSP.LicenseAuthority activate` flow remain; the response adds a
   machine-bound unlock payload.
6. **Anti-rollback and witness infrastructure is reused.** The Unlock Secret
   and activation state ride the existing DPAPI-protected store and
   out-of-directory witness.
7. **It is compatible with a future Option C editions layer.**

---

## 8. Detailed reasoning

### 8.1 Why the server private key is the right "small critical element"

- `ServerProtocol.HandleAsync` **must** sign a fresh nonce with the server
  RSA private key before any client message is processed
  (`RsaCrypto.Sign(_serverPrivateKey, serverNonce)`).
- `ClientProtocol` refuses to continue unless that signature verifies against
  the public key embedded in the client bundle.
- `ServerProtocol.ReceiveSessionKeyAsync` refuses to accept a session key
  unless it can `RsaCrypto.DecryptOaep(_serverPrivateKey, wrapped)`.
- Therefore if the server private key is unavailable, the protocol fails
  closed before any traffic can be relayed — even if every other license flag
  were somehow set.

This is exactly a "component that does not exist before activation": the
**Unlock Secret + unwrap capability** is absent, so the server private key is
inert.

### 8.2 Why a separate unlock artifact is better than putting the secret only in the existing license

- The existing license artifact is installed *before* activation. If the
  high-entropy unlock secret were embedded there, it would exist before
  activation, violating the stated requirement.
- The `tools/SSP.LicenseAuthority activate` action currently consumes a
  single-use OTT and returns a code. That same offline response can also
  produce the signed unlock artifact without changing the transport model.
- A separate artifact keeps the existing `SSP.Activation` artifact versioning
  and validator mostly unchanged, reducing the risk to a very heavily tested
  library.

### 8.3 Why not modify the protocol

The user specifically asked whether the missing server authentication key
could be the activation unlock mechanism without redesigning the protocol,
tunnel, enrollment, or existing cryptography. **Yes, if we protect the key at
rest instead of moving key generation to the vendor.** Moving the server key
generation entirely into the authority would be a major change: it would
require delivering private key material across an offline channel, escrowing
per-machine keys, changing setup, client bundling, and rotation. It is not
needed.

### 8.4 Why the 10-digit code must not be the only cryptographic secret

The 10-digit activation code is only about 10^10 candidates. If the code were
the sole key used to unwrap the service key, a local attacker holding the
license and unlock artifact could brute-force it offline. The recommended
design therefore:

1. Uses the code only to authorize activation and to verify customer intent.
2. Delivers a **high-entropy Unlock Secret** in the authority's offline
   activation response.
3. Binds that secret to the customer's Computer ID and to the machine-side
   unlock keypair.

This keeps the operator UX (10-digit code) while avoiding a
code-only cryptographic fence.

---

## 9. Activation workflow

### 9.1 New installation

1. Customer installs SSP using the existing `SSP.Server.exe` /
   `SSP.ServiceHost` / embedded client template distribution.
2. On first activation-aware setup/status run, SSP resolves the stable
   Computer ID (`InstallationId`), creates a machine-side `InstallationUnlock`
   keypair if the unlock artifact uses public-key encapsulation, and shows the
   Computer ID in `--license-status`.
3. The product cannot provision or start any protected service yet.

### 9.2 Offline license issuance

4. Customer provides the Computer ID (`InstallationId`) to the vendor.
5. Vendor issues a machine-bound `ssp-license` v2 artifact with
   `InstallationId` set, optionally `ComputerName`, and activation required.
6. Vendor returns the license artifact.

### 9.3 Activation

7. Customer installs the license: `SSP.Server --install-license <file>`.
8. SSP validates the signature/bindings and reports `ActivationRequired`.
9. Customer runs `SSP.Server --create-activation-request`; the request
   carries the license identity, the existing activation OTT, and the
   Computer ID/machine unlock public key.
10. Vendor runs `tools/SSP.LicenseAuthority activate`; it matches the OTT,
    generates the 10-digit code, consumes the OTT, and emits an
    `activation-unlock.json` payload encrypted/signed to the customer's
    Computer ID.
11. Customer receives the code (email) and the activation-unlock artifact
    (same out-of-band channel, or an attached file from the vendor console).
12. Customer runs `SSP.Server --activate <code>` after importing the unlock
    artifact.
13. SSP verifies the activation code hash, verifies the unlock artifact
    against the authority anchor and machine binding, derives/releases the
    Unlock Secret, persists it in the encrypted state store/witness, and
    transitions to `Valid`.
14. SSP is now able to unwrap/create per-service server keys and operate.

### 9.4 Provisioning / service start

15. Setup may now run (`SetupEngine`). It wraps the per-service server private
    key using the Unlock Secret and stores `.sysdata.bin` wrapped.
16. `SspRuntimeLicense.CreateForService` validates the license and confirms
    the Unlock Secret is available, then `SspServiceKeyStore` unwraps the key
    and hands it to `ServerGateway`/`ServerProtocol`.
17. Protocol, enrollment, session-key establishment, and tunneling operate
    exactly as today.

### 9.5 Alternative if a pure 10-digit code-only workflow is mandatory

A fallback level can derive the unlock key from `HKDF(ComputerId,
activationCode, info)` without a separate high-entropy payload. This preserves
the 7–13 UX but is weaker because the code's 10-digit entropy is the only
secret contribution. **Recommendation: use this only for internal/early
deployments; for commercial deployments, deliver the high-entropy unlock
artifact.**

---

## 10. Computer ID binding design

### 10.1 What exists today

`SspInstallationIdentityProvider`
(`src/SSP.Server/Activation/SspInstallationIdentityProvider.cs`) reads the
Windows `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, hashes it with
SHA-256 and a domain-separation tag
(`SSP-LICENSE-INSTALL-v1`), and returns lowercase hex. The raw MachineGuid
never leaves the provider. Non-Windows hosts return null and bound licenses
fail closed.

This is the correct foundation for the "Computer ID".

### 10.2 Why MachineGuid remains the primary source

- Stable across reboots and ordinary hardware churn.
- Not directly hardware-dependent, so it avoids the fragility of MAC/SMBIOS
  collection (VMs, cloned images, adapters, cloud instances).
- It is OS-generated identity, which is easy for support to explain and easy
  to re-bind after reinstall/sysprep.
- It is already part of the signed license pipeline, so adding unlock binding
  to it is small.

### 10.3 Recommendation

- **Primary Computer ID:** existing `InstallationId`
  (`SHA-256(MachineGuid ‖ SSP-LICENSE-INSTALL-v1)`).
- **Do not use raw MAC/SMBIOS/CPU ID as the primary key.** They are often
  duplicated in cloned/cloud/virtual environments, change with hardware
  replacement, and are not reliable commercial binding tokens.
- Optionally add a **stability claim** field that records additional
  machine information (e.g. machine name, TPM/WMI summary) for support
  diagnostics only, never as a trust input.
- The activation-unlock artifact is additionally bound to the same
  `InstallationId` so that a copied license + copied unlock payload fails on
  another machine.
- The existing license-state binding id
  (`SSP-LICENSE-STATE-BIND-v1`) should continue to be used for the durable
  state and witness binding; keep it distinct from the license-binding id.

### 10.4 Hardware replacement recovery

- If hardware changes but the OS image/MachineGuid is reused, Computer ID does
  not change; no action required.
- If the OS is reinstalled/MachineGuid changes, the installation appears as a
  new Computer ID. Vendor support can:
  - mark the previous activation as replaced/moved in the authority console,
  - issue a new license for the new Computer ID,
  - optionally revoke the old activation record.
- This is administrative hardening, not a security weakening.

---

## 11. Installer impact

SSP has no install package in the repository beyond
`ServerInstallationBootstrapper` (copies `SSP.Server.exe`, creates a desktop
shortcut), `SetupEngine` (provisions services), and `WindowsServiceInstaller`
(registers/extracts `SSP.ServiceHost`). The recommended mechanism therefore
has a modest installer impact:

1. **No new large artifacts.** The base install continues to ship
   `SSP.Server.exe`, embedded `SSP.Client` template, and embedded
   `SSP.ServiceHost` image.
2. **First-run activation readiness.** On first launch, SSP should generate
   the `InstallationUnlock` keypair (if used) and show the Computer ID /
   activation status before setup can create a protected service.
3. **Setup/provision becomes activation-aware.** `SetupEngine` must not
   create usable plaintext server keys if the Unlock Secret is unavailable.
   It should either refuse before key generation or generate a placeholder
   only after the unlock is present.
4. **Existing service migration.** The upgrade path detects an existing
   plaintext `.sysdata.bin`:
   - If already activated and an Unlock Secret is available, rewrap the key
     in place.
   - If not activated, refuse service start and direct the operator to
     activate first. Do not silently retain an unprotected key.
5. **Authenticode remains mandatory.** The unlock artifact is separate from
   Authenticode; both trust chains remain disjoint.
6. **The existing `SSP_LICENSE_ROOT` test/dev seam** may be extended for
   `activation-unlock` and unlock-state paths for tests, but it must never
   be able to disable signature/machine checks.

---

## 12. Vendor license management console impact

The vendor-side system is `tools/SSP.LicenseAuthority` plus the operationally
managed private key and activation records. Recommended changes:

| Area | Change |
| --- | --- |
| Computer ID | Store customer Computer ID/InstallationId; show it in records. |
| License issuance | Existing `issue-certified` adds `--installation-id`, `--computer-name`; keep v2 activation material. |
| Activation records | Extend `ActivationRecord` with the unlock secret, unlock artifact digest, machine unlock public key, and consumed/latest state. |
| Activation response | `activate` must consume the OTT, return the code, and emit `activation-unlock.json` (signed + machine-bound). |
| Moves/replacements | Add a "deactivate/move/reissue" operation that revokes or consumes the old unlock/activation and issues for a new Computer ID. |
| Revocation | A signed `revoked` license renewal remains the revoked path; the unlock artifact should be bound to the same `sequenceNumber`/license id so a revoked license cannot use its old unlock secret. |
| Storage | Activation records and unlock secrets are authority-side secrets, never in the repo/build/CI/customer artifacts. |
| Audit | Keep activation issue/consume/reissue audit logs (customer id, license id, machine id, date) without secret material. |

The authority private key continues to be supplied per invocation and never
embedded in the product. The unlock artifacts are signed with the same root
authority, reusing `SspTrustAnchor`.

---

## 13. Customer management console impact

The customer console today is CLI-driven (`SSP.Server --license-status`,
`--install-license`, `--create-activation-request`, `--activate`,
`--trust-anchor-info`) plus the Windows service UI / dialogs. Recommended
changes:

1. **Show activation-plus-unlock state.** `DescribeStatus()` should report:
   - `UnlockSecretAvailable` / `ActivationUnlockMissing`.
   - `ProtectedServiceKeyState` (wrapped / unwrapped available / missing).
   - Which protected services are currently able to start.
2. **Keep simple operator flow.** The UI should present:
   - "Your Computer ID: ..."
   - "Import license file"
   - "Create activation request"
   - "Import activation unlock + enter code"
   - "Activated" confirmation.
3. **Setup screen gating.** Disable protected-service creation until
   `Valid` + Unlock Secret is present. Existing `--setup`/`--setup-batch`
   should produce a clear "activate first" error when unlock is missing.
4. **Diagnostics and support.** Export a **secret-free support bundle** with
   status, Computer ID, license id, activation state, presence of unlock
   material, but never the Unlock Secret, activation code, private keys, or
   signature bytes.
5. **No customer-visible cryptographic key material.** Code and secret
   material stay out of logs, dialogs, and event sinks.

---

## 14. Migration plan

### Phase 0 — design freeze / no code changes

- Record this decision; do not modify code until approval.
- Agree on the exact unlock artifact schema, canonical form, and whether to
  use the machine unlock keypair or the pure code-derivation fallback.

### Phase 1 — library/SSP.Server additive changes

- Add the unlock artifact schema/codec/validator.
- Extend `SspLicenseStateStore`/witness to persist Unlock Secret state.
- Add `SspServiceKeyStore` wrapping/unwrapping.
- Keep existing plaintext key path available on non-activated/test builds via
  an explicit fail-closed seam; do not silently keep plaintext keys in
  production.

### Phase 2 — authority tooling

- Extend `tools/SSP.LicenseAuthority` to generate unlock artifacts and emit
  them on `activate`.
- Extend activation records with unlock material/metadata.
- Keep the existing `--activate` code output; add an optional artifact output.

### Phase 3 — migration of existing installs

- For existing activated installs: on first startup, migrate plaintext
  `.sysdata.bin` to wrapped form using the already-activated Unlock Secret.
- For existing unactivated installs: force activation before any protected
  service starts; do not allow a plaintext key to continue serving.
- Preserve anti-rollback state, witness, sequence floors, and activation ids.
- Do not break developer/test builds: an unanchored/unarmed build remains
  fail-closed as today (`SSP_SKIP_EMBED`, `LicensedTestEnvironment`,
  `UnlicensedTestGate`).

### Phase 4 — hardening and adoption

- Add machine-bound unlock payload verification tests.
- Add recovery/move/reissue support tests.
- Run full suite under .NET 8 SDK before sign-off (current docs note the
  automated suite could not be executed in this environment because `dotnet`
  is not installed).

---

## 15. Repository changes required

These are the likely **future** changes after approval. **None were made in
this task.**

### New SSP-specific files (server side)

- `src/SSP.Server/Activation/SspActivationUnlockArtifact.cs`
- `src/SSP.Server/Activation/SspActivationUnlockCodec.cs`
- `src/SSP.Server/Activation/SspActivationUnlockValidator.cs`
- `src/SSP.Server/Activation/SspUnlockSecretStore.cs`
- `src/SSP.Server/Activation/SspServiceKeyStore.cs`
- `src/SSP.Server/Activation/SspInstallationUnlockKeyPairProvider.cs`
- Corresponding tests in `tests/SSP.Tests/Activation/*`.

### Modified SSP files

- `src/SSP.Server/Activation/SspActivationService.cs` — extend request /
  activation to import and release unlock material.
- `src/SSP.Server/Activation/SspRuntimeLicense.cs` — require unlock presence
  before `AuthorizeServiceStart`.
- `src/SSP.Server/Setup/SetupEngine.cs` — create wrapped service keys; refuse
  plaintext protected key creation after activation-aware mode is armed.
- `src/SSP.Server/Program.cs` — add `--import-activation-unlock` / related
  status output if not folded into `--activate`.
- `src/SSP.Server/Activation/SspLicensePaths.cs` — add unlock artifact path /
  unlock state path (test-redirectable via a dedicated seam).
- `src/SSP.Server/Activation/SspInstallationIdentityProvider.cs` — likely no
  semantic change; the existing `GetInstallationId()` is the Computer ID.
- `src/SSP.Server/Activation/SspLicenseStateStore.cs` — persist unlock
  material in encrypted primary/witness history.
- Possible additive `ProtectedFileStore` protected-name entry for the unlock
  secret or wrapped service key file.
- `core/CodeIntegrity` manifest tooling must include the new unlock/wrapped-key
  state if it is part of a protected runtime component; at minimum the
  startup gate remains before key load.

### Authority tool changes

- `tools/SSP.LicenseAuthority/ActivationRecord.cs`
- `tools/SSP.LicenseAuthority/LicenseIssuance.cs`
- `tools/SSP.LicenseAuthority/Program.cs`
- `tools/SSP.LicenseAuthority/AuthorityKeyMaterial.cs` (metadata only)

### Files that should remain untouched

- `src/SSP.Core/Protocol/*` — wire protocol.
- `src/SSP.Core/Crypto/RsaCrypto.cs`, `AesGcmCrypto.cs` — algorithm
  wrappers stay unchanged.
- `src/SSP.Server/Runtime/ServerProtocol.cs`,
  `ServerGateway.cs` — should not change; they still receive an `RSA`.
- `src/SSP.Client/**` — remains licensing-free.
- `src/SSP.Core/Models/ServiceConfig.cs` and client bundle/patch-slot format
  — no schema change needed.

---

## 16. Risks and open questions

### Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Local admin patches SSP binary to bypass unlock | High (if trusted) | High | Authenticode + `RuntimeCodeIntegrity`; accept residual as software-only. |
| 10-digit activation code brute-forced offline if used as the only secret | Medium | High if no high-entropy unlock payload | Always deliver high-entropy machine-bound unlock payload; never rely on code alone. |
| Existing plaintext service key remains readable after upgrade | Medium | High | Mandatory migration/rewrap; fail-closed when activation/unlock is unavailable. |
| Unlock secret lost or corrupted | Low | High (availability) | Persist in DPAPI primary + witness; vendor reissue path. |
| MachineGuid changes on reinstall/clone | Medium | Medium (support) | Rebind/reissue; document support move/reissue process. |
| Vendor console/store compromise | Low | High | Authority side keeps unlock secrets outside repo/build/CI; HSM/vault semantics. |
| Copy of activation-unlock artifacts from one customer to another | Low | Medium | Strong Computer ID binding + unlock artifact bound to installation/Computer ID. |
| Unlock artifact replay/rollback | Low | Medium | Bound to license/sequence; state-store floor and witness enforce monotonicity. |
| Test/dev build behavior diverges from production | Medium | Medium | Keep unanchored/unarmed builds fail-closed; add `SSP_SKIP_EMBED`-compatible unlock seam. |

### Open questions to resolve before implementation

1. **High-entropy unlock delivery channel.** Can the vendor send an
   `activation-unlock.json` attachment in the same email/response, or must
   the 10-digit code be the only artifact? This determines whether we use the
   strong Level 2 or the weaker code-derived Level 1.
2. **Machine unlock keypair vs. code-derived key.** If a machine keypair is
   used, where is its private key stored and who creates it? Recommendation:
   create it from `SspInstallationIdentityProvider` + a protected install-time
   secret; never in client or logs.
3. **Should unlock material be embedded in the license artifact or separate?**
   Recommendation: separate, so the high-entropy secret does not exist before
   activation.
4. **Backward compatibility with existing plaintext `.sysdata.bin`.**
   Exact migration/upgrade behavior for installs that already have service
   directories and a valid license.
5. **Whether the activation `UnlockSecret` should also be usable for other
   editions/features.** If yes, design it as a general "activation secret",
   not a service-key-unwrap-only secret.
6. **Whether to keep a beta/dev "unlock by test license" seam.** Should be
   explicitly fail-closed in production; test assemblies only.
7. **Do we want a separate activation-unlock authority key or reuse the root
   authority key?** Reusing the same key is simpler and compatible with
   `SspTrustAnchor`; a separate key would require a second trust-anchor
   ceremony.
8. **Hardware replacement policy.** Is a same-OS/reinstall move handled by
   support reissuance, or should a TPM/attestation flow be optional? The
   current project is offline-first; keep TPM/attestation out of scope unless
   product demands it.
9. **Vendor console scope.** Is the "vendor license management console" an
   existing product or a new one? The repository only has
   `tools/SSP.LicenseAuthority`; the production console is outside this repo.
10. **Test runtime.** No .NET SDK is installed in the current environment;
    all new code and migration paths must be compiled/executed in a .NET 8
    environment before the architecture is implemented.

---

## Conclusion

The recommended architecture is **Option A, implemented as a
machine-bound, authority-signed activation-unlock artifact that releases a
high-entropy Unlock Secret required to unwrap the per-service server
private key.** This is the smallest source-mapped change that makes the
critical element genuinely absent before activation, does not redesign the
protocol, tunnel, enrollment, or existing cryptography, and remains
compatible with the current offline activation workflow. Option D remains as
the outer license gate, and Option C is a later extension for editions.

This is an architecture decision only. **No source code, tests, build files,
or configuration were modified, no implementation was performed, and no pull
request was created.**
