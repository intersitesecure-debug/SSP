# SSP License Activation Architecture (v2)

Status: design + implementation record. This document describes only what is
implemented in the repository. It complements `docs/LICENSE_AUTHORITY.md`
(authority operations) and `docs/THREAT_MODEL.md` (threat catalogue).

## 1. Trust chain (two levels)

```
Root Authority Key  (compiled-in, immutable SSP Licensing Authority public key)
        │
        │ signs (RSA-PSS-SHA256)
        ▼
Per-License Key Certification   (LicenseId, ProductId, CustomerId,
        │                        NotBefore/ExpiresAt, leaf public key SPKI,
        │                        optional activation OTT + activation-code hash)
        │ certifies
        ▼
Per-License Leaf Public Key  (fresh RSA key per issued license)
        │
        │ signs (RSA-PSS-SHA256)
        ▼
License Payload  (all license/customer/installation fields)
```

* The root authority public key remains the only trust anchor (`SspTrustAnchor`
  → `LicenseTrustAnchor`). A public key found inside a license artifact is
  **never** trusted by itself: it is only usable after the root signature over
  its certification verifies.
* The leaf private key never exists in `SSP.Server`, in the license artifact,
  or in any shipped binary. It exists only authority-side, generated per
  license, and is never persisted for reuse across licenses.
* Compromise of license A's leaf key cannot forge license B: license B's
  artifact embeds B's certification (bound to B's `LicenseId`/`CustomerId` and
  B's distinct leaf public key), and A's key produces a signature that does not
  verify under B's certification.

## 2. Artifact versions

| version | format | verification | activation |
|---|---|---|---|
| 1 (legacy) | `ssp-license` envelope, root signs payload directly | root verifies payload signature | none |
| 2 (current) | `ssp-license` envelope + `keyCertification` + `keyCertificationSignature` | root verifies certification; leaf verifies payload | certification may carry OTT + code hash |

* Version 1 remains accepted (legacy licenses). It is *not* insecure: the root
  authority is the highest trust, and signing the payload directly is strictly
  stronger than signing a leaf key. Version 2 exists to add the per-license key
  isolation and activation workflow.
* Unknown versions fail closed (`unknown_artifact_version`).
* The existing `LicenseIssuer.EncodeLicenseArtifact` continues to produce
  version 1 (legacy, root-signed). New issuance of version 2 goes through
  `LicenseCertificationIssuer`.

## 3. Activation model (separate from enrollment)

The existing SSP client-enrollment OneTimeToken / AuthenticationCode flow is
**not** reused. Licensing activation is its own mechanism:

1. The Licensing Authority generates a random activation OTT (256-bit,
   base64url) and a 10-digit activation code.
2. The code is **never stored in plaintext in the license artifact**; only its
   SHA-256 (`activationCodeHash`) is signed into the certification. The OTT is
   also signed into the certification (the customer cannot replace it).
3. The certificate + leaf key sign the license payload.
4. `SSP.Server` loads the artifact, verifies the whole chain, then reports
   `ActivationRequired` (not `Valid`). All protected operations stay
   fail-closed because the policy only allows `LicenseState.Valid`.
5. The customer runs `SSP.Server --activate <code>`. The server hashes the
   typed code and compares it (constant time) with the signed hash, then
   persists `ActivatedLicenseId` in the DPAPI state store and revalidates to
   `Valid`.
6. Activation is bound to the specific `LicenseId` (single-use per license) and
   survives restart (the activated license id is durable).

`SSP.Server` never generates an activation code (enforced by
`LicenseAuthoritySecurityIsolationTests`).

## 4. Offline transport (implemented now)

```
SSP.Server --create-activation-request
        │  writes an activation-request file (license identity + OTT)
        ▼
activation-request.json      (licensing directory; transport only)
        │  transferred out-of-band (email / phone / support ticket)
        ▼
SSP Licensing Authority  `activate --request ... --activation-record ...`
        │  validates the OTT (single-use), consumes it, prints the code
        ▼
operator
        │  types the code into the server
        ▼
SSP.Server --activate <code>
```

The request file is not a security boundary: the OTT's authority is established
by the authority matching it against its own activation record. A forged OTT
simply does not match.

## 5. Transport != cryptography != activation state

* **Cryptography/protocol** (`SSP.Activation`): `LicenseKeyCertification`,
  `LicenseKeyCertificationCanonicalJson`, `LicenseCertificationIssuer`,
  `LicenseActivation` (OTT/code generation + verification), the certified
  validation pipeline, and the `ActivationRequired` state.
* **Activation state**: `LicenseStateRecord.ActivatedLicenseId` (DPAPI-backed
  via `SspLicenseStateStore`), consulted by `LicenseValidator` and written by
  `LicenseManager.TryActivate`.
* **Transport**: the request file written by `SSP.Server` and read by the
  authority CLI is the current *offline* transport. It serializes the shared
  `ActivationRequest` message via `ActivationRequestCodec` (pure data + strict
  serialization). A future `HttpsActivationTransport` would send the same
  `ActivationRequest` bytes over HTTPS and consume the same authority-side OTT
  validation — no change to the certificate chain, the activation state machine,
  signature validation, installation binding, anti-rollback or policy.

## 6. Customer identity fields

`LicensePayload` gains two optional, signature-covered fields:

* `OrganizationOrPersonName` → canonical JSON key `organizationName`
* `ComputerName` → canonical JSON key `computerName`

They are part of the signed payload (tampering invalidates the signature) and
are shown in `--license-status` and in the activation request. `ComputerName`
is an additional administrative binding; the cryptographic installation binding
remains `InstallationId` (unchanged). The authority CLI issues them via
`--organization-name` / `--computer-name`.
