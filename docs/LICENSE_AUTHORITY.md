# SSP Licensing Authority tooling

Offline, authority-side CLI. It is **not** part of any customer SSP ship
(`SSP.Server`, `SSP.ServiceHost`, `SSP.Client`, `SSP.ServiceBuilder`). It
holds **no key material of its own**: the Licensing Authority private key is
supplied on every invocation as a file that must live **outside** this
repository, outside the SSP build, and outside every shipped artifact.

Issuance uses the `SSP.Activation` issuing API over the `ssp-license`
format / `RSA-PSS-SHA256`:

* `issue` produces the legacy **v1** envelope (the root authority signs the
  payload directly) via `LicenseIssuer`.
* `issue-certified` produces the **v2** envelope (the root authority certifies
  a fresh per-license key; that leaf key signs the payload) via
  `LicenseCertificationIssuer`, optionally carrying the activation OTT and the
  SHA-256 of a 10-digit activation code.

Both formats are part of one `ssp-license` format family; the envelope
version is `artifactVersion` (see `docs/LICENSE_ACTIVATION_ARCHITECTURE.md`).

Companion: `TRUST_ANCHOR_KEY_CEREMONY.md` (how the *public* half is compiled
into a release binary). This document is how the *private* half is used to
issue licenses.

---

## 1. What this tool is allowed to do

| Command | Purpose | Private key? |
| --- | --- | --- |
| `keygen` | Generate a production **RSA-3072** authority key pair. Writes the private key only to `--private-key`. Writes the public key **only** if `--public-key` is passed. | writes it |
| `export-public` | Export the SPKI `BEGIN PUBLIC KEY` PEM from a private key file. | reads it |
| `fingerprint` | Print (and optionally `--expect`) the SPKI SHA-256 of the public key. Same algorithm as `SSP.Server --trust-anchor-info`. | optional (public half) |
| `issue` | Sign a `LicensePayload` with `LicenseIssuer.EncodeLicenseArtifact` (v1). | reads it |
| `issue-certified` | Sign a v2 artifact: root certifies a fresh per-license key, that key signs the payload; optional `--activation-required` adds the activation OTT + 10-digit code and writes an activation record. | reads it |
| `renew` | Re-issue an existing artifact with a **higher** `sequenceNumber` (renewal or signed revocation). Verifies the original signature first. | reads it |
| `inspect` | Decode and print payload fields. Does **not** verify the signature and never prints signature bytes. | no |
| `verify` | Run the existing `LicenseValidator` pipeline against `--public-key`. Exit 0 iff `Valid`. | no |
| `activate` | Match a customer activation request's OTT against an activation record (single use) and print the 10-digit code. | no |

The tool never:

* reads a private key from the environment, from a compiled resource, or from
  the SSP licensing directory
* embeds a private key in `SSP.Server` / `SSP.ServiceHost` / client binaries
* changes the compiled-in trust anchor of a running SSP process
* weakens fail-closed behaviour of an unanchored development build

---

## 2. Key material lives outside the repository

```powershell
# On the offline ceremony host / HSM — NEVER in the SSP working tree,
# NEVER on a build machine, NEVER in CI secrets.
dotnet run --project tools/SSP.LicenseAuthority -- keygen `
    --private-key D:\ceremony\ssp-authority-private.pem `
    --public-key  D:\ceremony\ssp-authority-public.pem
```

`keygen` prints the SPKI SHA-256 (secret-free) and refuses to print PEM.
Record that fingerprint in the ceremony minutes; it is the value passed to
the release build as `-p:SspAuthorityPublicKeySha256=...`.

Equivalent OpenSSL form (also acceptable; see `TRUST_ANCHOR_KEY_CEREMONY.md`):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ssp-authority-private.pem
openssl rsa -in ssp-authority-private.pem -pubout -out ssp-authority-public.pem
```

Production preferred form is an HSM non-exportable key. Software PEM is the
reference ceremony for hosts that do not yet have an HSM.

Show / verify the fingerprint without exposing the private key:

```powershell
dotnet run --project tools/SSP.LicenseAuthority -- fingerprint `
    --public-key D:\ceremony\ssp-authority-public.pem `
    --expect <fingerprint from the minutes>
```

---

## 3. Issuing a license (existing payload schema)

Required payload fields are exactly those of `LicensePayload`:

`licenseId`, `productId`, `productName`, `customerId`, `customerName`,
`edition`, `licenseVersion`, `issuedAt`, `notBefore`, `expiresAt`,
`installationId?`, `organizationName?`, `computerName?`, `featureSet`,
`limits`, `status`, `sequenceNumber`.

`--organization-name` and `--computer-name` are optional signature-covered
identity fields (administrative binding, shown in `SSP.Server --license-status`
and in the activation request). They never replace `--installation-id`, which
remains the cryptographic installation binding.

```powershell
dotnet run --project tools/SSP.LicenseAuthority -- issue `
    --private-key D:\ceremony\ssp-authority-private.pem `
    --output      D:\outbox\contoso-rdp.json `
    --customer-id 11111111-1111-1111-1111-111111111111 `
    --customer-name "Contoso Ltd." `
    --edition Enterprise `
    --installation-id <id from SSP.Server --license-status> `
    --feature rdp --feature ssh `
    --limit max_services=3 `
    --limit max_clients=10 `
    --limit max_concurrent_tunnels=5 `
    --not-before 2026-01-01T00:00:00Z `
    --expires-at 2027-01-01T00:00:00Z
```

Defaults:

* `--product-id` / `--product-name` = SSP product id `d81f65cb-bd7e-4a6e-9b4c-3be9d13c0f2a` / `"SSP"` (must stay identical to `SspLicensing`)
* `--license-id` = new GUID
* `--license-version` = `1.0`
* `--status` = `active`
* `--sequence` = `1`
* omitted `installationId` = floating (the tool warns; production licenses
  should be bound)
* omitted limits = unconstrained (library semantics)

`--spec spec.json` supplies the same fields as JSON (this is an *issuance
spec*, not a license artifact). CLI flags override spec fields. Passing a
signed `ssp-license` file as `--spec` is refused; use `renew`.

The customer installs the resulting file with:

```powershell
SSP.Server.exe --install-license D:\inbox\contoso-rdp.json
SSP.Server.exe --license-status
```

---

## 4. Renewal and revocation

Both are **signed re-issues**, not edits of the old file (an edit would
break the signature). `sequenceNumber` must increase so the anti-rollback
floor on the customer machine accepts the new artifact.

```powershell
# Renewal (new validity window, sequence += 1)
dotnet run --project tools/SSP.LicenseAuthority -- renew `
    --private-key D:\ceremony\ssp-authority-private.pem `
    --license     D:\outbox\contoso-rdp.json `
    --output      D:\outbox\contoso-rdp-seq2.json `
    --expires-at  2028-01-01T00:00:00Z

# Signed revocation (status=revoked, sequence += 1)
dotnet run --project tools/SSP.LicenseAuthority -- renew `
    --private-key D:\ceremony\ssp-authority-private.pem `
    --license     D:\outbox\contoso-rdp.json `
    --output      D:\outbox\contoso-rdp-revoked.json `
    --status revoked
```

`renew` will not re-sign an artifact whose signature does not verify against
`--private-key`. That closes the failure mode of minting a real authority
signature over a tampered payload.

---

## 4a. Activation-required issuance and offline activation

Issue a **v2** license that requires activation. The command generates a fresh
per-license key, a random activation OTT and a 10-digit activation code, writes
the signed license, and writes an activation record (authority secret):

```powershell
dotnet run --project tools/SSP.LicenseAuthority -- issue-certified `
    --private-key  D:\ceremony\ssp-authority-private.pem `
    --output       D:\outbox\contoso-rdp.json `
    --customer-id 11111111-1111-1111-1111-111111111111 `
    --customer-name "Contoso Ltd." `
    --edition Enterprise `
    --installation-id <id from SSP.Server --license-status> `
    --organization-name "Contoso R&D" `
    --computer-name TUNNEL-01 `
    --feature rdp --feature ssh `
    --limit max_services=3 `
    --activation-required `
    --activation-record D:\ceremony\activation-records\<licenseId>.json `
    --not-before 2026-01-01T00:00:00Z `
    --expires-at 2027-01-01T00:00:00Z
```

* The activation **code** is printed once and is **not** written into the
  license: only its SHA-256 (`activationCodeHash`) and the OTT are signed into
  the key certification. The leaf private key is generated, used, and discarded
  in-process — it is never persisted and never appears in any file.
* The **activation record** (`--activation-record`) contains the OTT and the
  plaintext code. It is authority secret material and must be kept with the
  authority private key: outside the repository, the build, CI and every
  customer artifact.
* Omit `--activation-required` for a pre-activated v2 license (no activation
  step needed on the customer machine).

When the customer's SSP.Server reports `ActivationRequired`, the customer
produces a request file and the authority answers with the code:

```powershell
# Customer machine:
SSP.Server.exe --install-license D:\inbox\contoso-rdp.json
SSP.Server.exe --create-activation-request     # writes activation-request.json
# ...send activation-request.json to the authority out-of-band...

# Authority host:
dotnet run --project tools/SSP.LicenseAuthority -- activate `
    --request D:\inbox\activation-request.json `
    --activation-record D:\ceremony\activation-records\<licenseId>.json
# prints the 10-digit code; the OTT is consumed (single use)

# Customer machine:
SSP.Server.exe --activate <code>               # transitions to Valid
```

`activate` refuses a request whose OTT does not match the record, whose
license id does not match, or whose record was already consumed. The OTT is
consumed only after a successful match, so a rejected attempt leaves the record
usable.

---

## 5. Inspection and verification

```powershell
dotnet run --project tools/SSP.LicenseAuthority -- inspect --license D:\outbox\contoso-rdp.json

dotnet run --project tools/SSP.LicenseAuthority -- verify `
    --license D:\outbox\contoso-rdp.json `
    --public-key D:\ceremony\ssp-authority-public.pem `
    --installation-id <customer installation id> `
    --expect-fingerprint <ceremony fingerprint>
```

`verify` is the existing six-stage `LicenseValidator` pipeline (parse,
signature, status, product, installation, time, optional anti-rollback
floor via `--highest-accepted-sequence`). Exit code 0 only for `Valid`.
Reports never contain PEM or signature bytes.

---

## 6. Fail-closed rules

* RSA only. EC / DSA / certificates / garbage PEM are refused.
* Keys smaller than 2048 bits are refused (library floor). `keygen` always
  produces 3072. Keys between 2048 and 3071 are accepted with a warning.
* A public-key command given a `PRIVATE KEY` PEM is refused by name.
* Existing output files are not overwritten without `--force`.
* Invalid payload fields (inverted time window, empty GUIDs, unknown
  status, negative limits, invalid feature names) fail at issue time.
* An unanchored SSP development build stays unanchored. This tool cannot
  provision, replace or bypass `SspTrustAnchor`.

Tests in `tests/SSP.Tests/Activation/Authority/` use **ephemeral** keys
under `Path.GetTempPath()` and never production ceremony material.
