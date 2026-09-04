# SSP Licensing Authority tooling

Offline, authority-side CLI. It is **not** part of any customer SSP ship
(`SSP.Server`, `SSP.ServiceHost`, `SSP.Client`, `SSP.ServiceBuilder`). It
holds **no key material of its own**: the Licensing Authority private key is
supplied on every invocation as a file that must live **outside** this
repository, outside the SSP build, and outside every shipped artifact.

Issuance uses the existing `SSP.Activation.LicenseIssuer` and the existing
`ssp-license` v1 / `RSA-PSS-SHA256` payload. This tool does not invent a
second license format.

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
| `issue` | Sign a `LicensePayload` with `LicenseIssuer.EncodeLicenseArtifact`. | reads it |
| `renew` | Re-issue an existing artifact with a **higher** `sequenceNumber` (renewal or signed revocation). Verifies the original signature first. | reads it |
| `inspect` | Decode and print payload fields. Does **not** verify the signature and never prints signature bytes. | no |
| `verify` | Run the existing `LicenseValidator` pipeline against `--public-key`. Exit 0 iff `Valid`. | no |

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
`installationId?`, `featureSet`, `limits`, `status`, `sequenceNumber`.

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
