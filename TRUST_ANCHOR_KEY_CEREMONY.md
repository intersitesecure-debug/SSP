# SSP Licensing Authority trust anchor — release key ceremony

**Status of this repository: fail-closed by design.** No SSP build produced from
this source tree carries a Licensing Authority public key. `SspTrustAnchor.IsCompiledIn`
is `false`, `SspTrustAnchor.Create()` throws, `SspRuntimeLicense.CreateForService(...)`
throws `trust_anchor_missing`, and no protected SSP service can start. That is the
intended state: the authority key pair is created and held **outside** the
repository, and only its **public** half is injected into a binary, at build time,
by the ceremony below.

The authority **private key never enters this repository, this build, or any
shipped artifact** — not as a file, not as a secret variable, not as a signing
step in CI. It is used only by the (future, P4) authority tooling on the offline
ceremony host / HSM that issues licenses.

---

## 1. What the build gives you (the seam)

`src/SSP.Server/Activation/SspTrustAnchor.targets` is imported by
`src/SSP.Server/SSP.Server.csproj` and provisions the anchor from MSBuild
properties:

| Property | Meaning |
| --- | --- |
| `SspAuthorityPublicKeyPemFile` | Path to the authority **PUBLIC** key PEM (`-----BEGIN PUBLIC KEY-----`, SubjectPublicKeyInfo). The file lives outside the working tree. Embedded verbatim as the manifest resource `SSP.Server.Activation.AuthorityPublicKey.pem`. |
| `SspAuthorityPublicKeySha256` | SHA-256 (hex) of that key's DER SubjectPublicKeyInfo, taken from the ceremony minutes. Recorded as assembly metadata and **enforced at runtime**: a binary that embedded a different key fails closed. |
| `SspRequireTrustAnchor` | `true` in every release pipeline: the build **fails** (`SSPTA001`) if no anchor was supplied, so an unanchored binary cannot be shipped by accident. |

Build-time refusals (all in `SspTrustAnchor.targets`):

* `SSPTA001` — release build without an anchor.
* `SSPTA002` — the PEM path does not exist.
* `SSPTA003` — the file contains `PRIVATE KEY` material.
* `SSPTA004` — the file has no `BEGIN PUBLIC KEY` block.
* `SSPTA005` (warning) — anchor embedded without a fingerprint pin.

Runtime refusals (all in `SspTrustAnchor.Create()`, all fail closed): missing
anchor, private-key material, unparsable SPKI, trailing DER data, key `< 2048`
bits, fingerprint ≠ pin.

There is **no** environment variable, config file, license file, registry value
or command-line switch that supplies the anchor to a running SSP process. The
only input that can create authorization on a customer machine is a signed
license artifact verified against this compiled-in key.

---

## 2. What must happen OUTSIDE this repository

1. **Generate the key pair on the offline ceremony host / HSM** (two-person
   control, recorded minutes). SSP mandates **RSA 3072** (`RSASSA-PSS`,
   SHA-256; the runtime floor is 2048 and `--trust-anchor-info` warns below
   3072).

   ```bash
   # Reference (software) form. In production this is an HSM key-gen ceremony;
   # the private key must never exist as an exportable file on a build machine.
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
       -out ssp-authority-private.pem            # NEVER leaves the ceremony host / HSM
   openssl rsa -in ssp-authority-private.pem -pubout -out ssp-authority-public.pem
   openssl pkey -pubin -in ssp-authority-public.pem -outform DER \
       | openssl dgst -sha256                    # -> record this fingerprint in the minutes
   ```

2. **Escrow the private key** (HSM backup / split custody), and record in the
   minutes: date, participants, key size, algorithm, SPKI SHA-256, escrow
   location, rotation date.

3. **Publish the public key + fingerprint** to the release pipeline as a
   protected artifact (the *public* half may be widely distributed; the
   fingerprint is what makes substitution detectable).

4. **Never** commit either half, and never add the private key to CI secrets:
   nothing in the SSP build reads a private key.

---

## 3. Release build

```powershell
dotnet publish src\SSP.Server\SSP.Server.csproj -c Release `
    -p:PublishSingleFile=true `
    -p:SspRequireTrustAnchor=true `
    -p:SspAuthorityPublicKeyPemFile=D:\ceremony\ssp-authority-public.pem `
    -p:SspAuthorityPublicKeySha256=<fingerprint from the minutes>
```

The same properties are forwarded automatically to the nested
`SSP.ServiceHost` single-file publish (that image embeds its own copy of
`SSP.Server.dll` and is what an installed service actually runs), so the server
executable and the service host image always carry the *same* anchor.

## 4. Mandatory verification before signing / shipping

```powershell
SSP.Server.exe --trust-anchor-info      # exit code 0 only if the anchor is present and usable
```

Check that the printed `SPKI SHA-256` equals the fingerprint in the ceremony
minutes and that `Pinned fingerprint` is not `(none recorded)`. Then
Authenticode-sign the binaries. A quick negative check on the shipped package
(`no private key left anywhere`) is part of the release checklist:

```powershell
Select-String -Path <package>\* -Pattern "PRIVATE KEY" -SimpleMatch   # must find nothing
```

## 5. Rotation

The library ships **one** anchor. To rotate: build a release carrying the new
public key, re-issue every live license with the new private key **before** the
old-anchor build is retired (sequence numbers stay monotonic so anti-rollback is
unaffected), then withdraw the old build. Multi-anchor support is an explicit
future library change and is deliberately not improvised at ceremony time.

## 6. Test / development keys

Tests generate **ephemeral in-memory** authority keys (`LicensedTestEnvironment`,
`SspActivationService.Compose(...)`) and never write key material to disk or to
the repository. They are structurally isolated from the production trust
configuration, and that isolation is asserted by
`tests/SSP.Tests/Activation/SspTrustAnchorProvisioningTests.cs`:

* a test anchor is never the compiled-in anchor;
* a default build embeds no authority key resource at all;
* no environment variable and no file dropped into the licensing directory can
  supply an anchor;
* with a perfectly valid test-signed license on disk, the *production*
  composition path still refuses to compose in an unanchored build.
