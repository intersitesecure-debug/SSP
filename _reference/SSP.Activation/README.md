# SSP.Activation

Standalone licensing subsystem for **SSP (Secure Session Protocol)**.

> **Prime invariant:** without a cryptographically valid license issued by the trusted SSP
> Licensing Authority, protected SSP functionality must not become operational.

- .NET 8 / C# 12, **zero external NuGet dependencies** (BCL cryptography + JSON only)
- Ed25519-free, RSA-PSS-SHA256 signatures (FIPS-friendly, universally available)
- Deterministic canonical JSON signing, strict fail-closed artifact parsing
- Headless enforcement + non-destructive lockdown, ready for future SSP.Core integration

## Solution layout

```text
SSP.Activation.sln
├── src/SSP.Activation/            # the licensing library (public API below)
│   ├── Models/                   #   LicensePayload, LicenseState, results, events…
│   ├── Abstractions/             #   IClock, ILicenseProvider, ILicensePolicy…
│   ├── Crypto/                   #   LicenseTrustAnchor, SignatureAlgorithms
│   ├── Canonicalization/         #   LicenseCanonicalJson
│   ├── Serialization/            #   LicenseArtifactCodec (strict artifact envelope)
│   ├── Validation/               #   LicenseValidator (the pipeline)
│   ├── Enforcement/              #   DefaultLicensePolicy, LicenseEnforcement
│   ├── Providers/ Identity/ Events/ Persistence/
│   ├── LicenseManager.cs         #   runtime composition root
│   └── LicenseIssuer.cs          #   AUTHORITY-SIDE issuing API (bring-your-own key)
├── tests/SSP.Activation.Tests/    # automated unit / integration / security tests incl. 9 named invariants
└── docs/ARCHITECTURE.md          # full design & security documentation
```

## Build & test

```bash
dotnet restore
dotnet build
dotnet test
```

Requires the .NET 8 SDK. No network access is needed at runtime; the library never phones
home (there is no networking code at all).

## Quick start (future SSP.Core integration)

```csharp
using SSP.Activation;

// 1. Trust anchor: ONLY the authority's public key (never a private key).
using var trustAnchor = LicenseTrustAnchor.FromPem(File.ReadAllText("ssp-authority.pub.pem"));

// 2. Composition root: everything the runtime needs, wired once.
var manager = new LicenseManager(
    new LicenseValidationOptions(expectedProductId: sspProductId),
    trustAnchor,
    identityProvider: new StaticInstallationIdentityProvider(installationId), // replace with SSP's protected provider
    licenseProvider: new LocalLicenseFileProvider("ssp.license.json"),
    eventSink: new InMemorySecurityEventSink(),                               // replace with real log sink
    stateStore: new FileLicenseStateStore(Path.Combine(appDataDir, "ssp-license-state.json"))); // durable anti-rollback floor

var result = manager.Load();
Console.WriteLine($"{result.State}: {result.ReasonCode}");

// 3. Enforcement boundary used by SSP.Core.
ILicenseEnforcement enforcement = new LicenseEnforcement(manager);

if (enforcement.CanUseFeature("rdp").IsAllowed) { /* start protected feature */ }
if (enforcement.CanCreateSession(activeSessions).IsAllowed) { /* open session */ }

// 4. Periodically (and after any policy-relevant event):
manager.Revalidate();
```

Issuing licenses (authority side only — the private key never leaves the authority):

```csharp
string artifactJson = LicenseIssuer.EncodeLicenseArtifact(payload, authorityRsaPrivateKey);
```

## Public API summary

| Type | Purpose |
|---|---|
| `ILicenseManager` / `LicenseManager` | Load / revalidate / authorize; runtime state `Unknown · Valid · LockedDown` |
| `ILicenseEnforcement` / `LicenseEnforcement` | `CanUseFeature`, `CanCreateSession`, `CanEstablishTunnel`, `CanStartProtectedService`, `CheckLimit` |
| `ILicensePolicy` / `DefaultLicensePolicy` | Fail-closed decision point (replaceable) |
| `LicenseValidator` | Standalone pipeline (activation tooling, tests) |
| `LicenseTrustAnchor` | Authority public key (PEM / SPKI DER) |
| `LicenseIssuer` | Authority-side artifact signing |
| `LicenseValidationResult`, `LicenseState`, `LicenseReasons` | Structured, secret-free outcomes |
| `ProtectedOperation`, `AuthorizationDecision` | Authorization requests & verdicts |
| `IClock`, `IInstallationIdentityProvider`, `ILicenseProvider`, `ILicenseStateStore`, `ISecurityEventSink`, `ILicenseRevocationChecker` | Injectable boundaries |

See **docs/ARCHITECTURE.md** for the trust model, canonicalization rules, validation
pipeline, lockdown semantics, anti-rollback and revocation strategy, security assumptions
and known limitations.
