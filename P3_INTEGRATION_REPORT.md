# P3 — SSP.Activation Integration & Runtime Licensing: Hardening Report

Branch: `arena/01a06301-ssp` (from `main` @ `7a73efb`)
Scope: P3 only. **No P4 work was started** (no `tools/SSP.LicenseAuthority`, no online
activation, no key rotation, no TPM, no unrelated refactoring).

---

## 0. Honest status up front

| Item | Status |
|---|---|
| Audit (§1, §2) | **COMPLETE** |
| Architecture fix + enforcement points (§3–§9) | **COMPLETE** (code written, wired into every production entry point) |
| Storage / trust / identity / event audits (§10–§14) | **COMPLETE** (one release blocker documented in §11, by instruction not "fixed") |
| New integration + fail-closed tests (§15–§17) | **COMPLETE** (59 new test cases in 4 files) |
| Vendored reference test suite wired into the solution | **COMPLETE** (135 declarations / 21 files) |
| Existing SSP tests preserved (§18) | **COMPLETE** (no assertion changed anywhere) |
| **Build + test execution (§19)** | **NOT RUN — BLOCKED.** See §19. No `PASS`/`FAIL` numbers are reported because none were observed. |
| Architecture map (§20) | **COMPLETE** |

> **This report does not claim a passing build.** The sandbox this work was done in has
> no .NET SDK and no network route to obtain one (§19.1). Every statement below about
> behaviour is derived from reading the code, not from executing it. Items that can only
> be confirmed by a compiler or a test run are marked **[UNVERIFIED — needs build]**.

---

## 1. Audit findings (what was actually wrong)

### 1.1 Dependency graph as found

```
SSP.Activation (vendored, 25 files)
   LicenseManager ── LicenseValidator ── LicenseTrustAnchor / IClock /
   │                                     IInstallationIdentityProvider /
   │                                     ILicenseStateStore / ILicenseProvider /
   │                                     ILicenseRevocationChecker / ISecurityEventSink
   ├── LicenseEnforcement (ILicenseEnforcement)  ← all decisions funnel here
   ├── DefaultLicensePolicy (ILicensePolicy)
   └── models: License, LicensePayload, LicenseFeatureSet, LicenseLimits,
               AuthorizationDecision, LicenseState, LicenseReasons,
               ProtectedOperation, LicenseLimitNames

SSP.Server adapters (src/SSP.Server/Activation/)
   SspActivationService  (composition root + the one revalidation loop)
   SspTrustAnchor, SspInstallationIdentityProvider, SspLicensePaths,
   SspLicenseStateStore, SspSecurityEventSink

SSP.Core
   SspLicensing (ProductId, ProductName, Features, Limits,
                 InstallationBindingPurposeTag)
```

### 1.2 Defects found

| # | Defect | Where |
|---|---|---|
| D1 | `ServerGateway(..., ILicenseEnforcement? enforcement = null)` — **optional, nullable enforcement**. Every production call site passed nothing, so the gate was `null` and every `if (_enforcement is not null)` branch was skipped: a fully fail-open runtime. | `src/SSP.Server/Runtime/ServerGateway.cs` |
| D2 | `CanStartProtectedService(1)` was called **per inbound TCP connection**, and `CanStartProtectedService(0)` in the constructor. Neither is the semantics of the operation (`max_services` counts service *instances*, and the usage argument is the count *before* the grant). Constructor denial only printed a message and kept serving. | `ServerGateway` ctor + `HandleClientAsync` |
| D3 | **No enforcement at the service-start boundary at all** — `Program.RunServiceModeAsync` and `SspWindowsService.OnStart` built a gateway with no licensing runtime, so an unlicensed service bound its port and served traffic. | `Program.cs`, `SspWindowsService.cs` |
| D4 | **No enforcement at enrollment** (`max_clients`) and **no enforcement at tunnel admission** (`max_concurrent_tunnels` / `max_concurrent_sessions`). | `ServerProtocol` |
| D5 | **An alternate path to a live tunnel**: `ClientProtocol.ConnectAndAuthenticateAsync(establishSessionKey: true)` negotiates a session key on the *enrollment* socket, and `ServerGateway` bridges whatever key comes back. Any gate placed only in the future-authorization handler would have been bypassed by every first-run enrollment. | `ServerProtocol.ReceiveSessionKeyAsync` |
| D6 | **No revalidation timer** — nothing re-checked the license after start, so expiry / revocation / renewal were invisible until a process restart. | `SspActivationService` |
| D7 | Feature names existed only as prose. No `LicenseFeatures`-style mapping, so any feature gate would have been a scattered string literal. | `SspLicensing` |
| D8 | The vendored reference test suite (135 declarations) was **not in the solution**, so the licensing subsystem itself was untested in this repo. | `SSP.sln` |

---

## 2. One licensing authority (§2)

There is exactly **one** authoritative decision path and exactly **one** authoritative state:

```
ISspLicenseGate.AdmitTunnel()/CanEnrollClient()/CanStartProtectedService()/CanUseFeature()
      └─> SspRuntimeLicense          (SSP-side boundary; owns usage counters only)
            └─> LicenseEnforcement   (vendored; no policy of its own)
                  └─> LicenseManager.Authorize(ProtectedOperation)   ← ONE state, ONE lock
                        └─> DefaultLicensePolicy.Evaluate(LicenseEvaluationContext)
```

Verified by reading every call site:

* No second `IsLicensed` / `licenseValid` / `hasLicense` cache exists anywhere in `src/`.
  This is now enforced by a reflection test
  (`LicensingCompositionTests.NoRuntimeComponent_CachesALicensingVerdict`) over
  `ServerGateway`, `ServerProtocol`, `SspRuntimeLicense`, `SspWindowsService`.
* `SspActivationService` is composed **once per process** by
  `SspRuntimeLicense.CreateForService` (service mode / SCM) or
  `TryCreateForProvisioning` (setup mode / ServiceBuilder). Nothing else calls
  `SspActivationService.Create`/`Compose` in `src/`.
* `LicenseManager` holds the state; every read goes through `Manager.Authorize` under
  `Manager`'s own lock, so a `Valid → LockedDown` transition cannot be observed as an
  authorization by a racing call.
* `SspRuntimeLicense` caches exactly two things, neither of which is a verdict: the
  **feature identity** of the application (immutable) and the **usage counters**.

---

## 3. `ILicenseEnforcement?` removed — production is fail-closed by construction (§3)

The nullable dependency is gone. In its place:

**`src/SSP.Server/Activation/ISspLicenseGate.cs`** (new) — the single SSP-side boundary:

```csharp
public interface ISspLicenseGate
{
    string? Feature { get; }              // immutable feature identity (or null)
    LicenseState CurrentState { get; }    // diagnostics only — never a decision input
    long ActiveTunnels { get; }           // host-supplied usage
    long ActiveSessions { get; }
    SspTunnelAdmission AdmitTunnel();     // EP1+EP2+EP3, atomic check-and-reserve
    AuthorizationDecision CanStartProtectedService(long currentRunningServices);
    AuthorizationDecision CanEnrollClient(long currentAuthorisedClients);
    AuthorizationDecision CanUseServiceFeature();
    AuthorizationDecision CanUseFeature(string feature);
}
```

**`src/SSP.Server/Activation/SspRuntimeLicense.cs`** (new) — the only production
implementation:

* `CreateForService(config, serviceDir, paths?, clock?, startRevalidationTimer = true)`
  throws `SspActivationException` when (a) no trust anchor is compiled in,
  (b) composition fails, (c) the license is not `Valid`, (d) the protocol is not in the
  licensed feature set, or (e) `max_services` is exhausted. It never returns an
  unlicensed gate.
* `TryCreateForProvisioning(applicationName)` returns `null` — with one loud
  `Console.Error` diagnostic — when no anchor is compiled in. This is **not** a fail-open
  path: provisioning only creates directories/keys/OTTs; EP1/EP2/EP3 remain unconditional,
  so nothing provisioned there can ever become operational.
* `AdmitTunnel()` performs feature + tunnel-limit + session-limit checks **and** the slot
  reservation inside one `lock (_admissionGate)`, so two connections racing for the last
  licensed slot cannot both be admitted. Lock ordering is
  `_admissionGate → LicenseManager._gate`; the manager never calls back, so it cannot invert.
* A disposed runtime **denies without throwing** (`LicenseReasons.LicenseNotValid`), so an
  in-flight connection during shutdown is refused rather than crashing its handler.

**Consumers take a mandatory, non-nullable gate** — `enforcement: null` is no longer
representable:

```csharp
public ServerGateway(ServiceConfig, RSA, string, string, ISspLicenseGate license)   // no default
public ServerProtocol(ServiceConfig, RSA, string, string, ISspLicenseGate license)  // no default
```

Both throw `ArgumentNullException(nameof(license))` with an explanatory message.

**Test seams kept, made explicit** (§3 "keep test seams"):

* `tests/SSP.Tests/Helpers/UnlicensedTestGate.cs` — allow-all, lives in the **test
  assembly**, unreachable from any shipped binary, and records every call
  (`Calls`, `AdmittedTunnels`) so a test can assert the runtime really consulted it.
* `tests/SSP.Tests/Helpers/LicensedTestEnvironment.cs` — a **real** licensing runtime
  (ephemeral authority key, genuinely signed artifact on disk, production
  `SspLicensePaths`/`SspLicenseStateStore`/`LocalLicenseFileProvider`, controllable
  `IClock`) for the integration tests.
* `SspTestHarness.CreateAsync/CreateWithExplicitTokenAsync/CreateFromExistingConfigAsync`
  take an optional `ISspLicenseGate?` and default to the seam; the resolved gate is exposed
  as `harness.License`.

Guarded by tests: `ServerGateway_RefusesToRunWithoutALicenseGate`,
`ServerProtocol_RefusesToRunWithoutALicenseGate`,
`ProtectedRuntimeComponents_HaveNoConstructorWithoutAMandatoryGate` (reflection: every
ctor has exactly one non-nullable, non-optional `ISspLicenseGate` parameter).

---

## 4–9. Enforcement points

| EP | Operation | Limit / check | Exact code location | Usage supplied by |
|---|---|---|---|---|
| **EP0a** | create a protected service (SETUP MODE, batch, ServiceBuilder) | feature + `max_services` | `SetupEngine.AuthorizeNewProtectedService`, called from `RunNewApplicationAsync` before anything is created | `SspProtectedServiceInventory.CountProtectedServices()` |
| **EP0b** | provision an additional client | `max_clients` | `SetupEngine.AuthorizeAdditionalClientAsync`, called from `RunAdditionalClientAsync` **before the OTT is minted** | `AuthorisedUsersStore.LoadAsync(.index.dat).Users.Count` |
| **EP1** | **service instance start** | Valid + feature + `max_services` | `SspRuntimeLicense.AuthorizeServiceStart` (internal), called by `CreateForService`, invoked from `Program.RunServiceModeAsync` (`--run-once`) and `SspWindowsService.OnStart` — **before** key import, before the gateway exists, before any socket is bound | `CountProtectedServices(excludeServiceDir: serviceDir)` (a service never counts itself) |
| **EP1′** | per-connection feature re-check | feature | inside `AdmitTunnel()` (so a lockdown or a re-issued license takes effect without a restart) | — |
| **EP2** | client enrollment | `max_clients` | `ServerProtocol.HandleEnrollmentLockedAsync`, after OTT + nonce-signature verification, **before** the Authentication Code is generated, before any disk write and before the OTT is consumed | `users.Users.Count` (minus one for a re-enrollment of the same fingerprint), read inside the per-service enrollment semaphore **and** the cross-process `ServiceConfigFileLock` |
| **EP3** | tunnel/session admission | feature + `max_concurrent_tunnels` + `max_concurrent_sessions` | **(a)** `ServerProtocol.HandleFutureAuthorizationAsync` — after the client is cryptographically authenticated, before `AuthorizationOutcome(true)`; **(b)** `ServerProtocol.ReceiveSessionKeyAsync` — the **single choke point**, before the RSA-OAEP unwrap | `SspRuntimeLicense` counters |
| **EP-T** | periodic revalidation | — | `SspActivationService.StartRevalidationTimer` → one `PeriodicTimer` loop → `RefreshLicense()` = `Manager.Load()` | — |

### §4 — why EP1 is at the startup boundary, not per connection

`CanStartProtectedService` authorizes *one more protected service instance becoming
operational*. An accepted TCP connection is not that. D2's per-connection
`CanStartProtectedService(1)` both mis-stated the operation and mis-counted the limit
(usage must be the count **before** the grant). EP1 now runs once, in the composition root,
before the listening socket exists — an unlicensed service never binds its port at all.

### §6 — atomic check + increment, host supplies usage

The vendored policy deliberately takes usage as an argument and never duplicates policy
logic in SSP. `SspRuntimeLicense` is the single place that owns SSP's counters and performs
check-and-reserve atomically. `SspTunnelAdmission` transfers ownership:
`ServerProtocol.TakeTunnelAdmission()` → `ServerGateway.HandleClientAsync`'s `finally`
releases it exactly once, whether the tunnel completed, the client dropped, or anything
threw in between. `ServerProtocol.Dispose()` covers the handshake-failed-after-grant case.
Both disposals are idempotent.

Admission happens **after** identity verification on purpose: reserving a licensed slot for
an unauthenticated peer would let an anonymous caller exhaust
`max_concurrent_tunnels` and deny service to licensed clients.

### §7 — no alternate path to a tunnel

Every path that can produce a session key (which is what makes `ServerGateway` bridge
traffic) goes through `ReceiveSessionKeyAsync`:

* future authorization → already holds an admission (taken in
  `HandleFutureAuthorizationAsync`), so the choke point does not take a second one;
* **enrollment with `establishSessionKey: true`** → holds none, so the choke point admits
  here. On denial the offer is refused with the protocol's own
  `SessionKeyAck { Accepted = false }` (which the client already handles as a rejection),
  **before** `RsaCrypto.DecryptOaep` runs, so a denied connection cannot even cause
  session-key material to be processed.

Searched for other tunnel-creation paths: `TunnelRelay.BridgeAsync` is called from exactly
one place (`ServerGateway.HandleClientAsync`) and only when `sessionKey is { Length: > 0 }`.
There is no `CreateTunnel`/`Bridge`/`Relay` entry point that bypasses the handshake.
Test: `EnrollmentSocket_CannotOpenADataPlane_WhenTheFeatureIsNotLicensed`.

### §8 — one revalidation timer

* Composition (`Create`/`Compose`) starts **no** background work — asserted by
  `Composition_NeverStartsBackgroundWork`.
* `StartRevalidationTimer(interval?)` is explicit, idempotent under
  `_revalidationTimerGate`, rejects non-positive intervals, and throws
  `ObjectDisposedException` after shutdown.
* The loop awaits the tick, then calls the synchronous `RefreshLicense()`, then awaits the
  next tick — no overlap. The body catches everything, so a transient provider/I-O failure
  neither faults the owned task nor stops later refreshes (test:
  `RevalidationTimer_SurvivesAProviderFailure_WithoutFailingOpen`).
* Each tick calls `Load()` **not** `Revalidate()`: `Revalidate()` re-checks only the
  artifact held in memory, so it can detect expiry but can never notice a renewal — and
  clearing a lockdown requires *loading* a valid artifact.
* `Dispose()` clears the owned references under the gate, cancels, disposes the
  `PeriodicTimer`, **joins the loop outside the gate** (so an in-flight RSA/file refresh is
  never serialized against unrelated `IsRevalidationTimerRunning` readers), observes every
  task failure, then disposes the trust anchor.
* No stale `Valid` cache exists to go stale (§2).
* Started only after the runtime is proven licensed (`CreateForService`), owned by whoever
  owns the service lifetime, and disposed by `SspWindowsService.OnStop` **after** the accept
  loop has stopped and the RSA key is gone.

### §9 — lockdown propagation

`Valid → LockedDown` is produced by `LicenseManager.Apply` for any invalid result with a
non-null artifact. Because no component caches a verdict, the **next** protected operation
denies. Asserted at three levels:

* gate level: `Lockdown_PropagatesImmediatelyToEveryRuntimeGate` (every decision method,
  not just tunnels);
* timer level: `RevalidationTimer_DetectsExpiry_AtRuntime_AndPropagatesTheLockdown`
  (nobody calls `Reload()`; only the owned background loop does);
* live runtime: `LockdownAfterStartup_DeniesSubsequentTunnels_WithoutARestart` — the same
  gateway process that just served a tunnel refuses the next connection.

Recovery: `LockedDown → Valid` only by loading a cryptographically valid artifact
(`Recovery_LockedDownThenValidNewerLicense_AllowsProtectedOperationsAgain`,
`RecoveryTimer…DetectsAnInstalledRenewal_AndClearsTheLockdown`,
`RecoveryAfterLockdown_AllowsTunnelsAgain_WithoutARestart`). Deleting the license never
recovers a lockdown (`DeletingTheLicense_NeverRecoversALockdown`). Lockdown is
non-destructive: no license material is deleted, and `LicenseLockdownCleared` is emitted on
recovery.

Per-service isolation of the state machine: `AnExpiredArtifact_IsSeenByEveryServiceProcessOnTheHost_AfterItsOwnRefresh`.

---

## 10–14. Audits

### §10 License file / state store

* `SspLicensePaths.Resolve(licenseRootOverride?)` is the **only** place licensing paths are
  invented: `{canonical product root}/licensing/{license.json, .license-state.dat,
  ssp-activation-security.log}`, redirected only by its own dedicated `SSP_LICENSE_ROOT`
  seam (never by `SSP_CLIENT_ROOT`). Paths are canonicalized so every spelling of one
  directory yields one value.
* The artifact is **deliberately plaintext signed JSON** (transport is never a security
  boundary); writes go through `AtomicFile` (temp + move), so a reader never sees a partial
  artifact — asserted by
  `LicenseFileWritesAreAtomic_NoPartialArtifactIsEverLeftReadable`.
* `.license-state.dat` is on `ProtectedFileStore.ProtectedFileNames`, so the anti-rollback
  floor is written in the SSP encrypted-at-rest envelope (DPAPI LocalMachine on Windows,
  AES-GCM fallback elsewhere) — asserted by
  `LicenseArtifact_IsPublicSignedMaterial_AndTheStateStoreHoldsNoSecrets`.
* Store reads **fail closed** (`state_store_unavailable` → not Valid) and the store can only
  ever *restrict* authorization (anti-rollback floor), never grant it.
* No secrets are stored: the state record holds only
  `HighestAcceptedSequenceNumber`, `LastAcceptedLicenseId`, `LastValidatedUtc`.
* The private authority key never exists in this repo; the ephemeral test authority in
  `LicensedTestEnvironment` is in-memory only and disposed with the environment.

### §11 Trust anchor — **RELEASE BLOCKER (deliberately unresolved)**

```csharp
// src/SSP.Server/Activation/SspTrustAnchor.cs
public const string AuthorityPublicKeyPem = "";          // empty placeholder
public static bool IsCompiledIn => !string.IsNullOrWhiteSpace(AuthorityPublicKeyPem);
```

Per instruction, **no key was invented** and **no substitution path exists**: the anchor is
a compiled-in constant; there is no environment variable, config file, license file or
command-line option that can supply it (`SspLicensePaths.EnvironmentRootOverrideVariable`
redirects the *directory* only, never the key).

Consequences, all fail-closed:

* `SspTrustAnchor.Create()` throws `InvalidOperationException`.
* `SspRuntimeLicense.CreateForService(...)` throws
  `SspActivationException(trust_anchor_missing)` → **no protected service can start in this
  build**.
* `TryCreateForProvisioning(...)` returns `null` with a loud diagnostic; provisioning can
  lay out directories that will never run.
* `SSP.Server --license-status` prints `UNLICENSED BUILD: no Licensing Authority trust
  anchor is compiled into this binary` and exits non-zero.

> **BLOCKER:** before any build that is meant to protect anything, set
> `SspTrustAnchor.AuthorityPublicKeyPem` at the release key ceremony and rebuild.
> Test: `ProductionServiceStart_FailsClosed_WhenNoTrustAnchorIsCompiledIn`.

### §12 Installation identity

`SspInstallationIdentityProvider` reads the Windows `MachineGuid` and returns
`SHA256(MachineGuid + SspLicensing.InstallationBindingPurposeTag)` as lowercase hex:

* **stable** — cached after first read, survives reboots;
* **hashed** — the raw MachineGuid never appears in an artifact or event;
* **purpose-bound** — domain-separated by `SSP-LICENSE-INSTALL-v1`, so the same MachineGuid
  used for another purpose yields a different identifier;
* **never throws** — registry failure or non-Windows ⇒ `null`, which makes an
  installation-bound license fail closed (`installation_identity_unavailable`) while
  floating licenses still validate.

New test: `InstallationIdentity_IsPurposeBound_AndNeverExposesTheRawSource` (complements the
pre-existing `SspInstallationIdentityProviderTests`).

### §13 Connection identity isolation

`ServerA/RDP ≠ ServerA/WEB` is preserved under licensing:

* one gate, one feature identity, one pair of usage counters **per service process**;
* the license artifact, trust anchor, installation identity and anti-rollback floor are
  shared (one machine, one authority) — that is intended;
* the **state machine is per process**: a second service does not inherit another's
  transition, it observes it through the artifact on its own refresh;
* enrollment serialization is per service directory
  (`ServerProtocol.EnrollmentLocks`, keyed by `Path.GetFullPath(_serviceDir)`), so
  `max_clients` check-and-commit cannot race within a service and services cannot block
  each other.

Tests: `TwoServiceProcessesOnOneHost_ShareTheArtifact_ButNotTheUsageCounters`,
`FeatureIdentityIsPerConnection_NotPerMachine`,
`TwoServicesInOneProcess_HaveIndependentLicensingAndCounters`,
`LockingDownOneService_DoesNotAffectAnotherServiceInSameProcess`,
`EnrollmentLockIsScopedPerServiceDirectory_AndALicensingDenialReleasesIt`.

### §14 Security events are secret-free

`LicenseSecurityEvent` carries only `EventType`, `OccurredAtUtc`, `State`, `LicenseId`,
`ReasonCode`, `Detail`. Reason codes are the stable `LicenseReasons` vocabulary. Details are
diagnostic strings (a state-store failure reports the exception **type name**, not its
message). `SspRuntimeLicense.DescribeLicenseSummary()` prints licenseId/edition/expiry/
sequence only.

Tests: `Denials_AreReportedAsSecurityEvents_WithoutSecrets`,
`SecurityEvents_NeverContainKeyMaterialOrArtifactContent` (asserts no raw identity source,
no `BEGIN`/`PRIVATE KEY`/`PUBLIC KEY`, no OTT wording, no artifact JSON).

### §5 Feature mapping — single mechanism, no scattered literals

`SspLicensing.Features` is the only place SSP names a license feature:

| Constant | Value | Application aliases accepted |
|---|---|---|
| `Features.RemoteDesktopProtocol` | `rdp` | rdp, remote desktop, remotedesktop, remote desktop protocol, mstsc |
| `Features.SecureShell` | `ssh` | ssh, secure shell, openssh |
| `Features.Web` | `web` | web, http, https, rdweb |
| `Features.Sql` | `sql` | sql, mssql, sqlserver, sql server, ms sql, tds |

`Features.Known` is the closed set; `ResolveForApplication`/`TryResolveForApplication` are
the only mapping entry points (trim + invariant lower-case). No feature name was invented:
values match the vendored library's normalized vocabulary and the aliases are only
spellings SSP itself already uses. `SspLicensing.Limits` mirrors `LicenseLimitNames` so
SSP.Core needs no reference to the activation assembly.

An application name outside the vocabulary resolves to `null` ⇒ **no feature gate**, but the
Valid-state gate and every limit gate still apply unconditionally. That is the only
permissive direction, and an unlicensed installation is denied whatever the application is
called.

`max_sessions` is documented as **reserved, not enforced**: it is a cumulative total that
SSP cannot measure offline across restarts without persisting a per-license counter, and
enforcing it against a per-process total would silently change its meaning.

---

## 15–18. Tests

### §15/§16/§17 — new tests (all in `tests/SSP.Tests/Activation/Runtime/`)

| File | Declarations | Cases | Covers |
|---|---|---|---|
| `LicensingFailClosedMatrixTests.cs` | 18 `[Fact]` | 18 | §16 negative matrix: missing, tampered, foreign authority, malformed, expired, not-yet-valid, revoked, wrong product, wrong installation, identity unavailable, superseded (anti-rollback), state-store failure, throwing policy, deletion; plus the valid-license positive, lockdown propagation, recovery, and secret-free denial events |
| `TunnelLicensingIntegrationTests.cs` | 15 `[Fact]` | 15 | §15 mandatory integration set over a **real** gateway + **real** client handshake: valid RDP, valid SSH, wrong feature, enrollment-socket data plane, missing/tampered/expired license, `max_concurrent_tunnels` N→N+1→release, `max_concurrent_sessions`, `max_clients`, lockdown without restart, recovery without restart, two-service isolation, lockdown isolation, and the explicit test seam being consulted |
| `LicensingCompositionTests.cs` | 16 `[Fact]` + 2 `[Theory]` (6 cases) | 22 | §17 dedicated no-enforcement production path, §3 non-representability, §9 no cached verdict, §8 timer lifecycle, §10 artifact/state-store storage, §12 purpose binding, §14 event hygiene |
| `ConnectionIsolationLicensingTests.cs` | 4 `[Fact]` | 4 | §13 shared artifact vs. per-service counters, per-connection feature identity, per-process state machine, per-service enrollment lock (including "a licensing denial must not leak the semaphore") |
| **Total new** | **55** | **59** | |

Every fail-closed test asserts **all** gate decisions through one helper
(`AssertEveryProtectedOperationDenied`): tunnel admission, service start, client enrollment,
all four features, the service feature, both limits at `long.MaxValue`, and that no slot was
consumed. A license failure that denied tunnels but still allowed enrollment would fail
these tests.

§17's dedicated production-path test:
`ProductionServiceStart_FailsClosed_WhenNoTrustAnchorIsCompiledIn` — asserts
`SspTrustAnchor.IsCompiledIn == false`, that `CreateForService` throws
`SspActivationException` with reason `trust_anchor_missing`, and that `SspTrustAnchor.Create()`
itself refuses. Companion: `ProvisioningWithoutATrustAnchor_ReturnsNull_Loudly_AndNeverAGate`,
`ServiceStartAuthorization_RefusesWithoutAValidLicense`,
`ServiceStartAuthorization_RefusesAnUnlicensedFeature_AndAnExhaustedServiceLimit`.

### Vendored reference suite (§2, §16 coverage of the library itself)

`tests/SSP.Activation.Tests/` — 21 files copied **verbatim** from
`_reference/SSP.Activation/tests/SSP.Activation.Tests/` (`diff -rq` reports no differences),
135 `[Fact]`/`[Theory]` declarations + 50 `[InlineData]`/`[MemberData]` cases. Added to
`SSP.sln` under the existing `tests` solution folder (GUID
`{A7C3E9F1-4B2D-4E8A-9C6F-2D5A8B1E4F70}`, Debug/Release × ActiveCfg/Build.0). Its relative
project reference (`..\..\src\SSP.Activation\SSP.Activation.csproj`) resolves identically
from the new location. The vendored `src/SSP.Activation` sources are byte-identical to the
reference (only `SSP.Activation.csproj` differs, by the pre-existing documented
`DebugType=embedded` integration fix), and the library exposes no `InternalsVisibleTo`, so
the reference tests compile against the vendored project using public API only.

### §18 — existing SSP tests preserved

* `tests/SSP.Tests`: 236 pre-existing `[Fact]`/`[Theory]` declarations, **no assertion
  changed**.
* The only edits to pre-existing test code are dependency declarations, exactly as
  instructed ("make test dependencies explicit instead"):
  * `Helpers/SspTestHarness.cs` — optional `ISspLicenseGate?` parameter on the three factory
    methods, new `License` property, and the two `new ServerGateway(...)` call sites now
    pass the resolved gate (default `UnlicensedTestGate.Instance`).
  * `ServiceStartRegressionTests.cs` — two `new ServerGateway(config, rsa, pubPem, "/tmp")`
    call sites gained the explicit `UnlicensedTestGate.Instance` argument + one `using`.
    No assertion touched.
* AES-GCM crypto, 10 MB transfer, fragmented frames, restart, OTT, multi-server /
  multi-service / multi-client, and connection-isolation suites are otherwise untouched
  (`git diff --stat tests/` shows only those two files modified; everything else under
  `tests/` is new).

---

## 19. Build and test — **NOT RUN (BLOCKED)**

### 19.1 Why

This sandbox has no .NET SDK and no way to get one:

* `command -v dotnet` → not found; no `/usr/share/dotnet`, no `~/.dotnet`, no
  `~/.nuget/packages` cache.
* No package-manager privileges to install one.
* `api.nuget.org`, `dotnet.microsoft.com`, `builds.dotnet.microsoft.com`,
  `dotnetcli.azureedge.net`, `deb.debian.org` are unreachable; `raw.githubusercontent.com`
  fails TLS.

`dotnet restore`, `dotnet build` and `dotnet test` therefore could not be executed, and no
PASS/FAIL result was observed. **No test outcome is claimed.** Reporting fabricated results
would violate the task's own final rule.

### 19.2 Exact commands to run

```powershell
cd C:\SSP
dotnet restore SSP.sln
dotnet build   SSP.sln -c Debug --no-restore
dotnet test    SSP.sln -c Debug --no-build --logger "console;verbosity=detailed"
```

Expected projects: `SSP.Core`, `SSP.Client`, `SSP.Server`, `SSP.ServiceBuilder`,
`SSP.ServiceHost`, `SSP.Activation`, `tests/SSP.Tests`, `tests/SSP.Activation.Tests`.

### 19.3 What is **[UNVERIFIED — needs build]**

Because no compiler ran, the following are reasoned-about but unproven. They are the first
things to check if the build complains:

1. **New test files** (`tests/SSP.Tests/Activation/Runtime/*.cs`,
   `tests/SSP.Tests/Helpers/{LicensedTestEnvironment,UnlicensedTestGate}.cs`) — every symbol
   they use was checked by reading its declaration (`LicenseReasons`, `LicenseState`,
   `LicenseStatus`, `LicenseLimitNames`, `AuthorizationDecision`, `LicenseValidationResult`,
   `LicenseSecurityEvent(+Type)`, `LicenseStateRecord`, `ILicenseProvider.FetchLicense`,
   `ILicensePolicy.Evaluate`, `ILicenseStateStore`, `LicenseIssuer.EncodeLicenseArtifact`,
   `LicenseTrustAnchor.FromPublicKey`, `LocalLicenseFileProvider`,
   `StaticInstallationIdentityProvider`, `InMemorySecurityEventSink`,
   `InMemoryLicenseStateStore`, `SspActivationService.Compose/Load/Reload/
   StartRevalidationTimer/IsRevalidationTimerRunning/DescribeStatus`,
   `SspRuntimeLicense.*`, `SspLicensePaths.Resolve`, `SspLicenseStateStore`,
   `SspTrustAnchor.*`, `SspInstallationIdentityProvider.ComputeInstallationId` (made
   `internal`; `SSP.Server` already has `InternalsVisibleTo("SSP.Tests")`),
   `SspProtectedServiceInventory.CountProtectedServices`, `ServerGateway.License/
   ActiveTunnels`, `ServerProtocol.TakeTunnelAdmission/Dispose`,
   `ServiceConfigStore`, `AuthorisedUsersStore`, `ProtectedFileStore.HasEncryptedEnvelope`,
   `TokenGenerator.*`, `ClientRuntime.*`, `ClientProtocol.*`, `EnrollmentHelper`).
2. **One production visibility change**: `SspRuntimeLicense.AuthorizeServiceStart` went from
   `private` to `internal` (with a default `serviceDir`) so the EP1 fail-closed contract can
   be asserted directly instead of being re-implemented in a test. Its only existing caller
   (`CreateForService`) is unaffected.
3. **One production code change made defensively**: `SspLicensing.Features.TryResolveForApplication`
   no longer uses `out feature!` (rewritten to a plain `TryGetValue` + assignment) because
   that form could not be compile-verified here.
4. `SSP.sln` edit (new project entry, configurations, nesting under the `tests` folder).
5. `--license-status` as a `System.CommandLine` command name. It follows the file's existing
   convention (`--setup`, `--setup-batch`, `--service`, `--run-once` are already declared the
   same way against `System.CommandLine 2.0.0-beta4.22272.1`), so it should parse — but it is
   new surface and is unexercised by any test.
6. Runtime timing assumptions in the integration tests (they poll with 25 ms ticks and 10–15 s
   deadlines, and the assembly sets
   `[assembly: CollectionBehavior(DisableTestParallelization = true)]`, so the
   `Console.SetOut` capture in `EnrollmentHelper` and the static `EnrollmentLocks` dictionary
   are not contended).

---

## 20. Final architecture map (actual class names)

```
COMPOSITION ROOTS (one gate per protected service process)
  SSP.Server.Program.RunServiceModeAsync          --run-once / foreground
  SSP.Server.ServiceHost.SspWindowsService.OnStart SCM path (ERROR 1064 on refusal,
                                                   ERROR 1053 contract untouched)
        │
        └─► SspRuntimeLicense.CreateForService(config, serviceDir)      [src/SSP.Server/Activation/SspRuntimeLicense.cs]
              ├─ SspTrustAnchor.IsCompiledIn / .Create()                [SspTrustAnchor.cs]  ← RELEASE BLOCKER
              ├─ SspActivationService.Create(paths, clock)              [SspActivationService.cs]
              │     └─ Compose(SspLicensePaths, LicenseTrustAnchor,
              │                SspInstallationIdentityProvider,
              │                SspSecurityEventSink,
              │                SspLicenseStateStore,
              │                LocalLicenseFileProvider,
              │                IClock, DefaultLicensePolicy)
              │           └─ LicenseManager ── LicenseValidator ── LicenseArtifactCodec
              │              LicenseEnforcement (ILicenseEnforcement)
              ├─ SspLicensing.Features.ResolveForApplication(appName)   [src/SSP.Core/Activation/SspLicensing.cs]
              ├─ AuthorizeServiceStart(config, serviceDir)              EP1  (internal)
              │     └─ SspProtectedServiceInventory.CountProtectedServices(excludeServiceDir)
              └─ SspActivationService.StartRevalidationTimer()          EP-T (30 min default)

PROVISIONING (short-lived; no timer)
  SSP.Server.Program.RunInteractiveSetupAsync / RunBatchSetupAsync
  SSP.ServiceBuilder.Program
        └─► SspRuntimeLicense.TryCreateForProvisioning(appName)   → null when no anchor
              └─► SetupEngine(ISspLicenseGate?)
                    ├─ AuthorizeNewProtectedService(appName)      EP0a (feature + max_services)
                    └─ AuthorizeAdditionalClientAsync(authPath)   EP0b (max_clients, pre-OTT)

RUNTIME (gate is a MANDATORY ctor dependency)
  ServerGateway(config, rsa, pubPem, serviceDir, ISspLicenseGate)       [src/SSP.Server/Runtime/ServerGateway.cs]
        │  License, ActiveTunnels (diagnostics; never a cached verdict)
        └─► per connection: ServerProtocol(config, rsa, pubPem, serviceDir, ISspLicenseGate)
              ├─ HandleEnrollmentAsync        → EnrollmentLocks[Path.GetFullPath(serviceDir)]
              │    └─ HandleEnrollmentLockedAsync
              │         ├─ ServiceConfigFileLock + .cache.dat reload (OTT)
              │         ├─ _license.CanEnrollClient(users.Users.Count)         EP2
              │         └─ ReceiveSessionKeyAsync(allowEof: true)  ─┐
              ├─ HandleFutureAuthorizationAsync                     │
              │    ├─ _license.AdmitTunnel()  →  _heldAdmission     EP3        │
              │    └─ ReceiveSessionKeyAsync(allowEof: false) ──────┤
              └─ ReceiveSessionKeyAsync  ◄── SINGLE CHOKE POINT ────┘
                   if (_heldAdmission is null) _heldAdmission = _license.AdmitTunnel()
                   denial → SessionKeyAck{Accepted=false}, return null (BEFORE RSA-OAEP unwrap)
              TakeTunnelAdmission() / Dispose()  → ownership transfer
        └─► HandleClientAsync: admission adopted, released exactly once in finally
              └─ TunnelRelay.BridgeAsync(localStream, TunnelCodec, remoteStream, ct)

DECISION PATH (one authority, one state)
  ISspLicenseGate  [src/SSP.Server/Activation/ISspLicenseGate.cs]
    ├─ SspRuntimeLicense        (production; the only implementation in src/)
    └─ UnlicensedTestGate       (test assembly only)  [tests/SSP.Tests/Helpers/UnlicensedTestGate.cs]
  → LicenseEnforcement → LicenseManager.Authorize(ProtectedOperation) → DefaultLicensePolicy.Evaluate

TEST RUNTIME
  LicensedTestEnvironment / TestClock / LicensedTestOptions   [tests/SSP.Tests/Helpers/LicensedTestEnvironment.cs]
    ephemeral authority + LicenseIssuer.EncodeLicenseArtifact + real adapters + real gate
  SspTestHarness(..., ISspLicenseGate?)                       [tests/SSP.Tests/Helpers/SspTestHarness.cs]

OPERATOR DIAGNOSIS
  SSP.Server --license-status [--license-root <dir>]  → Program.RunLicenseStatusAsync
    SspActivationService.Create + Load + DescribeStatus; exit 0 iff Valid; never starts a
    protected service and never starts the timer.
```

---

## 21. Definition of Done

| # | Requirement | Status |
|---|---|---|
| 1 | Activation architecture and dependency graph audited | ✅ §1.1 |
| 2 | Exactly one licensing authority; no competing `IsLicensed` caches | ✅ §2 (+ reflection test) |
| 3 | `ILicenseEnforcement?` nullable architecture removed; production fail-closed; test seams kept | ✅ §3 |
| 4 | EP0/EP1 correct semantics at the **service startup** boundary | ✅ §4 |
| 5 | Feature gating with a single constants mapping, no scattered literals | ✅ §5 |
| 6 | Limits enforced at real creation/destruction points, atomic check+increment, host supplies usage | ✅ §6 |
| 7 | Tunnel boundary check before the tunnel is active; all creation paths searched | ✅ §7 |
| 8 | Revalidation timer: one timer, no overlap, clean dispose, no stale Valid cache | ✅ §8 |
| 9 | Lockdown propagated everywhere, no cached-bool bypass | ✅ §9 |
| 10 | License file/state store: atomic writes, fail-closed, DPAPI, no secrets | ✅ §10 |
| 11 | Trust anchor left as fail-closed placeholder; no invented key; release blocker documented | ✅ §11 **(BLOCKER OPEN BY DESIGN)** |
| 12 | Installation identity stable, hashed, purpose-bound | ✅ §12 |
| 13 | Connection identity isolation preserved under licensing | ✅ §13 |
| 14 | Security events secret-free | ✅ §14 |
| 15 | Mandatory integration tests (missing, invalid sig, expired, wrong feature, valid feature, concurrent tunnel limit, lockdown, recovery, connection isolation) | ✅ §15 — all nine present |
| 16 | Negative fail-closed tests for every failure mode | ✅ §16 — 14 failure modes |
| 17 | Dedicated no-enforcement production path test | ✅ §17 |
| 18 | All existing SSP tests preserved unchanged | ✅ §18 — zero assertions modified |
| 19 | Build + test with exact PASS/FAIL report | ❌ **NOT MET — BLOCKED.** No SDK, no network route to one (§19.1). Nothing was run; nothing is claimed. |
| 20 | Final architecture map with actual class names | ✅ §20 |
| 21 | P4 not started | ✅ no `tools/SSP.LicenseAuthority`, no online activation, no key rotation, no TPM, no unrelated refactoring |

### Overall: **PARTIAL — implementation complete, verification outstanding.**

The two things standing between this branch and "done":

1. **Run the build and the tests** (§19.2) and fix whatever the compiler finds. Until that
   happens, the 59 new test cases and the 135 vendored ones are *written*, not *passing*.
2. **Set the real Licensing Authority public key** in `SspTrustAnchor.AuthorityPublicKeyPem`
   at the release key ceremony. Until then every protected service correctly refuses to
   start — which is the intended fail-closed posture, not a working product.

---

## Appendix A — files changed

**Production (modified)**
```
SSP.sln                                            + tests/SSP.Activation.Tests project
src/SSP.Core/Activation/SspLicensing.cs            + Features (rdp/ssh/web/sql), aliases,
                                                     ResolveForApplication/TryResolveForApplication,
                                                     Limits vocabulary + enforcement notes
src/SSP.Server/Activation/SspActivationService.cs  + Compose(...policy), RefreshLicense,
                                                     StartRevalidationTimer + owned loop, Dispose
src/SSP.Server/Program.cs                          + CreateForService in RunServiceModeAsync,
                                                     --license-status, provisioning gates,
                                                     bootstrapper exclusion
src/SSP.Server/Runtime/ServerGateway.cs            gate mandatory; EP1 removed from the
                                                     connection path; admission lifecycle
src/SSP.Server/Runtime/ServerProtocol.cs           + EP2 enrollment gate, EP3 future-auth gate,
                                                     single choke point in ReceiveSessionKeyAsync,
                                                     TakeTunnelAdmission/Dispose
src/SSP.Server/ServiceHost/SspWindowsService.cs    + CreateForService in OnStart, _license field,
                                                     disposal after the gateway in OnStop
src/SSP.Server/Setup/SetupEngine.cs                + optional ISspLicenseGate?, EP0a, EP0b
src/SSP.ServiceBuilder/Program.cs                  + TryCreateForProvisioning
src/SSP.ServiceBuilder/SSP.ServiceBuilder.csproj   + SSP.Activation ProjectReference
```

**Production (new)**
```
src/SSP.Server/Activation/ISspLicenseGate.cs       ISspLicenseGate, SspTunnelAdmission,
                                                     SspActivationException
src/SSP.Server/Activation/SspRuntimeLicense.cs     production gate, CreateForService,
                                                     TryCreateForProvisioning, AuthorizeServiceStart,
                                                     AdmitTunnel, SspProtectedServiceInventory
```

**Tests (new)**
```
tests/SSP.Tests/Helpers/UnlicensedTestGate.cs
tests/SSP.Tests/Helpers/LicensedTestEnvironment.cs
tests/SSP.Tests/Activation/Runtime/LicensingFailClosedMatrixTests.cs
tests/SSP.Tests/Activation/Runtime/TunnelLicensingIntegrationTests.cs
tests/SSP.Tests/Activation/Runtime/LicensingCompositionTests.cs
tests/SSP.Tests/Activation/Runtime/ConnectionIsolationLicensingTests.cs
tests/SSP.Activation.Tests/                        21 files, verbatim from _reference
```

**Tests (modified — dependencies only, no assertions)**
```
tests/SSP.Tests/Helpers/SspTestHarness.cs
tests/SSP.Tests/ServiceStartRegressionTests.cs
```

## Appendix B — behaviour matrix

| Situation | Service start (EP1) | Enrollment (EP2) | New tunnel (EP3) | Existing tunnel |
|---|---|---|---|---|
| No trust anchor in build | refused (`trust_anchor_missing`) | n/a — service never runs | n/a | n/a |
| No license file | refused (`missing_license`, state Unknown) | denied (`license_not_valid`) | denied | never existed |
| Tampered / foreign authority | refused (`invalid_signature`/`malformed_artifact`, LockedDown) | denied | denied | n/a |
| Expired / not-yet-valid / revoked | refused | denied | denied | **never killed** — the reference architecture is non-destructive; the tunnel ends when the client ends it |
| Valid, feature missing | refused (`feature_not_licensed`) | allowed (identity is not feature-gated) | denied (`feature_not_licensed`) | n/a |
| Valid, `max_clients` reached | allowed | refused (`limit_exceeded`) **before the OTT is consumed** | allowed | unaffected |
| Valid, `max_concurrent_tunnels` reached | allowed | allowed (enrollment socket's own session-key offer is refused) | refused (`limit_exceeded`) | unaffected |
| Valid → LockedDown at runtime | already running | denied from the next call | denied from the next connection | unaffected |
| LockedDown → renewal installed | no restart needed | allowed again | allowed again | — |
| License file deleted after lockdown | refused | denied | denied | — |
| State store unreadable | refused (`state_store_unavailable`) | denied | denied | — |
| Policy throws | refused | denied (`internal_error`) | denied (`internal_error`) | — |
| Gate disposed (shutdown) | — | denied | denied **without throwing** | released by the gateway's `finally` |
