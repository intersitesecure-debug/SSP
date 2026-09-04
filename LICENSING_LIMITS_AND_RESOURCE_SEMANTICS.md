# SSP Licensing Limits & Resource Semantics — Source-Verified Analysis

Scope: licensing limits and resource semantics only, in the current `SSP` + `SSP.Activation`
integration. Read-only; no code, tests or configuration were modified.

**Verification status:** every conclusion below is cited to a file path + type/method and to
the line(s) read in this session. No build or test run was possible in this sandbox — the .NET
8 SDK is not installed (`dotnet` is absent from PATH and from `/usr/lib/dotnet`,
`/usr/share/dotnet`, `/opt/dotnet`, `~/.dotnet`) and outbound network is blocked
(`curl https://dot.net/v1/dotnet-install.sh` → `SSL_ERROR_SYSCALL`, HTTP 000). So the claims are
source-evidence only and are **not** backed by an executed test run.

---

## 1. What is a "service"?

A **protected service = one provisioned application directory** on the machine.

| Evidence | Location |
|---|---|
| Counting definition: complete application directory under `{Program Files}\SSP\services\` | `src/SSP.Server/Activation/SspRuntimeLicense.cs` — `SspProtectedServiceInventory.CountProtectedServices` (l.455-493), `ResolveServicesRoot` (l.495-504) |
| "Complete" = `.cache.dat` **and** `.sysdata.bin` **and** `.runtime.dat` all present | `SspProtectedServiceInventory.IsCompleteApplicationDirectory` (l.506-518) |
| The same three-file rule used by provisioning | `src/SSP.Server/Setup/SetupEngine.cs` — `IsExistingApplicationDirectory` (l.120-131) |
| Runtime configuration of a service | `src/SSP.Core/Models/ServiceConfig.cs` — `ServiceConfig` (l.14-71) |
| One gate instance per service process | `src/SSP.Server/Activation/ISspLicenseGate.cs` l.40-41; `SspRuntimeLicense.cs` l.3 |

Notes read directly from source:
- The service being started is **excluded** from its own count
  (`excludeServiceDir`, `CountProtectedServices` l.465-474; `AuthorizeServiceStart` l.271).
- Documented limitation (l.441-445): a service provisioned outside the canonical root via an
  explicit `--service-dir` is **not** counted.
- On any I/O error the inventory returns `0` (l.484-492), which leaves `max_services`
  effectively unconstrained for that check while every other gate still applies.
- The XML remark at l.435-438 says "`.cache.dat` plus both RSA key files"; the code
  (l.510-512) checks `.cache.dat`, `.sysdata.bin`, `.runtime.dat` — which *are* the two key
  files per `ServiceConfig.ServerPrivateKeyPath`/`ServerPublicKeyPath` (l.34, l.39). The two
  statements agree.

## 2. What is a "client"?

A **client = one enrolled, authorized public-key identity recorded in that service's
`.index.dat`** — not a TCP connection.

| Evidence | Location |
|---|---|
| The record | `src/SSP.Core/Models/ServiceConfig.cs` — `AuthorisedUser` (l.92-112): `ClientPublicKeyFingerprint`, `ClientPublicKeyPem`, `IsAuthorized`, `EnrolledAtUtc`, `Label` |
| The store | `src/SSP.Core/Models/ServiceConfig.cs` — `AuthorisedUsersFile` (l.119-124); `src/SSP.Core/IO/ConfigStore.cs` — `AuthorisedUsersStore` (l.162) |
| Store path default `.index.dat` | `ServiceConfig.AuthorisedUsersPath` (l.44) |
| Usage count = `users.Users.Count` | `src/SSP.Server/Runtime/ServerProtocol.cs` l.265-267; `src/SSP.Server/Setup/SetupEngine.cs` — `AuthorizeAdditionalClientAsync` l.532-548 |
| Re-enrollment does not count against itself | `ServerProtocol.cs` l.259-267 (`reEnrollsExistingClient` → `Count - 1`) |

Scope: the count is **per service** (`.index.dat` lives in the service directory), i.e.
`max_clients` is a per-application limit — matching `SspLicensing.Limits.MaxClients`' summary
"Maximum number of authorised clients **per service**" (`src/SSP.Core/Activation/SspLicensing.cs`
l.201-202), which is narrower than `LicenseLimitNames.MaxClients`' "Maximum number of licensed
clients" (`src/SSP.Activation/Models/LicenseLimitNames.cs` l.14-15).

## 3. What is a "tunnel"?

A **tunnel = one admitted, authenticated data-plane connection**: the encrypted bridge between
the client's socket and `127.0.0.1:LocalApplicationPort`, driven by exactly one `TunnelCodec`
built from that connection's session key.

| Evidence | Location |
|---|---|
| Per-connection handler, one `ServerProtocol` per accepted socket | `src/SSP.Server/Runtime/ServerProtocol.cs` l.13-16; `src/SSP.Server/Runtime/ServerGateway.cs` l.191 |
| The tunnel body: one `TunnelCodec(sessionKey)` + `TunnelRelay.BridgeAsync` | `ServerGateway.HandleClientAsync` l.201-226 |
| Codec / relay types | `src/SSP.Core/Protocol/TunnelCodec.cs` — `TunnelCodec` (l.21-26), `TunnelRelay` (l.77) |
| "Tunnels currently admitted by the license gate and not yet released" | `ServerGateway.ActiveTunnels` l.106-111 |

Important: the counter measures **admitted**, not **bridging**. The slot is reserved at
admission time, before the session key is accepted and before any traffic flows
(`SspRuntimeLicense.AdmitTunnel` l.356-359; `ISspLicenseGate` l.124-130).

## 4. What is a "session"?

A **session = the same authenticated data-plane connection, identified by its negotiated
session key.** In this codebase "session" and "tunnel" are two names for one resource, not two
resources.

| Evidence | Location |
|---|---|
| Explicit statement of the identity | `src/SSP.Server/Activation/SspRuntimeLicense.cs` l.345-349: *"In SSP one authenticated data-plane connection is both the session and the tunnel (the session key negotiated for it feeds exactly one TunnelCodec), so the counters move together"* |
| Same statement in the limit vocabulary docs | `src/SSP.Core/Activation/SspLicensing.cs` l.183-187 |
| Session key acceptance is the single data-plane choke point | `ServerProtocol.ReceiveSessionKeyAsync` l.498-559 (comment l.513-535) |
| One session key → one codec | `ServerGateway.HandleClientAsync` l.195, l.203 |

There is **no** session object, session table, session id, or session lifetime in the code. The
only "session" artifacts are `SessionKeyOfferMessage` / `SessionKeyAckMessage`
(`src/SSP.Core/Protocol/Messages.cs`) and the derived `TunnelCodec`.

## 5. `_activeTunnels` / `_activeSessions` — full lifecycle

Both are `private long` fields of `SspRuntimeLicense`
(`src/SSP.Server/Activation/SspRuntimeLicense.cs` l.47-48), default-initialized to 0, exposed
read-only via `Interlocked.Read` (l.84-87). `SspRuntimeLicense` is the **only** production
`ISspLicenseGate` (`SspRuntimeLicense.cs` l.42; the only other implementor is
`tests/SSP.Tests/Helpers/UnlicensedTestGate.cs` l.30, test-assembly only).

**Reservation — `AdmitTunnel()` (l.306-361)**, one `lock (_admissionGate)` covering decision *and*
reservation:
1. disposed → deny (l.316-324)
2. EP1 feature re-check `enforcement.CanUseFeature(Feature)` (l.328-335)
3. EP3 `enforcement.CanEstablishTunnel(_activeTunnels)` (l.339-343)
4. EP2 `enforcement.CanCreateSession(_activeSessions)` (l.350-354)
5. `_activeTunnels++; _activeSessions++;` (l.356-357)
6. return `SspTunnelAdmission.Grant(ReleaseTunnel)` (l.359) — the release callback is bound here

**Call sites of `AdmitTunnel()` — exactly two**, both in `ServerProtocol`, both *after*
cryptographic identity authorization (rationale l.28-33 and l.446-459):
- `HandleFutureAuthorizationAsync` l.460 — stored in `_heldAdmission` l.476
- `ReceiveSessionKeyAsync` l.538 — only when `_heldAdmission is null` (l.536), the single choke
  point that closes the enrollment→session-key alternate path (l.524-529)

**Release — `ReleaseTunnel()` (l.363-377)**: under the same lock, decrements each counter only if
`> 0` (l.367-375). Invoked solely through `SspTunnelAdmission.Dispose()` → `_release?.Invoke()`
(`src/SSP.Server/Activation/ISspLicenseGate.cs` l.171-179), made exactly-once by
`Interlocked.Exchange(ref _disposed, 1)` (l.173-176). A **denied** admission carries
`release: null` (l.158), so disposing it cannot decrement.

**Ownership transfer / release points:**

| Step | Location |
|---|---|
| Held by the protocol handler | `ServerProtocol._heldAdmission` l.66 |
| Denied admission disposed immediately (no-op) | `ServerProtocol.cs` l.463, l.541 |
| Defensive dispose before replace | `ServerProtocol.cs` l.475 |
| Session-key receive failed → give the slot back at once | `ServerProtocol.cs` l.488-489 |
| Ownership transferred to the gateway, field cleared | `ServerProtocol.TakeTunnelAdmission` l.96-101, called at `ServerGateway.cs` l.199 |
| Any admission still held by the handler | `ServerProtocol.Dispose` l.104-109, called at `ServerGateway.cs` l.241 |
| Normal end of tunnel (completion, disconnect, or throw) | `ServerGateway.HandleClientAsync` `finally` l.240 |
| Shutdown joins every handler so no release is skipped | `ServerGateway.DisposeCoreAsync` l.258-280; accept-loop `Task.Run` comment l.155-158 |

Both disposals are idempotent, so the failure path (handler still holding it) and the success
path (gateway holding it) each release exactly once (`ServerGateway.cs` l.234-239).

## 6. Does one tunnel always equal one session?

**Yes — in the current code they are strictly 1:1 and the two counters can never differ.**

Evidence:
- The only writes to either field are l.356-357 (both `++`) and l.367-375 (both `--`), both
  inside `lock (_admissionGate)`. Both start at 0. Verified by exhaustive grep:
  `_activeTunnels` / `_activeSessions` appear only at l.47, 48, 84, 87, 339, 350, 356, 357, 367,
  369, 372, 374 of `SspRuntimeLicense.cs` — no other mutation site exists in `src/` or `tests/`.
- There is no separate session-creation or session-release API: `ISspLicenseGate` exposes only
  `AdmitTunnel()` plus `ActiveTunnels` / `ActiveSessions` getters (l.61-84).
- One `SspTunnelAdmission` per connection, and one `ServerProtocol` per socket
  (`ServerProtocol.cs` l.13-16), so a single connection can hold at most one reservation.
- Consequently the `> 0` guards in `ReleaseTunnel` can never clip one counter and not the other.

The difference between the two limits is therefore **only which limit name a license may
constrain**; the measured usage is identical. The source states this as intent
(`SspRuntimeLicense.cs` l.345-349, `SspLicensing.cs` l.183-187): both are checked so *"the
stricter limit always wins."*

## 7. Where is `max_concurrent_tunnels` enforced?

Single enforcement point, per connection, inside the admission critical section:

```
ServerProtocol.HandleFutureAuthorizationAsync l.460  ─┐
ServerProtocol.ReceiveSessionKeyAsync        l.538  ─┴─► SspRuntimeLicense.AdmitTunnel l.339
      enforcement.CanEstablishTunnel(_activeTunnels)
   → LicenseEnforcement.CanEstablishTunnel        (src/SSP.Activation/Enforcement/LicenseEnforcement.cs l.19-20)
   → ProtectedOperation.EstablishTunnel           (src/SSP.Activation/Models/ProtectedOperation.cs l.42-44)
   → CheckLimit("max_concurrent_tunnels", usage)  (ProtectedOperation.cs l.51-52)
   → LicenseManager.Authorize, under lock (_gate) (src/SSP.Activation/LicenseManager.cs l.224-269)
   → DefaultLicensePolicy.Evaluate, LimitCheckKind(src/SSP.Activation/Enforcement/DefaultLicensePolicy.cs l.55-86)
```

`DefaultLicensePolicy` semantics (l.72-85): absent limit or explicit `null` = unconstrained
(Allow); `CurrentUsage < max` = Allow; otherwise Deny with `LicenseReasons.LimitExceeded`. Usage
is measured **before** the grant (`ProtectedOperation.CurrentUsage` l.31-32).

Notably it is *not* enforced per socket accept: `ServerGateway.cs` l.16-30 states EP1 is
enforced once by the composition root and that tunnel/session limits are enforced per
connection through `AdmitTunnel()` after authentication.

## 8. Where is `max_concurrent_sessions` enforced?

Same call site, same critical section, immediately after the tunnel check:

```
SspRuntimeLicense.AdmitTunnel l.350
      enforcement.CanCreateSession(_activeSessions)
   → LicenseEnforcement.CanCreateSession          (LicenseEnforcement.cs l.22-23)
   → ProtectedOperation.CreateSession             (ProtectedOperation.cs l.46-48)
   → CheckLimit("max_concurrent_sessions", usage)
   → LicenseManager.Authorize → DefaultLicensePolicy.Evaluate (as above)
```

Because the two checks are sequential and both must pass before l.356-357 reserve anything, a
denial by either limit consumes no slot. Denials are reported as
`ProtectedOperationDenied` events (`LicenseManager.cs` l.258-268).

## 9. What does `max_sessions` mean, and does any code need it?

**Meaning per the contracts:** a **cumulative total** of sessions over the license's life —
distinct from `max_concurrent_sessions`.
- `src/SSP.Activation/Models/LicenseLimitNames.cs` l.17-18: *"Maximum total number of sessions."*
- `src/SSP.Core/Activation/SspLicensing.cs` l.204-205: *"Maximum total number of sessions
  (reserved seam; not enforced)."*
- `src/SSP.Core/Activation/SspLicensing.cs` l.188-194 states the reason: it is a cumulative
  total that SSP cannot measure offline across process restarts without persisting a
  per-license counter, so it is *"left unconstrained rather than enforced incorrectly."*

**Does any code need it? No.**
- `ProtectedOperation` has **no** factory for it — only `StartProtectedService`,
  `EstablishTunnel`, `CreateSession`, `UseFeature`, `CheckLimit`, `RequireValidLicense`
  (`ProtectedOperation.cs` l.34-60).
- No call anywhere constructs a limit-check with that name: a case-insensitive grep for
  `max_sessions` / `MaxSessions` across `src/` returns exactly three hits — the declaration at
  `LicenseLimitNames.cs:18`, the mirror declaration at `SspLicensing.cs:205`, and the
  explanatory comment at `SspLicensing.cs:188`. No consumer.
- The only reference in the whole repository outside those is a constant-equality assertion:
  `tests/SSP.Tests/Activation/SspLicensingAndTrustAnchorTests.cs` l.28.
- `DefaultLicensePolicy` is name-generic (l.72 `payload.Limits.TryGetValue(limitName, …)`), so a
  license carrying `max_sessions` parses, canonicalizes and round-trips fine — the value is
  simply never consulted.

Consequence, stated as fact: a license issued with `max_sessions = N` imposes **no** restriction
on a running SSP today.

## 10. Other licensing limits defined in SSP.Activation but not enforced by SSP

The complete limit vocabulary in `SSP.Activation` is the five constants of
`LicenseLimitNames` (`src/SSP.Activation/Models/LicenseLimitNames.cs` l.12-24). A grep for every
`max_*` string literal in `src/` returns only those five names, in the two mirrored vocabularies
(`LicenseLimitNames.cs` and `SspLicensing.Limits`) — no others exist.

| Limit | Enforced by SSP? | Enforcement site |
|---|---|---|
| `max_services` | **Yes** | `SspRuntimeLicense.AuthorizeServiceStart` l.271-280; `SetupEngine.cs` l.517-524 |
| `max_clients` | **Yes** | `SspRuntimeLicense.CanEnrollClient` l.384-385, called from `ServerProtocol.cs` l.269 and `SetupEngine.cs` l.541 |
| `max_concurrent_tunnels` | **Yes** | `SspRuntimeLicense.AdmitTunnel` l.339 |
| `max_concurrent_sessions` | **Yes** | `SspRuntimeLicense.AdmitTunnel` l.350 |
| `max_sessions` | **No** | — none; declared only |

**`max_sessions` is the only unenforced licensing limit.** `LicenseLimitNames` itself notes the
names are "conventions, not reserved keywords" and that hosts may add their own via
`ProtectedOperation.CheckLimit(string, long)` (l.3-7), so the library defines no further limits
behind these five. (`LicenseStringLimits` in
`src/SSP.Activation/Serialization/LicenseArtifactCodec.cs` l.609 are serialization length caps,
not licensing limits.)

---

## Scope asymmetry worth recording (observed, not a proposal)

| Limit | Measured over | Persisted? |
|---|---|---|
| `max_services` | machine-wide, filesystem inventory (`SspProtectedServiceInventory`) | implicitly, as directories |
| `max_clients` | per service, `.index.dat` (`AuthorisedUsersStore`) | yes |
| `max_concurrent_tunnels` | per server process, `_activeTunnels` | no — resets on restart |
| `max_concurrent_sessions` | per server process, `_activeSessions` | no — resets on restart |
| `max_sessions` | not measured | no |
