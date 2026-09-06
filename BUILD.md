# Building, restoring and testing SSP

Audience: anyone hitting `NU1900`, building on a machine that cannot reach
`api.nuget.org`, or wiring this solution into CI.

---

## 1. The NU1900 failure and how it is handled

Observed symptom (any .NET 8+ SDK, machine without access to the NuGet
advisory feed):

```
src\SSP.Activation\SSP.Activation.csproj : error NU1900: Warning As Error:
    Error occurred while getting package vulnerability data: Unable to load
    the service index for source https://api.nuget.org/v3/index.json.
Restore failed with 1 error(s) and 4 warning(s)
```

Facts that explain the shape of that output:

* `NU1900` is **not** a dependency problem. It is the failure of NuGet's
  optional *vulnerability audit* to download its advisory index. The packages
  themselves resolved from the global cache; the other four projects printed
  the same line as a warning and restored successfully.
* Only the two projects that set `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`
  (`src/SSP.Activation`, `tests/SSP.Activation.Tests`) turn it into an error.
  `TreatWarningsAsErrors` escalates *every* warning, and NuGet feeds the same
  four properties to the restore task that the compiler uses (`TreatWarningsAsErrors`,
  `WarningsAsErrors`, `WarningsNotAsErrors`, `NoWarn`), so a transport error
  becomes a build error even though nothing in the source is wrong.
* `SSP.Activation` has **zero** `PackageReference` items: the audit there had
  literally nothing to walk, it still contacted the feed.

Resolution (all in build configuration, no code change):

| File | Change | Why |
| --- | --- | --- |
| `Directory.Build.props` (new) | `NoWarn += NU1900` | An unreachable advisory feed is an environment condition. Never a build error, no warning noise either. |
| `Directory.Build.props` | `WarningsNotAsErrors += NU1901;NU1902;NU1903;NU1904` | Real advisories stay **visible** as warnings in every project, but a disclosure published later against, e.g., a test-stack package cannot brick every build. |
| `src/SSP.Activation/SSP.Activation.csproj` | `NuGetAudit=false` | Nothing to audit (zero packages). Skips the pointless round-trip entirely; consuming projects still audit their own graphs. |
| `src/SSP.Server/SSP.Server.csproj` | reads `SSP_SKIP_EMBED_EFFECTIVE` | `SSP_SKIP_EMBED` was documented as `=1` but only matched the literal `true`; the numeric form silently ran the recursive single-file publish. |

`TreatWarningsAsErrors` is intentionally **kept** for both projects: it is what
makes nullable-annotation and analyzer regressions in the licensing subsystem
fail the build. Only NuGet's environment diagnostics are exempted, explicitly,
in one place.

To restore the previous, stricter behaviour for a CI leg that has a working
feed: `/p:WarningsNotAsErrors=` (advisories fatal again) or `/p:NuGetAudit=true`
per project.

## 1b. Runtime code-integrity (Phase 5 / M-4): no build impact unless armed

`src/SSP.Core/CodeIntegrity` (manifest + streaming SHA-256 verifier) is pure BCL
(`System.Security.Cryptography`, `System.Text.Json`) — **no new package**, so the
dependency inventory below and the offline restore contract are unchanged. The
SSP.Server gate (`RuntimeCodeIntegrity`, called at the top of
`SspRuntimeLicense.CreateForService`) is a **no-op unless a build is armed**, and
arming is opt-in at the release ceremony only:

```powershell
dotnet publish src/SSP.Server/SSP.Server.csproj -c Release -r win-x64 \
    -p:PublishSingleFile=true \
    -p:SspRequireCodeIntegrity=true \
    -p:SspCodeIntegrityManifestFile=D:\ceremony\ssp-code-integrity.json
```

`Activation/SspCodeIntegrity.targets` embeds that JSON as
`SSP.Server.CodeIntegrity.manifest.json` and propagates it into the standalone
`SSP.ServiceHost` publish via `SspCodeIntegrityPublishArgs`. Developer/CI builds
(including `SSP_SKIP_EMBED=true` test builds) never set the property, embed
nothing, and are byte-for-byte unaffected. See `Security Correction.md` Phase 5,
`docs/THREAT_MODEL.md` T35, and the manifest schema in
`src/SSP.Core/CodeIntegrity/CodeIntegrityManifest.cs` (pinned by
`RuntimeCodeIntegrityTests`).

## 2. Dependency inventory

Direct package dependencies of the whole solution — verified against the
GitHub Advisory Database (`GET /advisories?ecosystem=nuget`), which reported
**no advisory affecting any of them**, and all versions are exact (no floating
`*`, no ranges), which is what makes an offline cache usable:

| Package | Version | Used by | Notes |
| --- | --- | --- | --- |
| `System.Security.Cryptography.ProtectedData` | 8.0.0 | `SSP.Core` | DPAPI (`CurrentUser`/`LocalMachine`) envelope for `ProtectedFileStore`; Windows-guarded at the call sites, so the assembly still builds and tests on other platforms. |
| `System.ServiceProcess.ServiceController` | 8.0.0 | `SSP.Server` | SCM client used by `WindowsServiceInstaller` / service start verification. |
| `System.CommandLine` | 2.0.0-beta4.22272.1 | `SSP.Server`, `SSP.ServiceBuilder` | Same version in both, so no downgrade or unification conflict (NU1510/NU1605/MSB3277 stay quiet). The pinned beta is the only published form of the 2.0 line. |
| `Microsoft.NET.Test.Sdk` | 17.8.0 | both test projects | |
| `xunit` | 2.5.3 | both test projects | Brings `xunit.analyzers`; that is what makes `tests/SSP.Activation.Tests` (strict) sensitive to `xUnit1xxx`/`xUnit2xxx` diagnostics. **2.5.3 has no user-message overload of `Assert.Equal`**: the third argument is a COMPARER (`IEqualityComparer<T>` or `Func<T, T, bool>`), so `Assert.Equal(expected, actual, "why")` fails to bind with `CS1503: cannot convert from 'string' to 'System.Func<T, T, bool>'`. Message-bearing value comparisons go through `Assert.True(condition, message)` (see `tests/SSP.Tests/ClientIdentityKeyProtectionTests.AssertEnvelopeScope`). |
| `xunit.runner.visualstudio` | 2.5.3 | both test projects | Version-matched to `xunit`. |
| `coverlet.collector` | 6.0.0 | both test projects | |

Project graph: `SSP.Core` ← `SSP.Client` ← `SSP.Server` (← `SSP.ServiceHost`,
`SSP.ServiceBuilder`), `SSP.Activation` ← `SSP.Server`; `SSP.Activation` has no
package or project dependency by design. `tests/SSP.Tests` reaches internals of
`SSP.Client`, `SSP.Server` and `SSP.ServiceHost` through their
`InternalsVisibleTo` attributes; `SSP.Core` and `SSP.Activation` expose nothing
internal to the tests, and nothing in the test code needs it.

**Do not bump these versions on an offline machine.** Restore is satisfied from
`%USERPROFILE%\.nuget\packages` for exactly the versions above; a newer version
is not in that cache and will fail with `NU1900`'s louder cousin `NU1101`.
Upgrades belong on a networked machine or an internal mirror.

## 3. Build and test on a machine without a NuGet feed

The only part of a *normal* build that needs a feed beyond the packages above is
`SSP.Server`'s two template targets, which re-publish `SSP.Client` and
`SSP.ServiceHost` as self-contained single-file `win-x64` images (that pulls
`Microsoft.NETCore.App.Host.win-x64` and `Microsoft.NETCore.App.Runtime.win-x64`).
Use the documented test seam to skip them:

```powershell
# restore only the projects' own packages (works from the local cache)
dotnet restore

# offline build and test: framework-dependent stand-ins are embedded instead
dotnet build -p:SSP_SKIP_EMBED=true
dotnet test  tests/SSP.Tests -p:SSP_SKIP_EMBED=true
dotnet test  tests/SSP.Activation.Tests -p:SSP_SKIP_EMBED=true

# or for a whole shell session
$env:SSP_SKIP_EMBED = "true"     # 1 / yes work too
```

`SSP_SKIP_EMBED=true` embeds the framework-dependent `SSP.Client.dll` as the
client template and embeds no service-host image; the suites that exercise the
extraction contract use the `SSP_SERVICE_HOST_IMAGE` seam for that. Production
publishes must **not** set it: a shipped `SSP.Server.exe` has to carry the real
self-contained single-file images (see the spec notes in
`src/SSP.Server/SSP.Server.csproj`).

If packages are genuinely missing from the cache, point NuGet at an internal
mirror or a folder drop and restore from it:

```powershell
dotnet nuget add source https://nexus.internal/repository/nuget-v3/ -name internal
# or fully offline, from a directory of .nupkg files:
dotnet restore -s C:\feed -s https://api.nuget.org/v3/index.json
```

`NUGET_PACKAGES` relocates the global packages folder if CI shares a cache.

## 4. Checking that the build is clean

```powershell
dotnet clean            # 0 errors
dotnet restore          # 0 errors, 0 warnings  <- this is what NU1900 broke
dotnet build            # production path: needs the win-x64 packs, or set SSP_SKIP_EMBED
dotnet build -p:SSP_SKIP_EMBED=true
dotnet test             # both test projects
```

Audit is still active where it is meaningful; to review it explicitly:

```powershell
dotnet list package --vulnerable --include-transitive
```

If a build reports *compiler* warnings as errors (a newer SDK, a new analyzer
rule, mostly in `SSP.Activation` and `SSP.Activation.Tests`, which keep
`TreatWarningsAsErrors`), triage with the escalation off and fix the reported
sites rather than the switch:

```powershell
dotnet build -p:TreatWarningsAsErrors=false 2>&1 | Select-String -Pattern "warning"
```

A build that is green for the wrong reason is easy to spot from the same output:
if `NU1901..NU1904` lines appear, there is a real advisory to triage, and it is
reported rather than silently suppressed.
