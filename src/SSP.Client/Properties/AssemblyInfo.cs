// File: src/SSP.Client/Properties/AssemblyInfo.cs
//
// Expose the internal client install handoff (e.g.
// ClientInstallationBootstrapper) to the test assembly so the Windows
// launch-gate logic can be verified on every platform, not only on an
// elevated Windows runner.

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SSP.Tests")]
