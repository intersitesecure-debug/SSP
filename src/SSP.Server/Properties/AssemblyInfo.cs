// File: src/SSP.Server/Properties/AssemblyInfo.cs
//
// Expose internal service-host types (e.g. ServiceDiagnostics) to the test
// assembly so the Windows Service start path can be verified on every
// platform, not only on an elevated Windows runner.

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SSP.Tests")]
