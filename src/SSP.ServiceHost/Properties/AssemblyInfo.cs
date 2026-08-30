// File: src/SSP.ServiceHost/Properties/AssemblyInfo.cs
//
// Expose the service host's mode gate to the test assembly so the
// "SSP.ServiceHost.exe only ever runs services" contract can be verified
// on every platform, not only on an elevated Windows runner.

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SSP.Tests")]
