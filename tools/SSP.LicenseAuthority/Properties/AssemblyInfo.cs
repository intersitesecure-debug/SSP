// File: tools/SSP.LicenseAuthority/Properties/AssemblyInfo.cs
//
// Expose internal command handlers to SSP.Tests so the authority CLI can be
// exercised in-process with ephemeral keys. Nothing here is visible to any
// shipped SSP binary: SSP.Server / SSP.ServiceHost / SSP.Client do not
// reference this assembly.

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SSP.Tests")]
