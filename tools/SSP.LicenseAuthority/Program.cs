// File: tools/SSP.LicenseAuthority/Program.cs
//
// SSP Licensing Authority CLI. Offline-only: key generation, public-key
// export, fingerprinting, license issuance, inspection and verification.
//
// This executable is NEVER shipped with SSP. It is not referenced by
// SSP.Server, SSP.ServiceHost, SSP.Client or SSP.ServiceBuilder. It holds
// no key material of its own — the authority private key is supplied by
// the operator as a file that must live outside the SSP repository, the
// build and every customer artifact.
//
// Usage:
//   SSP.LicenseAuthority keygen        --private-key <file> [--public-key <file>]
//   SSP.LicenseAuthority export-public --private-key <file> --output <file>
//   SSP.LicenseAuthority fingerprint   --public-key <file> [--expect <sha256>]
//   SSP.LicenseAuthority issue         --private-key <file> --output <file> ...
//   SSP.LicenseAuthority issue-certified --private-key <file> --output <file> ...
//   SSP.LicenseAuthority renew         --private-key <file> --license <file> --output <file> ...
//   SSP.LicenseAuthority inspect       --license <file>
//   SSP.LicenseAuthority verify        --license <file> --public-key <file> ...
//   SSP.LicenseAuthority activate      --request <file> --activation-record <file>

namespace SSP.LicenseAuthority;

public static class Program
{
    public static Task<int> Main(string[] args) => LicenseAuthorityCli.RunAsync(args);
}
