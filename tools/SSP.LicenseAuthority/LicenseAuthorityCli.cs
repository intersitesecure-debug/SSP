// File: tools/SSP.LicenseAuthority/LicenseAuthorityCli.cs
//
// Command table for the Licensing Authority tool. Every command that needs
// the private key takes it as an explicit --private-key file path; nothing
// is read from the environment, from the SSP repository, or from a compiled
// resource. Public-key export is a separate, explicit command.
//
// Parsing is BCL-only (no System.CommandLine) so this tool's restore graph
// is SSP.Activation and nothing else.

using System.Globalization;
using System.Security.Cryptography;
using SSP.Activation;

namespace SSP.LicenseAuthority;

/// <summary>
/// In-process entry point used by <c>Program.Main</c> and by SSP.Tests.
/// Passing <see cref="TextWriter"/>s keeps tests off the process console.
/// </summary>
public static class LicenseAuthorityCli
{
    private static readonly HashSet<string> KnownCommands = new(StringComparer.Ordinal)
    {
        "keygen", "export-public", "fingerprint", "issue", "issue-certified", "renew",
        "inspect", "verify", "activate", "help", "--help", "-h"
    };

    private static readonly HashSet<string> FlagNames = new(StringComparer.Ordinal)
    {
        "--force", "-f", "--help", "-h", "--activation-required"
    };

    private static readonly HashSet<string> KnownOptionNames = new(StringComparer.Ordinal)
    {
        "--private-key",
        "--public-key",
        "--output",
        "--expect",
        "--spec",
        "--license-id",
        "--product-id",
        "--product-name",
        "--customer-id",
        "--customer-name",
        "--organization-name",
        "--computer-name",
        "--edition",
        "--license-version",
        "--issued-at",
        "--not-before",
        "--expires-at",
        "--valid-for-days",
        "--installation-id",
        "--feature",
        "--limit",
        "--status",
        "--sequence",
        "--license",
        "--now",
        "--expect-fingerprint",
        "--highest-accepted-sequence",
        "--activation-required",
        "--activation-record",
        "--request",
    };

    public static Task<int> RunAsync(
        string[] args,
        TextWriter? stdout = null,
        TextWriter? stderr = null)
    {
        var oldOut = Console.Out;
        var oldErr = Console.Error;
        try
        {
            if (stdout is not null)
            {
                Console.SetOut(stdout);
            }

            if (stderr is not null)
            {
                Console.SetError(stderr);
            }

            if (args.Length == 0 || IsHelp(args[0]) && args.Length == 1)
            {
                PrintHelp();
                return Task.FromResult(args.Length == 0 ? 1 : 0);
            }

            return Task.FromResult(Dispatch(args));
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return Task.FromResult(1);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return Task.FromResult(1);
        }
        catch (CryptographicException)
        {
            Console.Error.WriteLine("error: cryptographic failure (CryptographicException).");
            return Task.FromResult(1);
        }
        finally
        {
            Console.SetOut(oldOut);
            Console.SetError(oldErr);
        }
    }

    private static int Dispatch(string[] args)
    {
        var command = args[0];
        if (!KnownCommands.Contains(command))
        {
            Console.Error.WriteLine($"error: unknown command '{command}'. Use 'help'.");
            return 1;
        }

        if (IsHelp(command))
        {
            PrintHelp();
            return 0;
        }

        ParsedArgs parsed;
        try
        {
            parsed = ParsedArgs.Parse(args.AsSpan(1));
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }

        if (parsed.HasFlag("--help") || parsed.HasFlag("-h"))
        {
            PrintHelp();
            return 0;
        }

        return command switch
        {
            "keygen" => RunKeygen(parsed.Get("--private-key"), parsed.Get("--public-key"), parsed.Force),
            "export-public" => RunExportPublic(parsed.Get("--private-key"), parsed.Get("--output"), parsed.Force),
            "fingerprint" => RunFingerprint(parsed.Get("--public-key"), parsed.Get("--private-key"), parsed.Get("--expect")),
            "issue" => RunIssue(
                privateKeyPath: parsed.Get("--private-key"),
                outputPath: parsed.Get("--output"),
                specPath: parsed.Get("--spec"),
                licenseId: parsed.Get("--license-id"),
                productId: parsed.Get("--product-id"),
                productName: parsed.Get("--product-name"),
                customerId: parsed.Get("--customer-id"),
                customerName: parsed.Get("--customer-name"),
                organizationName: parsed.Get("--organization-name"),
                computerName: parsed.Get("--computer-name"),
                edition: parsed.Get("--edition"),
                licenseVersion: parsed.Get("--license-version"),
                issuedAt: parsed.Get("--issued-at"),
                notBefore: parsed.Get("--not-before"),
                expiresAt: parsed.Get("--expires-at"),
                validForDays: parsed.GetInt("--valid-for-days"),
                installationId: parsed.Get("--installation-id"),
                features: parsed.GetAll("--feature"),
                limits: parsed.GetAll("--limit"),
                status: parsed.Get("--status"),
                sequence: parsed.GetLong("--sequence"),
                force: parsed.Force),
            "issue-certified" => RunIssueCertified(
                privateKeyPath: parsed.Get("--private-key"),
                outputPath: parsed.Get("--output"),
                specPath: parsed.Get("--spec"),
                licenseId: parsed.Get("--license-id"),
                productId: parsed.Get("--product-id"),
                productName: parsed.Get("--product-name"),
                customerId: parsed.Get("--customer-id"),
                customerName: parsed.Get("--customer-name"),
                organizationName: parsed.Get("--organization-name"),
                computerName: parsed.Get("--computer-name"),
                edition: parsed.Get("--edition"),
                licenseVersion: parsed.Get("--license-version"),
                issuedAt: parsed.Get("--issued-at"),
                notBefore: parsed.Get("--not-before"),
                expiresAt: parsed.Get("--expires-at"),
                validForDays: parsed.GetInt("--valid-for-days"),
                installationId: parsed.Get("--installation-id"),
                features: parsed.GetAll("--feature"),
                limits: parsed.GetAll("--limit"),
                status: parsed.Get("--status"),
                sequence: parsed.GetLong("--sequence"),
                activationRequired: parsed.HasFlag("--activation-required"),
                activationRecordPath: parsed.Get("--activation-record"),
                force: parsed.Force),
            "renew" => RunRenew(
                privateKeyPath: parsed.Get("--private-key"),
                licensePath: parsed.Get("--license"),
                outputPath: parsed.Get("--output"),
                issuedAt: parsed.Get("--issued-at"),
                notBefore: parsed.Get("--not-before"),
                expiresAt: parsed.Get("--expires-at"),
                validForDays: parsed.GetInt("--valid-for-days"),
                installationId: parsed.Get("--installation-id"),
                features: parsed.GetAll("--feature"),
                limits: parsed.GetAll("--limit"),
                status: parsed.Get("--status"),
                sequence: parsed.GetLong("--sequence"),
                force: parsed.Force),
            "inspect" => RunInspect(parsed.Get("--license")),
            "activate" => RunActivate(
                requestPath: parsed.Get("--request"),
                activationRecordPath: parsed.Get("--activation-record")),
            "verify" => RunVerify(
                licensePath: parsed.Get("--license"),
                publicKeyPath: parsed.Get("--public-key"),
                productId: parsed.Get("--product-id"),
                installationId: parsed.Get("--installation-id"),
                now: parsed.Get("--now"),
                expectFingerprint: parsed.Get("--expect-fingerprint"),
                highestAcceptedSequence: parsed.GetLong("--highest-accepted-sequence")),
            _ => Unknown(command)
        };
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"error: unknown command '{command}'.");
        return 1;
    }

    private static bool IsHelp(string value)
        => string.Equals(value, "help", StringComparison.Ordinal)
           || string.Equals(value, "--help", StringComparison.Ordinal)
           || string.Equals(value, "-h", StringComparison.Ordinal);

    private static void PrintHelp()
    {
        Console.WriteLine("SSP Licensing Authority tooling (offline).");
        Console.WriteLine("Manages authority key material OUTSIDE the SSP repository and issues ssp-license v1 artifacts.");
        Console.WriteLine("Never shipped with SSP. Never embeds or logs a private key.");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  keygen          Generate a production RSA-3072 authority key pair.");
        Console.WriteLine("  export-public   Export only the public key from a private key file.");
        Console.WriteLine("  fingerprint     Show / verify the public-key SPKI SHA-256 fingerprint.");
        Console.WriteLine("  issue           Sign a legacy ssp-license v1 artifact (root signs the payload).");
        Console.WriteLine("  issue-certified Sign a v2 artifact: root certifies a fresh per-license key,");
        Console.WriteLine("                  that key signs the payload; optional activation OTT + code.");
        Console.WriteLine("  renew           Re-issue an existing artifact with a higher sequence number.");
        Console.WriteLine("  inspect         Decode an artifact without verifying the signature.");
        Console.WriteLine("  verify          Validate an artifact with LicenseValidator against a public key.");
        Console.WriteLine("  activate        Validate an offline activation request against an activation");
        Console.WriteLine("                  record and print the single-use 10-digit activation code.");
        Console.WriteLine();
        Console.WriteLine("See docs/LICENSE_AUTHORITY.md.");
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    internal static int RunKeygen(string? privateKeyPath, string? publicKeyPath, bool force)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(privateKeyPath))
            {
                throw new AuthorityToolException("--private-key is required.");
            }

            EnsureWritable(privateKeyPath, force);
            if (!string.IsNullOrWhiteSpace(publicKeyPath))
            {
                EnsureWritable(publicKeyPath, force);
            }

            using var rsa = AuthorityKeyMaterial.GenerateProductionKeyPair();
            var privatePem = AuthorityKeyMaterial.ExportPrivateKeyPem(rsa);
            AuthorityKeyMaterial.WritePrivateKeyFile(privateKeyPath, privatePem, force);

            if (!string.IsNullOrWhiteSpace(publicKeyPath))
            {
                var publicPem = AuthorityKeyMaterial.ExportPublicKeyPem(rsa);
                AuthorityKeyMaterial.WritePublicKeyFile(publicKeyPath, publicPem, force);
            }

            var fingerprint = AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa);
            Console.WriteLine("Generated RSA-3072 Licensing Authority key pair.");
            Console.WriteLine($"  Private key        : {Path.GetFullPath(privateKeyPath)}");
            Console.WriteLine(string.IsNullOrWhiteSpace(publicKeyPath)
                ? "  Public key         : (not written; pass --public-key to export it)"
                : $"  Public key         : {Path.GetFullPath(publicKeyPath)}");
            Console.WriteLine($"  Key size           : {rsa.KeySize} bits");
            Console.WriteLine($"  SPKI SHA-256       : {fingerprint}");
            Console.Error.WriteLine(
                "This private key must NEVER enter the SSP repository, a build machine, CI secrets, " +
                "SSP.Server, SSP.ServiceHost, client binaries, or any shipped artifact.");
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static int RunExportPublic(string? privateKeyPath, string? outputPath, bool force)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(privateKeyPath) || string.IsNullOrWhiteSpace(outputPath))
            {
                throw new AuthorityToolException("--private-key and --output are required.");
            }

            using var rsa = AuthorityKeyMaterial.LoadPrivateKey(privateKeyPath);
            WarnIfWeak(rsa, privateKeyPath);
            var publicPem = AuthorityKeyMaterial.ExportPublicKeyPem(rsa);
            AuthorityKeyMaterial.WritePublicKeyFile(outputPath, publicPem, force);
            Console.WriteLine($"Public key written  : {Path.GetFullPath(outputPath)}");
            Console.WriteLine($"  Key size           : {rsa.KeySize} bits");
            Console.WriteLine($"  SPKI SHA-256       : {AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa)}");
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static int RunFingerprint(string? publicKeyPath, string? privateKeyPath, string? expect)
    {
        try
        {
            var hasPublic = !string.IsNullOrWhiteSpace(publicKeyPath);
            var hasPrivate = !string.IsNullOrWhiteSpace(privateKeyPath);
            if (hasPublic == hasPrivate)
            {
                throw new AuthorityToolException("Pass exactly one of --public-key or --private-key.");
            }

            int keySize;
            string fingerprint;
            string source;
            if (hasPublic)
            {
                using var rsa = AuthorityKeyMaterial.LoadPublicKey(publicKeyPath!);
                WarnIfWeak(rsa, publicKeyPath!);
                keySize = rsa.KeySize;
                fingerprint = AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa);
                source = Path.GetFullPath(publicKeyPath!);
            }
            else
            {
                using var rsa = AuthorityKeyMaterial.LoadPrivateKey(privateKeyPath!);
                WarnIfWeak(rsa, privateKeyPath!);
                keySize = rsa.KeySize;
                fingerprint = AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa);
                source = Path.GetFullPath(privateKeyPath!);
            }

            Console.WriteLine("SSP Licensing Authority public-key fingerprint");
            Console.WriteLine($"  Source             : {source}");
            Console.WriteLine($"  Key size           : {keySize} bits");
            Console.WriteLine($"  SPKI SHA-256       : {fingerprint}");

            var pin = AuthorityKeyMaterial.NormalizeFingerprint(expect);
            if (pin is null)
            {
                return 0;
            }

            if (!string.Equals(pin, fingerprint, StringComparison.Ordinal))
            {
                Console.Error.WriteLine(
                    $"error: fingerprint does not match --expect (expected sha256:{pin}, found sha256:{fingerprint}).");
                return 1;
            }

            Console.WriteLine("  Match              : yes");
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static int RunIssue(
        string? privateKeyPath,
        string? outputPath,
        string? specPath,
        string? licenseId,
        string? productId,
        string? productName,
        string? customerId,
        string? customerName,
        string? organizationName,
        string? computerName,
        string? edition,
        string? licenseVersion,
        string? issuedAt,
        string? notBefore,
        string? expiresAt,
        int? validForDays,
        string? installationId,
        string[]? features,
        string[]? limits,
        string? status,
        long? sequence,
        bool force)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(privateKeyPath) || string.IsNullOrWhiteSpace(outputPath))
            {
                throw new AuthorityToolException("--private-key and --output are required.");
            }

            var request = BuildIssueRequest(
                specPath,
                licenseId,
                productId,
                productName,
                customerId,
                customerName,
                organizationName,
                computerName,
                edition,
                licenseVersion,
                issuedAt,
                notBefore,
                expiresAt,
                validForDays,
                installationId,
                features,
                limits,
                status,
                sequence,
                defaultNow: DateTimeOffset.UtcNow);

            WarnUnknownVocabulary(request);
            if (string.IsNullOrEmpty(request.InstallationId))
            {
                Console.Error.WriteLine(
                    "warning: issuing a floating license (no --installation-id). " +
                    "Production SSP licenses should be bound to the customer's installation id.");
            }

            var payload = LicenseIssuance.ToPayload(request);
            using var rsa = AuthorityKeyMaterial.LoadPrivateKey(privateKeyPath);
            WarnIfWeak(rsa, privateKeyPath);
            var artifact = LicenseIssuance.Issue(payload, rsa);
            AuthorityKeyMaterial.WriteArtifactFile(outputPath, artifact, force);

            Console.WriteLine($"License issued       : {Path.GetFullPath(outputPath)}");
            Console.WriteLine($"  Signature algorithm : {SignatureAlgorithms.RsaPssSha256}");
            Console.WriteLine($"  Authority SPKI SHA-256 : {AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa)}");
            Console.Write(LicenseIssuance.DescribePayload(payload));
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static int RunRenew(
        string? privateKeyPath,
        string? licensePath,
        string? outputPath,
        string? issuedAt,
        string? notBefore,
        string? expiresAt,
        int? validForDays,
        string? installationId,
        string[]? features,
        string[]? limits,
        string? status,
        long? sequence,
        bool force)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(privateKeyPath) ||
                string.IsNullOrWhiteSpace(licensePath) ||
                string.IsNullOrWhiteSpace(outputPath))
            {
                throw new AuthorityToolException("--private-key, --license and --output are required.");
            }

            var artifactJson = ReadArtifact(licensePath);
            if (!LicenseArtifactCodec.TryDecode(artifactJson, out var artifact, out var decodeError) || artifact is null)
            {
                throw new AuthorityToolException(
                    decodeError is null
                        ? "Existing license could not be decoded."
                        : $"Existing license could not be decoded ({decodeError.Code}): {decodeError.Detail}");
            }

            using var rsa = AuthorityKeyMaterial.LoadPrivateKey(privateKeyPath);
            WarnIfWeak(rsa, privateKeyPath);
            if (!LicenseIssuance.SignatureMatches(artifactJson, rsa, out var signatureError))
            {
                throw new AuthorityToolException(
                    "Refusing to renew: " + (signatureError ?? "the existing artifact is not signed by --private-key") +
                    ". Re-signing a foreign or tampered payload would mint a real authority signature over untrusted fields.");
            }

            var original = artifact.Payload;
            var now = DateTimeOffset.UtcNow;
            var newIssuedAt = string.IsNullOrWhiteSpace(issuedAt) ? now : LicenseIssuance.ParseTimestamp(issuedAt, "issuedAt");
            var newNotBefore = string.IsNullOrWhiteSpace(notBefore) ? newIssuedAt : LicenseIssuance.ParseTimestamp(notBefore, "notBefore");
            DateTimeOffset newExpiresAt;
            if (!string.IsNullOrWhiteSpace(expiresAt))
            {
                newExpiresAt = LicenseIssuance.ParseTimestamp(expiresAt, "expiresAt");
            }
            else if (validForDays is not null)
            {
                if (validForDays.Value <= 0)
                {
                    throw new AuthorityToolException("--valid-for-days must be a positive integer.");
                }

                newExpiresAt = newNotBefore.AddDays(validForDays.Value);
            }
            else
            {
                newExpiresAt = original.ExpiresAt;
            }

            var newSequence = sequence ?? checked(original.SequenceNumber + 1);
            if (newSequence <= original.SequenceNumber)
            {
                throw new AuthorityToolException(
                    $"Renewal sequence {newSequence} must be greater than the original sequence {original.SequenceNumber} (anti-rollback).");
            }

            var newFeatures = HasValues(features)
                ? features!
                : original.FeatureSet.Values.ToArray();
            var newLimits = HasValues(limits)
                ? limits!.Select(LicenseIssuance.ParseLimit).ToArray()
                : original.Limits.Entries.Select(e => new KeyValuePair<string, long?>(e.Name, e.Max)).ToArray();
            var newStatus = string.IsNullOrWhiteSpace(status) ? original.Status : LicenseIssuance.ParseStatus(status);
            var newInstallationId = installationId ?? original.InstallationId;

            var request = new LicenseIssueRequest
            {
                LicenseId = Guid.NewGuid(),
                ProductId = original.ProductId,
                ProductName = original.ProductName,
                CustomerId = original.CustomerId,
                CustomerName = original.CustomerName,
                Edition = original.Edition,
                LicenseVersion = original.LicenseVersion,
                IssuedAt = newIssuedAt,
                NotBefore = newNotBefore,
                ExpiresAt = newExpiresAt,
                InstallationId = newInstallationId,
                Features = newFeatures,
                Limits = newLimits,
                Status = newStatus,
                SequenceNumber = newSequence
            };

            WarnUnknownVocabulary(request);
            var payload = LicenseIssuance.ToPayload(request);
            var issued = LicenseIssuance.Issue(payload, rsa);
            AuthorityKeyMaterial.WriteArtifactFile(outputPath, issued, force);

            Console.WriteLine($"License renewed      : {Path.GetFullPath(outputPath)}");
            Console.WriteLine($"  Replaces           : {original.LicenseId:D} (sequence {original.SequenceNumber})");
            Console.WriteLine($"  Signature algorithm : {SignatureAlgorithms.RsaPssSha256}");
            Console.WriteLine($"  Authority SPKI SHA-256 : {AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa)}");
            Console.Write(LicenseIssuance.DescribePayload(payload));
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        catch (OverflowException)
        {
            Console.Error.WriteLine("error: sequence number overflow.");
            return 1;
        }
    }

    internal static int RunIssueCertified(
        string? privateKeyPath,
        string? outputPath,
        string? specPath,
        string? licenseId,
        string? productId,
        string? productName,
        string? customerId,
        string? customerName,
        string? organizationName,
        string? computerName,
        string? edition,
        string? licenseVersion,
        string? issuedAt,
        string? notBefore,
        string? expiresAt,
        int? validForDays,
        string? installationId,
        string[]? features,
        string[]? limits,
        string? status,
        long? sequence,
        bool activationRequired,
        string? activationRecordPath,
        bool force)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(privateKeyPath) || string.IsNullOrWhiteSpace(outputPath))
            {
                throw new AuthorityToolException("--private-key and --output are required.");
            }

            if (activationRequired && string.IsNullOrWhiteSpace(activationRecordPath))
            {
                throw new AuthorityToolException("--activation-record is required when --activation-required is set.");
            }

            // Refuse to overwrite existing files up front (both deliverables), so a
            // half-issued license (artifact written, activation record refused) cannot happen.
            EnsureWritable(outputPath, force);
            if (activationRequired)
            {
                EnsureWritable(activationRecordPath!, force);
            }

            var request = BuildIssueRequest(
                specPath, licenseId, productId, productName, customerId, customerName,
                organizationName, computerName, edition, licenseVersion, issuedAt, notBefore,
                expiresAt, validForDays, installationId, features, limits, status, sequence,
                defaultNow: DateTimeOffset.UtcNow);

            WarnUnknownVocabulary(request);
            if (string.IsNullOrEmpty(request.InstallationId))
            {
                Console.Error.WriteLine(
                    "warning: issuing a floating license (no --installation-id). " +
                    "Production SSP licenses should be bound to the customer's installation id.");
            }

            var payload = LicenseIssuance.ToPayload(request);
            using var authorityKey = AuthorityKeyMaterial.LoadPrivateKey(privateKeyPath);
            WarnIfWeak(authorityKey, privateKeyPath);

            // A fresh per-license leaf key pair. The private half never leaves this process
            // and is never persisted, so a later license gets its own independent key.
            using var leafKey = RSA.Create(AuthorityKeyMaterial.MinimumKeySizeBits);

            string? activationOtt = null;
            string? activationCodeHash = null;
            string? activationCode = null;
            if (activationRequired)
            {
                activationOtt = LicenseActivation.GenerateActivationOtt();
                activationCode = LicenseActivation.GenerateActivationCode();
                activationCodeHash = LicenseActivation.ComputeActivationCodeHash(activationCode);
            }

            // The certification binds exactly this license identity to the leaf public key,
            // and carries the activation material the customer cannot replace (it is signed).
            var certification = new LicenseKeyCertification
            {
                LicenseId = payload.LicenseId,
                ProductId = payload.ProductId,
                CustomerId = payload.CustomerId,
                NotBefore = payload.IssuedAt,
                ExpiresAt = payload.ExpiresAt,
                PublicKeySpkiDer = leafKey.ExportSubjectPublicKeyInfo(),
                ActivationOtt = activationOtt,
                ActivationCodeHash = activationCodeHash
            };

            var artifact = LicenseCertificationIssuer.EncodeCertifiedLicenseArtifact(
                payload, certification, authorityKey, leafKey);
            AuthorityKeyMaterial.WriteArtifactFile(outputPath, artifact, force);

            Console.WriteLine($"License issued (certified) : {Path.GetFullPath(outputPath)}");
            Console.WriteLine($"  Signature algorithm        : {SignatureAlgorithms.RsaPssSha256}");
            Console.WriteLine($"  Authority SPKI SHA-256     : {AuthorityKeyMaterial.ComputeSpkiSha256Hex(authorityKey)}");
            Console.WriteLine($"  Leaf SPKI SHA-256          : {AuthorityKeyMaterial.ComputeSpkiSha256Hex(leafKey)}");

            if (activationRequired)
            {
                ActivationRecordStore.Save(activationRecordPath!, new ActivationRecord
                {
                    LicenseId = payload.LicenseId,
                    ActivationOtt = activationOtt!,
                    ActivationCode = activationCode!
                }, force);

                Console.WriteLine($"  Activation record          : {Path.GetFullPath(activationRecordPath!)}");
                Console.WriteLine($"  Activation code            : {activationCode}");
                Console.WriteLine(
                    "The activation record is authority secret material. Keep it with the authority " +
                    "private key - outside the repository, the build and every customer artifact.");
            }

            Console.Write(LicenseIssuance.DescribePayload(payload));
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static int RunActivate(string? requestPath, string? activationRecordPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(requestPath) || string.IsNullOrWhiteSpace(activationRecordPath))
            {
                throw new AuthorityToolException("--request and --activation-record are required.");
            }

            var requestJson = AuthorityKeyMaterial.ReadTextFile(requestPath, "activation request");
            if (!ActivationRequestCodec.TryDecode(requestJson, out var request, out var requestError) || request is null)
            {
                throw new AuthorityToolException(
                    requestError is null
                        ? "Activation request could not be decoded."
                        : $"Activation request could not be decoded: {requestError.Detail}");
            }

            var record = ActivationRecordStore.Load(activationRecordPath);

            if (record.LicenseId != request.LicenseId)
            {
                throw new AuthorityToolException(
                    $"The activation record is for license {record.LicenseId:D}, but the request is for license {request.LicenseId:D}. Refusing.");
            }

            if (record.Consumed)
            {
                throw new AuthorityToolException(
                    "This activation record has already been consumed. Activation is single-use; issue a new activation-required license for a new code.");
            }

            // Constant-time OTT comparison. The OTT's authority comes from the authority's
            // own record; a forged or replayed request simply does not match.
            if (!LicenseActivation.OttMatches(record.ActivationOtt, request.ActivationOtt))
            {
                throw new AuthorityToolException("The activation OTT in the request does not match this activation record. Refusing.");
            }

            // Consume ONLY after successful validation (single-use, not consumed before activation).
            var consumedAt = DateTimeOffset.UtcNow;
            ActivationRecordStore.Save(activationRecordPath, record.MarkConsumed(consumedAt), overwrite: true);

            Console.WriteLine("SSP license activation");
            Console.WriteLine($"  LicenseId : {record.LicenseId:D}");
            Console.WriteLine($"  Consumed  : {ActivationRecordStore.FormatTime(consumedAt)}");
            Console.WriteLine($"  Code      : {record.ActivationCode}");
            Console.WriteLine("Give this 10-digit code to the customer. Each code is single-use.");
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static int RunInspect(string? licensePath)
    {
        try
        {
            var artifactJson = ReadArtifact(licensePath);
            if (!LicenseArtifactCodec.TryDecode(artifactJson, out var artifact, out var decodeError) || artifact is null)
            {
                Console.Error.WriteLine(
                    decodeError is null
                        ? "error: license artifact could not be decoded."
                        : $"error: license artifact could not be decoded ({decodeError.Code}): {decodeError.Detail}");
                return 1;
            }

            Console.WriteLine("SSP license artifact (decoded, NOT verified)");
            Console.Write(LicenseIssuance.DescribePayload(
                artifact.Payload,
                artifact.SignatureAlgorithm,
                artifact.Signature.Length));
            Console.Error.WriteLine(
                "This report does not prove the signature. Use 'verify --license ... --public-key ...' to validate.");
            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static int RunVerify(
        string? licensePath,
        string? publicKeyPath,
        string? productId,
        string? installationId,
        string? now,
        string? expectFingerprint,
        long? highestAcceptedSequence)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(licensePath) || string.IsNullOrWhiteSpace(publicKeyPath))
            {
                throw new AuthorityToolException("--license and --public-key are required.");
            }

            var artifactJson = ReadArtifact(licensePath);
            using var rsa = AuthorityKeyMaterial.LoadPublicKey(publicKeyPath);
            WarnIfWeak(rsa, publicKeyPath);

            var fingerprint = AuthorityKeyMaterial.ComputeSpkiSha256Hex(rsa);
            var pin = AuthorityKeyMaterial.NormalizeFingerprint(expectFingerprint);
            if (pin is not null && !string.Equals(pin, fingerprint, StringComparison.Ordinal))
            {
                throw new AuthorityToolException(
                    $"Public key does not match --expect-fingerprint (expected sha256:{pin}, found sha256:{fingerprint}).");
            }

            Guid? expectedProduct = string.IsNullOrWhiteSpace(productId)
                ? AuthorityProduct.ProductId
                : LicenseIssuance.ParseGuid(productId, "productId");
            DateTimeOffset? clock = string.IsNullOrWhiteSpace(now)
                ? null
                : LicenseIssuance.ParseTimestamp(now, "now");

            var result = LicenseIssuance.Validate(
                artifactJson,
                rsa,
                expectedProduct,
                string.IsNullOrWhiteSpace(installationId) ? null : installationId,
                clock,
                highestAcceptedSequence);

            Console.WriteLine("SSP license verification");
            Console.WriteLine($"  State               : {result.State}");
            Console.WriteLine($"  Reason              : {result.ReasonCode}");
            if (!string.IsNullOrWhiteSpace(result.Detail))
            {
                Console.WriteLine($"  Detail              : {result.Detail}");
            }

            Console.WriteLine($"  Trust anchor        : rsa-{rsa.KeySize} sha256:{fingerprint}");
            Console.WriteLine($"  Expected product    : {expectedProduct:D}");
            if (result.License is not null)
            {
                Console.Write(LicenseIssuance.DescribePayload(result.License.Payload, result.License.SignatureAlgorithm));
            }

            if (!result.IsValid)
            {
                Console.Error.WriteLine($"error: license is not valid ({result.State} / {result.ReasonCode}).");
                return 1;
            }

            return 0;
        }
        catch (AuthorityToolException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static LicenseIssueRequest BuildIssueRequest(
        string? specPath,
        string? licenseId,
        string? productId,
        string? productName,
        string? customerId,
        string? customerName,
        string? organizationName,
        string? computerName,
        string? edition,
        string? licenseVersion,
        string? issuedAt,
        string? notBefore,
        string? expiresAt,
        int? validForDays,
        string? installationId,
        string[]? features,
        string[]? limits,
        string? status,
        long? sequence,
        DateTimeOffset defaultNow)
    {
        LicenseIssueSpecDocument? spec = string.IsNullOrWhiteSpace(specPath)
            ? null
            : LicenseIssuance.LoadSpec(specPath);

        var resolvedLicenseId = FirstGuid(licenseId, spec?.LicenseId, "licenseId") ?? Guid.NewGuid();
        var resolvedProductId = FirstGuid(productId, spec?.ProductId, "productId") ?? AuthorityProduct.ProductId;
        var resolvedProductName = FirstString(productName, spec?.ProductName) ?? AuthorityProduct.ProductName;
        var resolvedCustomerId = FirstGuid(customerId, spec?.CustomerId, "customerId")
            ?? throw new AuthorityToolException("--customer-id is required (or supply customerId in --spec).");
        var resolvedCustomerName = FirstString(customerName, spec?.CustomerName)
            ?? throw new AuthorityToolException("--customer-name is required (or supply customerName in --spec).");
        var resolvedOrganization = FirstString(organizationName, spec?.OrganizationName);
        var resolvedComputer = FirstString(computerName, spec?.ComputerName);
        var resolvedEdition = FirstString(edition, spec?.Edition)
            ?? throw new AuthorityToolException("--edition is required (or supply edition in --spec).");
        var resolvedVersion = FirstString(licenseVersion, spec?.LicenseVersion) ?? "1.0";

        var resolvedIssuedAt = FirstTimestamp(issuedAt, spec?.IssuedAt, "issuedAt") ?? defaultNow;
        var resolvedNotBefore = FirstTimestamp(notBefore, spec?.NotBefore, "notBefore") ?? resolvedIssuedAt;

        DateTimeOffset? resolvedExpires = FirstTimestamp(expiresAt, spec?.ExpiresAt, "expiresAt");
        var days = validForDays ?? spec?.ValidForDays;
        if (resolvedExpires is null)
        {
            if (days is null)
            {
                throw new AuthorityToolException("--expires-at or --valid-for-days is required (or supply expiresAt / validForDays in --spec).");
            }

            if (days.Value <= 0)
            {
                throw new AuthorityToolException("--valid-for-days must be a positive integer.");
            }

            resolvedExpires = resolvedNotBefore.AddDays(days.Value);
        }

        var resolvedInstallation = installationId ?? spec?.InstallationId;
        var resolvedFeatures = HasValues(features) ? features! : spec?.Features ?? Array.Empty<string>();
        IReadOnlyList<KeyValuePair<string, long?>> resolvedLimits;
        if (HasValues(limits))
        {
            resolvedLimits = limits!.Select(LicenseIssuance.ParseLimit).ToArray();
        }
        else if (spec?.Limits is not null)
        {
            resolvedLimits = spec.Limits.Select(kv => new KeyValuePair<string, long?>(kv.Key, kv.Value)).ToArray();
        }
        else
        {
            resolvedLimits = Array.Empty<KeyValuePair<string, long?>>();
        }

        var resolvedStatus = LicenseIssuance.ParseStatus(status ?? spec?.Status);
        var resolvedSequence = sequence ?? spec?.SequenceNumber ?? 1;

        return new LicenseIssueRequest
        {
            LicenseId = resolvedLicenseId,
            ProductId = resolvedProductId,
            ProductName = resolvedProductName,
            CustomerId = resolvedCustomerId,
            CustomerName = resolvedCustomerName,
            OrganizationOrPersonName = resolvedOrganization,
            ComputerName = resolvedComputer,
            Edition = resolvedEdition,
            LicenseVersion = resolvedVersion,
            IssuedAt = resolvedIssuedAt,
            NotBefore = resolvedNotBefore,
            ExpiresAt = resolvedExpires.Value,
            InstallationId = resolvedInstallation,
            Features = resolvedFeatures,
            Limits = resolvedLimits,
            Status = resolvedStatus,
            SequenceNumber = resolvedSequence
        };
    }

    private static Guid? FirstGuid(string? flag, Guid? spec, string field)
    {
        if (!string.IsNullOrWhiteSpace(flag))
        {
            return LicenseIssuance.ParseGuid(flag, field);
        }

        if (spec is { } value && value != Guid.Empty)
        {
            return value;
        }

        return null;
    }

    private static string? FirstString(string? flag, string? spec)
    {
        if (!string.IsNullOrWhiteSpace(flag))
        {
            return flag.Trim();
        }

        return string.IsNullOrWhiteSpace(spec) ? null : spec.Trim();
    }

    private static DateTimeOffset? FirstTimestamp(string? flag, string? spec, string field)
    {
        if (!string.IsNullOrWhiteSpace(flag))
        {
            return LicenseIssuance.ParseTimestamp(flag, field);
        }

        if (!string.IsNullOrWhiteSpace(spec))
        {
            return LicenseIssuance.ParseTimestamp(spec, field);
        }

        return null;
    }

    private static bool HasValues(string[]? values)
        => values is { Length: > 0 };

    private static string ReadArtifact(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new AuthorityToolException("--license is required.");
        }

        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
        {
            throw new AuthorityToolException($"License artifact was not found: {full}");
        }

        var info = new FileInfo(full);
        if (info.Length > LicenseArtifactCodec.MaxArtifactCharacters)
        {
            throw new AuthorityToolException(
                $"License artifact exceeds the maximum size of {LicenseArtifactCodec.MaxArtifactCharacters} characters.");
        }

        var text = File.ReadAllText(full);
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new AuthorityToolException($"License artifact '{full}' is empty.");
        }

        return text;
    }

    private static void WarnIfWeak(RSA rsa, string source)
    {
        if (!AuthorityKeyMaterial.IsBelowRecommendedSize(rsa))
        {
            return;
        }

        Console.Error.WriteLine(
            $"warning: RSA key from {source} is {rsa.KeySize} bits; " +
            $"the SSP key ceremony mandates RSA-{AuthorityKeyMaterial.ProductionKeySizeBits}.");
    }

    private static void WarnUnknownVocabulary(LicenseIssueRequest request)
    {
        var unknownFeatures = LicenseIssuance.UnknownFeatures(request.Features).ToArray();
        if (unknownFeatures.Length > 0)
        {
            Console.Error.WriteLine(
                "warning: feature name(s) not in the SSP host vocabulary " +
                $"({string.Join(", ", AuthorityProduct.KnownFeatures)}): {string.Join(", ", unknownFeatures)}.");
        }

        var unknownLimits = LicenseIssuance.UnknownLimits(request.Limits.Select(l => l.Key)).ToArray();
        if (unknownLimits.Length > 0)
        {
            Console.Error.WriteLine(
                "warning: limit name(s) not in the SSP host vocabulary: " + string.Join(", ", unknownLimits) + ".");
        }
    }

    private static void EnsureWritable(string path, bool force)
    {
        var full = Path.GetFullPath(path);
        if (File.Exists(full) && !force)
        {
            throw new AuthorityToolException(
                $"Refusing to overwrite existing file '{full}'. Pass --force to replace it.");
        }
    }

    private sealed class ParsedArgs
    {
        private readonly Dictionary<string, List<string>> _options = new(StringComparer.Ordinal);
        private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

        public bool Force => HasFlag("--force") || HasFlag("-f");

        public static ParsedArgs Parse(ReadOnlySpan<string> args)
        {
            var parsed = new ParsedArgs();
            for (var i = 0; i < args.Length; i++)
            {
                var token = args[i];
                if (string.IsNullOrEmpty(token) || token[0] != '-')
                {
                    throw new AuthorityToolException($"Unexpected argument '{token}'.");
                }

                string name;
                string? inlineValue = null;
                if (token.StartsWith("--", StringComparison.Ordinal) && token.Contains('=', StringComparison.Ordinal))
                {
                    var split = token.IndexOf('=');
                    name = token[..split];
                    inlineValue = token[(split + 1)..];
                }
                else
                {
                    name = token;
                }

                if (FlagNames.Contains(name))
                {
                    parsed._flags.Add(name);
                    continue;
                }

                if (!name.StartsWith("--", StringComparison.Ordinal) || !KnownOptionNames.Contains(name))
                {
                    throw new AuthorityToolException($"Unknown option '{name}'.");
                }

                string value;
                if (inlineValue is not null)
                {
                    value = inlineValue;
                }
                else
                {
                    if (i + 1 >= args.Length)
                    {
                        throw new AuthorityToolException($"Option '{name}' requires a value.");
                    }

                    value = args[++i];
                    if (value.StartsWith("--", StringComparison.Ordinal) && value != "--")
                    {
                        throw new AuthorityToolException($"Option '{name}' requires a value.");
                    }
                }

                parsed.Add(name, value);
            }

            return parsed;
        }

        public bool HasFlag(string name) => _flags.Contains(name);

        public string? Get(string name)
            => _options.TryGetValue(name, out var values) && values.Count > 0 ? values[^1] : null;

        public string[]? GetAll(string name)
            => _options.TryGetValue(name, out var values) && values.Count > 0 ? values.ToArray() : null;

        public int? GetInt(string name)
        {
            var raw = Get(name);
            if (raw is null)
            {
                return null;
            }

            if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            {
                throw new AuthorityToolException($"{name} must be an integer.");
            }

            return value;
        }

        public long? GetLong(string name)
        {
            var raw = Get(name);
            if (raw is null)
            {
                return null;
            }

            if (!long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            {
                throw new AuthorityToolException($"{name} must be an integer.");
            }

            return value;
        }

        private void Add(string name, string value)
        {
            if (!_options.TryGetValue(name, out var list))
            {
                list = new List<string>();
                _options[name] = list;
            }

            list.Add(value);
        }
    }
}
