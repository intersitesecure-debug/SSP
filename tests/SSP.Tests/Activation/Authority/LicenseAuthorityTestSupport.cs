// File: tests/SSP.Tests/Activation/Authority/LicenseAuthorityTestSupport.cs
//
// In-process harness for the P4 Licensing Authority CLI. Every key this
// helper produces is ephemeral, lives under Path.GetTempPath(), and is
// deleted with the workspace. No production authority material is used.

using System.Security.Cryptography;
using SSP.Core.Activation;
using SSP.LicenseAuthority;
using SSP.Server.Activation;

namespace SSP.Tests.Activation.Authority;

internal sealed class AuthorityWorkspace : IDisposable
{
    private bool _disposed;

    public AuthorityWorkspace()
    {
        Root = Path.Combine(Path.GetTempPath(), "ssp-authority-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
    }

    public string Root { get; }

    public string PathTo(string name) => Path.Combine(Root, name);

    public async Task<(int Exit, string Stdout, string Stderr)> Run(params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await LicenseAuthorityCli.RunAsync(args, stdout, stderr);
        return (exit, stdout.ToString(), stderr.ToString());
    }

    public void Write(string name, string contents) => File.WriteAllText(PathTo(name), contents);

    public string Read(string name) => File.ReadAllText(PathTo(name));

    public bool Exists(string name) => File.Exists(PathTo(name));

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
        catch
        {
            // Temp cleanup must never fail a test.
        }
    }
}

/// <summary>
/// Ephemeral RSA keys for authority-tool tests. 2048-bit keys are used for
/// the bulk of the suite (the library floor); a 3072-bit pair is generated
/// once per process for tests that exercise the production key size.
/// Nothing is written to disk until a test asks for it.
/// </summary>
internal static class EphemeralAuthorityKeys
{
    private static readonly Lazy<RsaPemPair> Lazy3072 = new(() => Create(3072), isThreadSafe: true);

    public static RsaPemPair ProductionSized => Lazy3072.Value;

    public static RsaPemPair Create(int keySizeBits)
    {
        using var rsa = RSA.Create(keySizeBits);
        return new RsaPemPair(
            rsa.ExportPkcs8PrivateKeyPem(),
            rsa.ExportSubjectPublicKeyInfoPem(),
            SspTrustAnchor.ComputeFingerprint(rsa.ExportSubjectPublicKeyInfo()),
            rsa.KeySize);
    }

    public static RsaPemPair CreateForeign() => Create(2048);
}

internal sealed record RsaPemPair(string PrivatePem, string PublicPem, string Fingerprint, int KeySizeBits);

internal static class AuthorityTestPayload
{
    public static readonly DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);

    public static string[] DefaultIssueArgs(
        string privateKey,
        string output,
        Guid? customerId = null,
        Guid? productId = null,
        string? installationId = "INSTALLATION-A",
        string expiresAt = "2031-01-01T00:00:00Z",
        string notBefore = "2030-01-01T00:00:00Z",
        string issuedAt = "2029-12-01T00:00:00Z",
        string? status = null,
        long? sequence = null,
        string[]? features = null,
        string[]? limits = null,
        bool force = false)
    {
        var args = new List<string>
        {
            "issue",
            "--private-key", privateKey,
            "--output", output,
            "--customer-id", (customerId ?? Guid.NewGuid()).ToString("D"),
            "--customer-name", "Authority Test Customer",
            "--edition", "Enterprise",
            "--product-id", (productId ?? SspLicensing.ProductId).ToString("D"),
            "--issued-at", issuedAt,
            "--not-before", notBefore,
            "--expires-at", expiresAt,
        };

        if (!string.IsNullOrEmpty(installationId))
        {
            args.Add("--installation-id");
            args.Add(installationId);
        }

        foreach (var feature in features ?? new[] { "rdp", "ssh", "web", "sql" })
        {
            args.Add("--feature");
            args.Add(feature);
        }

        foreach (var limit in limits ?? new[] { "max_services=3", "max_clients=10", "max_concurrent_tunnels=5" })
        {
            args.Add("--limit");
            args.Add(limit);
        }

        if (!string.IsNullOrEmpty(status))
        {
            args.Add("--status");
            args.Add(status);
        }

        if (sequence is not null)
        {
            args.Add("--sequence");
            args.Add(sequence.Value.ToString());
        }

        if (force)
        {
            args.Add("--force");
        }

        return args.ToArray();
    }

    public static string? FindRepositoryRoot()
    {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "SSP.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return null;
    }

    public static bool ContainsSecretMaterial(string text)
        => text.Contains("BEGIN", StringComparison.Ordinal)
           || text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase)
           || text.Contains("PUBLIC KEY", StringComparison.Ordinal);
}
