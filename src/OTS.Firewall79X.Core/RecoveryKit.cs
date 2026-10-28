using System.Security.Cryptography;
using System.Text;

namespace OTS.Firewall79X.Core;

// Creates a locally protected, printable recovery bundle. Does not manufacture bootable Windows media.
// The installed UAC recovery executable remains the supported, primary recovery route.
public static class RecoveryKit
{
    public sealed record Result(string Directory, bool IncludesRecoveryExecutable, int ConfigurationFiles, string ManifestPath);
    public static Result Create(string kitDirectory, string installedDirectory, string serviceDataDirectory)
    {
        Directory.CreateDirectory(kitDirectory);
        var manifest = new StringBuilder();
        manifest.AppendLine("# OTS Firewall79X local recovery kit");
        manifest.AppendLine($"Generated: {DateTimeOffset.UtcNow:O}");
        manifest.AppendLine("SHA-256 hashes detect accidental corruption, but do not authenticate the publisher.");
        manifest.AppendLine("Do not upload this folder publicly: configuration exports can include sensitive system details.");
        manifest.AppendLine("\n| File | SHA-256 |");
        manifest.AppendLine("|---|---|");

        int copies = 0; bool hasRecovery = false;
        foreach (var filename in new[] { "changes.json", "pre-activation.json" })
        {
            var source = Path.Combine(serviceDataDirectory, filename);
            if (!File.Exists(source)) continue;
            var info = new FileInfo(source);
            if (info.Length > 256 * 1024 || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException("Recovery data outside size/link safety budget");
            CopyChecked(source, Path.Combine(kitDirectory, filename), manifest);
            copies++;
        }

        const string recovery = "OTS.Firewall79X.Recovery.exe";
        var executable = Path.Combine(installedDirectory, recovery);
        if (File.Exists(executable))
        {
            var info = new FileInfo(executable);
            if (info.Length > 128 * 1024 * 1024 || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException("Recovery executable is outside safety budget");
            CopyChecked(executable, Path.Combine(kitDirectory, recovery), manifest);
            hasRecovery = true;
        }

        const string instructions = @"# OTS Firewall79X — printable recovery
1. If the desktop application works, select Restore Previous Configuration.
2. If it fails, run the installed OTS Firewall79X Recovery executable with Windows administrator approval.
3. If needed, stop the OTS Firewall79X service using Windows Services, then run the separate recovery executable with --restore. It restores only allowlisted OTS-owned changes when their current values still match OTS writes.
4. Inspect changes.json for prepared or applied changes and pre-activation.json for the original AutoRun state. Do not manually import old registry state over later third-party changes.
5. If the system will not boot, enter Windows Recovery or Safe Mode using Microsoft's supported recovery process; the installed executable may not run in WinRE. Restore from a known-good OS image when necessary.
6. Verify this kit's checksums and the executable's trusted digital signature independently before using a copied binary. A matching checksum alone is not publisher authentication.

This folder is NOT a bootable recovery image, not an offline registry editor, and is not guaranteed to function if Windows cannot start. Do not delete unrelated Windows firewall rules.";
        AtomicFile.Write(Path.Combine(kitDirectory, "RECOVERY_INSTRUCTIONS.md"), instructions + Environment.NewLine);
        // Never include machine-specific paths or an execution-policy bypass in the helper script.
        const string script = @"# Run from an elevated PowerShell session; do not bypass Windows security policies.
$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot 'OTS.Firewall79X.Recovery.exe'
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'Recovery executable is missing; use the installed Start menu recovery tool.' }
& $tool --restore
if ($LASTEXITCODE -ne 0) { throw ('Recovery returned exit code ' + $LASTEXITCODE) }
";
        AtomicFile.Write(Path.Combine(kitDirectory, "RESTORE_OWNED_SETTINGS.ps1"), script);
        var manifestPath = Path.Combine(kitDirectory, "MANIFEST.md");
        AtomicFile.Write(manifestPath, manifest.ToString());
        return new(kitDirectory, hasRecovery, copies, manifestPath);
    }

    private static void CopyChecked(string source, string target, StringBuilder manifest)
    {
        var staging = target + "." + Guid.NewGuid().ToString("N") + ".partial";
        try
        {
            File.Copy(source, staging, false);
            byte[] original, copy;
            using (var s = File.OpenRead(source)) original = SHA256.HashData(s);
            using (var s = File.OpenRead(staging)) copy = SHA256.HashData(s);
            if (!CryptographicOperations.FixedTimeEquals(original, copy))
                throw new InvalidDataException("Recovery kit copy failed verification");
            File.Move(staging, target, true); // replace an older OTS-owned copy; never modify source
            manifest.AppendLine($"| {Path.GetFileName(target)} | {Convert.ToHexString(copy)} |");
        }
        finally { if (File.Exists(staging)) File.Delete(staging); }
    }
}
