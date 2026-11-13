using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Verification-only update gate. A trust anchor MUST be provisioned out of band;
/// a key, checksum, certificate or URL delivered in the same manifest is untrusted.
/// This component never executes or installs received files.
/// </summary>
public static class TrustedArtifacts
{
    public sealed record Envelope(string PayloadBase64, string SignatureBase64);
    public sealed record Artifact(string Name, long Length, string Sha256);
    public sealed record Manifest(string Product, string Version, DateTimeOffset IssuedUtc,
        DateTimeOffset ExpiresUtc, string Kind, List<Artifact> Files);

    public static Manifest Verify(string envelopeJson, byte[] pinnedSubjectPublicKeyInfo,
        string stagedDirectory, Version minimumVersion, DateTimeOffset now)
    {
        if (pinnedSubjectPublicKeyInfo is null || pinnedSubjectPublicKeyInfo.Length is < 70 or > 4096)
            throw new InvalidDataException("Missing or invalid pre-provisioned publisher trust anchor");
        if (envelopeJson is null || Encoding.UTF8.GetByteCount(envelopeJson) > 64 * 1024)
            throw new InvalidDataException("Signed envelope exceeds size limit");
        var envelope = JsonSerializer.Deserialize<Envelope>(envelopeJson, Wire.Json)
            ?? throw new InvalidDataException("Signed envelope is empty");
        byte[] payload, signature;
        try
        {
            payload = Convert.FromBase64String(envelope.PayloadBase64);
            signature = Convert.FromBase64String(envelope.SignatureBase64);
        }
        catch (FormatException ex) { throw new InvalidDataException("Invalid base64 in signed envelope", ex); }
        if (payload.Length is < 2 or > 32 * 1024 || signature.Length is < 64 or > 256)
            throw new InvalidDataException("Invalid signed manifest/signature length");
        using (var signer = ECDsa.Create())
        {
            signer.ImportSubjectPublicKeyInfo(pinnedSubjectPublicKeyInfo, out int consumed);
            if (consumed != pinnedSubjectPublicKeyInfo.Length || signer.KeySize != 256 ||
                !signer.VerifyData(payload, signature, HashAlgorithmName.SHA256))
                throw new CryptographicException("Publisher signature verification failed");
        }
        var manifest = JsonSerializer.Deserialize<Manifest>(payload, Wire.Json)
            ?? throw new InvalidDataException("Signed payload is empty");
        if (manifest.Product != "OTS Firewall79X" || manifest.Kind is not ("software" or "feed") ||
            !Version.TryParse(manifest.Version, out var version) || version < minimumVersion ||
            manifest.IssuedUtc > now.AddMinutes(5) || manifest.ExpiresUtc <= now ||
            manifest.ExpiresUtc <= manifest.IssuedUtc ||
            manifest.ExpiresUtc - manifest.IssuedUtc > TimeSpan.FromDays(90))
            throw new InvalidDataException("Publisher, kind, version, or validity window rejected");
        if (manifest.Files is null || manifest.Files.Count is < 1 or > 128)
            throw new InvalidDataException("Signed file inventory is missing or too large");

        var root = Path.GetFullPath(stagedDirectory);
        if (!Directory.Exists(root))
            throw new InvalidDataException("Staging directory does not exist");
        for (var ancestor = new DirectoryInfo(root); ancestor != null; ancestor = ancestor.Parent)
            if ((ancestor.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Reparse point in signed staging path");
        // Signed inventory must be exact. An unlisted DLL, script or nested folder
        // in the staging directory is NOT trusted by this manifest.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long cumulativeBytes = 0;
        foreach (var entry in manifest.Files)
        {
            if (entry.Name is null || entry.Name.Length is < 1 or > 128 ||
                entry.Name is "." or ".." || Path.GetFileName(entry.Name) != entry.Name ||
                entry.Name.Contains('/') || entry.Name.Contains('\\') ||
                entry.Name.Contains(':') || entry.Name != entry.Name.Trim() ||
                entry.Name.EndsWith('.') || entry.Name.Any(c => c < 32 ||
                    c is '<' or '>' or '"' or '|' or '?' or '*') ||
                IsReservedWindowsFilename(entry.Name) || !seen.Add(entry.Name) ||
                entry.Length is < 1 or > 256 * 1024 * 1024 ||
                entry.Sha256 is null || entry.Sha256.Length != 64)
                throw new InvalidDataException("Unsafe signed file inventory");
            cumulativeBytes = checked(cumulativeBytes + entry.Length);
            if (cumulativeBytes > 512L * 1024 * 1024)
                throw new InvalidDataException("Signed package cumulative size budget exceeded");
            byte[] expected;
            try { expected = Convert.FromHexString(entry.Sha256); }
            catch (FormatException ex) { throw new InvalidDataException("Malformed signed digest", ex); }
            var path = Path.Combine(root, entry.Name);
            var file = new FileInfo(path);
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Missing or linked signed file");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                65536, FileOptions.SequentialScan);
            // Verify the size on the opened stream rather than a separate stat.
            if (stream.Length != entry.Length)
                throw new InvalidDataException("Signed file size mismatch");
            var actual = SHA256.HashData(stream);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                throw new CryptographicException("Staged file hash rejected");
        }
        int encountered = 0;
        foreach (var child in Directory.EnumerateFileSystemEntries(root))
        {
            var name = Path.GetFileName(child);
            if (!seen.Contains(name))
                throw new InvalidDataException("Unlisted file or directory in signed staging area");
            var file = new FileInfo(child);
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Untrusted staged artifact type");
            encountered++;
        }
        if (encountered != seen.Count)
            throw new InvalidDataException("Signed file inventory does not match staging directory");
        return manifest;
    }

    private static bool IsReservedWindowsFilename(string name)
    {
        var stem = name.Split('.')[0];
        return stem.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("CONIN$", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase) ||
            (stem.Length == 4 &&
             (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
              stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
             stem[3] >= '1' && stem[3] <= '9');
    }
}
