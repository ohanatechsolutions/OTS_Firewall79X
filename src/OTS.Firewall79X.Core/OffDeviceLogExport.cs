using System.Security.Cryptography;

namespace OTS.Firewall79X.Core;

// The queue contains encrypted archives only. An external destination is OPTIONAL and opt-in.
// No plaintext event logs are copied off the machine and no external account is required.
public static class OffDeviceLogExport
{
    public static string Enqueue(string queueDirectory, string sourceLog, string recoveryPassphrase)
    {
        var info = new FileInfo(sourceLog);
        if (!info.Exists || info.Length > 16 * 1024 * 1024) throw new InvalidDataException("Unsupported log source size");
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException("Linked log source rejected");
        Directory.CreateDirectory(queueDirectory);
        var plain = File.ReadAllBytes(sourceLog);
        var target = Path.Combine(queueDirectory, $"log-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.otslog");
        string partial = target + ".partial";
        try
        {
            SecureArchive.Encrypt(partial, plain, recoveryPassphrase);
            var roundtrip = SecureArchive.Decrypt(partial, recoveryPassphrase);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(roundtrip), SHA256.HashData(plain)))
                    throw new InvalidDataException("Encrypted log export failed verification");
            }
            finally { CryptographicOperations.ZeroMemory(roundtrip); }
            File.Move(partial, target, false);
            return target;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            if (File.Exists(partial)) File.Delete(partial);
        }
    }

    public static bool IsOffDeviceDestination(string folder)
    {
        try
        {
            var full = Path.GetFullPath(folder);
            var root = Path.GetPathRoot(full);
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(full)) return false;
            var drive = new DriveInfo(root);
            return drive.IsReady && drive.DriveType is DriveType.Network or DriveType.Removable;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        { return false; }
    }

    // Returns success only after a read-back hash check of the encrypted file on the target volume.
    // Failed exports remain in the queue for retry; existing target files are never overwritten.
    public static string Ship(string encryptedQueueFile, string externalFolder)
    {
        if (!IsOffDeviceDestination(externalFolder))
            throw new IOException("Destination is not a mounted removable or network volume");
        return CopyAndVerify(encryptedQueueFile, externalFolder);
    }

    public static string CopyAndVerify(string encryptedQueueFile, string destinationDirectory)
    {
        if (!Directory.Exists(destinationDirectory)) throw new DirectoryNotFoundException(destinationDirectory);
        var source = new FileInfo(encryptedQueueFile);
        if (!source.Exists || source.Length < 48 || source.Length > 64 * 1024 * 1024 + 48 ||
            !source.Name.EndsWith(".otslog", StringComparison.OrdinalIgnoreCase) ||
            source.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException("Invalid encrypted log queue entry");
        var target = Path.Combine(destinationDirectory, source.Name);
        if (File.Exists(target)) throw new IOException("Remote archive already exists; refusing overwrite");
        var temp = target + "." + Guid.NewGuid().ToString("N") + ".partial";
        try
        {
            using (var input = File.OpenRead(source.FullName))
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { input.CopyTo(output); output.Flush(true); }
            using var original = File.OpenRead(source.FullName);
            using var copied = File.OpenRead(temp);
            var h1 = SHA256.HashData(original);
            var h2 = SHA256.HashData(copied);
            if (!CryptographicOperations.FixedTimeEquals(h1, h2))
                throw new InvalidDataException("Off-device copy checksum mismatch");
            File.Move(temp, target, false);
            return target;
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    public static int RetryPending(string queueDirectory, string externalFolder, Action<string>? onFailure = null)
    {
        if (!IsOffDeviceDestination(externalFolder)) throw new IOException("Off-device destination unavailable");
        if (!Directory.Exists(queueDirectory)) return 0;
        int shipped = 0;
        foreach (var file in Directory.EnumerateFiles(queueDirectory, "*.otslog").Order().Take(16))
        {
            try { Ship(file, externalFolder); File.Delete(file); shipped++; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { onFailure?.Invoke(Wire.Clean(ex.Message, 180)); }
        }
        return shipped;
    }
}
