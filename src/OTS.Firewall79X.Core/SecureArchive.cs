using System.Security.Cryptography;
namespace OTS.Firewall79X.Core;
public static class SecureArchive
{
    // File format: OTS1 | salt(16) | nonce(12) | tag(16) | ciphertext.
    // AES-256-GCM with PBKDF2-SHA256; no archive content is written unencrypted.
    public static void Encrypt(string destination,byte[] payload,string password)
    {
        if(password.Length<12)throw new ArgumentException("Use at least 12 characters");
        if(payload.Length>64*1024*1024)throw new ArgumentException("Archive too large");
        var target=Path.GetFullPath(destination);
        if(File.Exists(target)||Directory.Exists(target))
            throw new IOException("Encrypted archives are versioned and must never overwrite an existing file");
        byte[] salt=RandomNumberGenerator.GetBytes(16),nonce=RandomNumberGenerator.GetBytes(12),
            tag=new byte[16],cipher=new byte[payload.Length];
        var key=Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32);
        try
        {
            using var aes=new AesGcm(key,16);
            aes.Encrypt(nonce,payload,cipher,tag,"OTS1"u8);
            var staging=target+"."+Guid.NewGuid().ToString("N")+".partial";
            try
            {
                using(var f=new FileStream(staging,FileMode.CreateNew,FileAccess.Write,FileShare.None,
                    65536,FileOptions.WriteThrough))
                {
                    f.Write("OTS1"u8);f.Write(salt);f.Write(nonce);f.Write(tag);f.Write(cipher);
                    f.Flush(true);
                }
                File.Move(staging,target,false);
            }
            finally
            {
                if(File.Exists(staging))File.Delete(staging);
            }
        }
        finally
        {
            // Caller owns payload; do not unexpectedly erase its buffer.
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }
    public static byte[] Decrypt(string path,string password)
    {
        // Open first, then use the opened stream's size, not a separate
        // FileInfo stat that can become stale before File.ReadAllBytes.
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(stream.Length<48||stream.Length>64*1024*1024+48)
            throw new InvalidDataException("Invalid archive size");
        byte[] file=new byte[(int)stream.Length];
        try
        {
            stream.ReadExactly(file);
            if(stream.ReadByte()!=-1)
                throw new InvalidDataException("Archive changed during bounded read");
            if(!file.AsSpan(0,4).SequenceEqual("OTS1"u8))
                throw new InvalidDataException("Invalid archive header");
            var key=Rfc2898DeriveBytes.Pbkdf2(password,file.AsSpan(4,16),600000,HashAlgorithmName.SHA256,32);
            byte[]? plaintext=null;
            try
            {
                plaintext=new byte[file.Length-48];
                using var aes=new AesGcm(key,16);
                aes.Decrypt(file.AsSpan(20,12),file.AsSpan(48),
                    file.AsSpan(32,16),plaintext,"OTS1"u8);
                return plaintext;
            }
            catch
            {
                // Tag failure must not leave a partially decrypted buffer alive.
                if(plaintext is not null)CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
            finally{CryptographicOperations.ZeroMemory(key);}
        }
        finally{CryptographicOperations.ZeroMemory(file);}
    }
}
