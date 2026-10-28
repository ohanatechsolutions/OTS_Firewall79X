using System.Security.Cryptography;
namespace OTS.Firewall79X.Core;
public static class SecureArchive
{
    // File format: OTS1 | salt(16) | nonce(12) | tag(16) | ciphertext. AES-GCM with PBKDF2-SHA256.
    public static void Encrypt(string destination,byte[] payload,string password)
    {
        if(password.Length<12)throw new ArgumentException("Use at least 12 characters");
        if(payload.Length>64*1024*1024)throw new ArgumentException("Archive too large");
        byte[] salt=RandomNumberGenerator.GetBytes(16),nonce=RandomNumberGenerator.GetBytes(12),tag=new byte[16],cipher=new byte[payload.Length];
        var key=Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32);
        try{using var aes=new AesGcm(key,16);aes.Encrypt(nonce,payload,cipher,tag,"OTS1"u8);using var f=File.Create(destination);f.Write("OTS1"u8);f.Write(salt);f.Write(nonce);f.Write(tag);f.Write(cipher);f.Flush(true);}finally{CryptographicOperations.ZeroMemory(key);}
    }
    public static byte[] Decrypt(string path,string password)
    {
        var info=new FileInfo(path);if(info.Length<48||info.Length>64*1024*1024+48)throw new InvalidDataException("Invalid archive size");
        var b=File.ReadAllBytes(path);if(!b.AsSpan(0,4).SequenceEqual("OTS1"u8))throw new InvalidDataException("Invalid archive header");
        var key=Rfc2898DeriveBytes.Pbkdf2(password,b.AsSpan(4,16),600000,HashAlgorithmName.SHA256,32);
        try{using var aes=new AesGcm(key,16);var plain=new byte[b.Length-48];aes.Decrypt(b.AsSpan(20,12),b.AsSpan(48),b.AsSpan(32,16),plain,"OTS1"u8);return plain;}finally{CryptographicOperations.ZeroMemory(key);}
    }
}
