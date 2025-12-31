using System.Security.Cryptography;
using HeatBeat.Shared.Contants;
using Microsoft.Extensions.Configuration;

namespace HeatBeat.Shared.Helpers.Services;

public interface IPayloadEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

public class PayloadEncryptionService : IPayloadEncryptionService
{
    private readonly byte[] _key;
    private readonly byte[] _fallbackIv;

    public PayloadEncryptionService(IConfiguration configuration)
    {
        var encryptionKey = configuration.GetValue<string>(EnvironmentCodes.EncryptionKey)
            ?? throw new InvalidOperationException($"{EnvironmentCodes.EncryptionKey} is not configured");

        var encryptionIV = configuration.GetValue<string>(EnvironmentCodes.EncryptionIV)
            ?? throw new InvalidOperationException($"{EnvironmentCodes.EncryptionIV} is not configured");

        _key = Convert.FromBase64String(encryptionKey);
        _fallbackIv = Convert.FromBase64String(encryptionIV);

        if (_key.Length != 32) // 256 bits
            throw new InvalidOperationException($"{EnvironmentCodes.EncryptionKey} must be 256 bits (32 bytes)");

        if (_fallbackIv.Length != 16) // 128 bits
            throw new InvalidOperationException($"{EnvironmentCodes.EncryptionIV} must be 128 bits (16 bytes)");
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return plainText;

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        var cipherBytes = msEncrypt.ToArray();

        // Prefix a version byte plus the IV so decrypt can extract per-message IVs; fall back to configured IV when absent.
        var payload = new byte[1 + aes.IV.Length + cipherBytes.Length];
        payload[0] = 1; // version marker
        Buffer.BlockCopy(aes.IV, 0, payload, 1, aes.IV.Length);
        Buffer.BlockCopy(cipherBytes, 0, payload, 1 + aes.IV.Length, cipherBytes.Length);

        return Convert.ToBase64String(payload);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return cipherText;

        var buffer = Convert.FromBase64String(cipherText);

        byte[] iv;
        byte[] cipherBytes;

        if (buffer.Length > 1 && buffer[0] == 1 && buffer.Length > 1 + 16)
        {
            iv = new byte[16];
            Buffer.BlockCopy(buffer, 1, iv, 0, iv.Length);
            cipherBytes = new byte[buffer.Length - 1 - iv.Length];
            Buffer.BlockCopy(buffer, 1 + iv.Length, cipherBytes, 0, cipherBytes.Length);
        }
        else
        {
            iv = _fallbackIv;
            cipherBytes = buffer;
        }

        if (cipherBytes.Length == 0)
            return string.Empty;

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var msDecrypt = new MemoryStream(cipherBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        return srDecrypt.ReadToEnd();
    }
}