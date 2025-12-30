using System.Security.Cryptography;
using HeatBeat.Shared.Contants;
using Microsoft.Extensions.Configuration;

namespace HeatBeat.Shared.Helpers;

public interface IPayloadEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

public class PayloadEncryptionService : IPayloadEncryptionService
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public PayloadEncryptionService(IConfiguration configuration)
    {
        var encryptionKey = configuration.GetValue<string>(EnvironmentCodes.EncryptionKey)
            ?? throw new InvalidOperationException($"{EnvironmentCodes.EncryptionKey} is not configured");

        var encryptionIV = configuration.GetValue<string>(EnvironmentCodes.EncryptionIV)
            ?? throw new InvalidOperationException($"{EnvironmentCodes.EncryptionIV} is not configured");

        _key = Convert.FromBase64String(encryptionKey);
        _iv = Convert.FromBase64String(encryptionIV);

        if (_key.Length != 32) // 256 bits
            throw new InvalidOperationException($"{EnvironmentCodes.EncryptionKey} must be 256 bits (32 bytes)");

        if (_iv.Length != 16) // 128 bits
            throw new InvalidOperationException($"{EnvironmentCodes.EncryptionIV} must be 128 bits (16 bytes)");
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return plainText;

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return cipherText;

        var buffer = Convert.FromBase64String(cipherText);

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var msDecrypt = new MemoryStream(buffer);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        return srDecrypt.ReadToEnd();
    }
}