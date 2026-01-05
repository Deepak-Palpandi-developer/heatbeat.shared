namespace HeatBeat.Shared.Helpers.Services;

public interface IPayloadEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

public class PayloadEncryptionService : IPayloadEncryptionService
{

    public PayloadEncryptionService()
    {
    }

    public string Encrypt(string plainText)
    {
        return CommonHelper.Encrypt(plainText);
    }

    public string Decrypt(string cipherText)
    {
        return CommonHelper.Decrypt(cipherText);
    }
}