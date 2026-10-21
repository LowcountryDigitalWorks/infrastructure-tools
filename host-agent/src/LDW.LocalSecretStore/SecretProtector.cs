using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace LDW.LocalSecretStore;

public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext, byte[]? optionalEntropy = null);
    byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy = null);
}

public sealed class SecretProtector : ISecretProtector
{
    private static readonly byte[] FallbackSalt = Encoding.UTF8.GetBytes("LDW01-LOCAL-SECRET-HANDOFF-V1");

    public byte[] Protect(byte[] plaintext, byte[]? optionalEntropy = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (OperatingSystem.IsWindows())
        {
            return ProtectWindowsDpapi(plaintext, optionalEntropy);
        }

        return ProtectFallbackAes(plaintext, optionalEntropy);
    }

    public byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy = null)
    {
        ArgumentNullException.ThrowIfNull(encryptedData);

        if (OperatingSystem.IsWindows())
        {
            return UnprotectWindowsDpapi(encryptedData, optionalEntropy);
        }

        return UnprotectFallbackAes(encryptedData, optionalEntropy);
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ProtectWindowsDpapi(byte[] plaintext, byte[]? optionalEntropy)
    {
        try
        {
            return ProtectedData.Protect(plaintext, optionalEntropy ?? FallbackSalt, DataProtectionScope.CurrentUser);
        }
        catch (PlatformNotSupportedException)
        {
            return ProtectFallbackAes(plaintext, optionalEntropy);
        }
    }

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectWindowsDpapi(byte[] encryptedData, byte[]? optionalEntropy)
    {
        try
        {
            return ProtectedData.Unprotect(encryptedData, optionalEntropy ?? FallbackSalt, DataProtectionScope.CurrentUser);
        }
        catch (PlatformNotSupportedException)
        {
            return UnprotectFallbackAes(encryptedData, optionalEntropy);
        }
    }

    private static byte[] ProtectFallbackAes(byte[] plaintext, byte[]? optionalEntropy)
    {
        using var aes = Aes.Create();
        var entropy = optionalEntropy ?? FallbackSalt;
        aes.Key = Rfc2898DeriveBytes.Pbkdf2(FallbackSalt, entropy, 100_000, HashAlgorithmName.SHA256, 32);
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var cipherText = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

        // Result payload: IV (16 bytes) + CipherText
        var result = new byte[aes.IV.Length + cipherText.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(cipherText, 0, result, aes.IV.Length, cipherText.Length);

        return result;
    }

    private static byte[] UnprotectFallbackAes(byte[] encryptedData, byte[]? optionalEntropy)
    {
        if (encryptedData.Length < 17)
            throw new CryptographicException("Invalid encrypted payload length.");

        using var aes = Aes.Create();
        var entropy = optionalEntropy ?? FallbackSalt;
        aes.Key = Rfc2898DeriveBytes.Pbkdf2(FallbackSalt, entropy, 100_000, HashAlgorithmName.SHA256, 32);

        var iv = new byte[16];
        Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
        aes.IV = iv;

        var cipherTextLength = encryptedData.Length - 16;
        var cipherText = new byte[cipherTextLength];
        Buffer.BlockCopy(encryptedData, 16, cipherText, 0, cipherTextLength);

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
    }
}
