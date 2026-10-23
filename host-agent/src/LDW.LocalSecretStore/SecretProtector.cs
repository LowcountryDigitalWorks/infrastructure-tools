using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace LDW.LocalSecretStore;

public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext, byte[]? optionalEntropy = null);
    byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy = null);
}

public sealed class SecretProtector : ISecretProtector
{
    public byte[] Protect(byte[] plaintext, byte[]? optionalEntropy = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("CurrentUser DPAPI is required.");
        return ProtectWindows(plaintext, optionalEntropy);
    }

    public byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy = null)
    {
        ArgumentNullException.ThrowIfNull(encryptedData);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("CurrentUser DPAPI is required.");
        return UnprotectWindows(encryptedData, optionalEntropy);
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ProtectWindows(byte[] data, byte[]? entropy) =>
        ProtectedData.Protect(data, entropy, DataProtectionScope.CurrentUser);

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectWindows(byte[] data, byte[]? entropy) =>
        ProtectedData.Unprotect(data, entropy, DataProtectionScope.CurrentUser);
}
