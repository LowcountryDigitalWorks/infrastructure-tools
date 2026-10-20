using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace LDW.HostAgent.AdminBroker.Core;

/// <summary>Stores the one V1 proof secret under the current Windows user's DPAPI identity.</summary>
public sealed class LocalSecretVault
{
    public const string SecretIdentity = "CORSAIR_NEON_DATABASE_URL";
    private const string FileName = "corsair-neon-database-url.dpapi";
    private const int MaximumSecretBytes = 64 * 1024;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("LowcountryDigitalWorks/AdminBroker/v1/CORSAIR_NEON_DATABASE_URL");
    private readonly string _path;

    public LocalSecretVault(string? rootDirectory = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The local secret vault requires Windows DPAPI.");

        var root = rootDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LowcountryDigitalWorks", "AdminBroker");
        _path = Path.Combine(Path.GetFullPath(root), FileName);
    }

    public bool IsPresent => File.Exists(_path);

    public void Store(SecureString secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
            throw new ArgumentException("The protected value must not be empty.", nameof(secret));

        var clear = SecureStringToUtf8(secret);
        try
        {
            if (clear.Length > MaximumSecretBytes)
                throw new ArgumentException("The protected value exceeds the local size limit.", nameof(secret));

            var protectedBytes = Protect(clear);
            try
            {
                var directory = Path.GetDirectoryName(_path)!;
                Directory.CreateDirectory(directory);
                var temporaryPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                    {
                        stream.Write(protectedBytes);
                        stream.Flush(flushToDisk: true);
                    }
                    File.Move(temporaryPath, _path, overwrite: true);
                }
                finally
                {
                    if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    public SecureString Load()
    {
        var fileInfo = new FileInfo(_path);
        if (!fileInfo.Exists || fileInfo.Length is 0 or > MaximumSecretBytes + 4096)
            throw new CryptographicException("The protected value is unavailable.");

        var protectedBytes = File.ReadAllBytes(_path);
        if (protectedBytes.Length is 0 or > MaximumSecretBytes + 4096)
            throw new CryptographicException("The protected value is unavailable.");

        byte[]? clear = null;
        try
        {
            clear = Unprotect(protectedBytes);
            if (clear.Length == 0 || clear.Length > MaximumSecretBytes)
                throw new CryptographicException("The protected value is unavailable.");

            var result = new SecureString();
            var chars = new UTF8Encoding(false, true).GetChars(clear);
            try
            {
                foreach (var value in chars) result.AppendChar(value);
            }
            finally
            {
                Array.Clear(chars);
            }
            result.MakeReadOnly();
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
        }
    }

    public void Remove()
    {
        if (File.Exists(_path)) File.Delete(_path);
    }

    private static byte[] SecureStringToUtf8(SecureString secret)
    {
        var pointer = Marshal.SecureStringToGlobalAllocUnicode(secret);
        try
        {
            var chars = new char[secret.Length];
            Marshal.Copy(pointer, chars, 0, chars.Length);
            try { return Encoding.UTF8.GetBytes(chars); }
            finally { Array.Clear(chars); }
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(pointer);
        }
    }

    private static byte[] Protect(byte[] clear) => Transform(clear, protect: true);
    private static byte[] Unprotect(byte[] protectedBytes) => Transform(protectedBytes, protect: false);

    private static byte[] Transform(byte[] input, bool protect)
    {
        var inputHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        var inputBlob = new DataBlob(input.Length, inputHandle.AddrOfPinnedObject());
        var entropyBlob = new DataBlob(Entropy.Length, entropyHandle.AddrOfPinnedObject());
        DataBlob outputBlob = default;
        try
        {
            var succeeded = protect
                ? CryptProtectData(ref inputBlob, SecretIdentity, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out outputBlob)
                : CryptUnprotectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out outputBlob);
            if (!succeeded || outputBlob.Data == IntPtr.Zero || outputBlob.Length <= 0)
                throw new CryptographicException("Windows DPAPI could not process the local secret.");

            var result = new byte[outputBlob.Length];
            Marshal.Copy(outputBlob.Data, result, 0, result.Length);
            return result;
        }
        finally
        {
            if (outputBlob.Data != IntPtr.Zero) _ = LocalFree(outputBlob.Data);
            inputHandle.Free();
            entropyHandle.Free();
        }
    }

    private const uint UiForbidden = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob(int length, IntPtr data)
    {
        public int Length = length;
        public IntPtr Data = data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob input, string description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
