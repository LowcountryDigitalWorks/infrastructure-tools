using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LDW.LocalSecretStore;

public sealed record SecretStatus(
    bool Exists,
    string SecretId,
    DateTime? LastUpdatedUtc,
    int ValueLength,
    string? Sha256Fingerprint);

public sealed record SecretEntryPayload(
    string SecretId,
    DateTime LastUpdatedUtc,
    int Length,
    string Sha256Fingerprint,
    string EncryptedDataB64);

public sealed record SecretStoreFileContent(
    int Version,
    Dictionary<string, SecretEntryPayload> Secrets);

public sealed class LocalSecretStore
{
    public const int Version = 1;
    public const string FixedSecretIdCorsairNeon = "CORSAIR_NEON_DATABASE_URL";

    private readonly string _storeFilePath;
    private readonly ISecretProtector _protector;
    private readonly object _lock = new();

    public LocalSecretStore(string? customStorePath = null, ISecretProtector? protector = null)
    {
        _protector = protector ?? new SecretProtector();
        _storeFilePath = !string.IsNullOrWhiteSpace(customStorePath)
            ? customStorePath
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LowcountryDigitalWorks",
                "Secrets",
                "ldw-secrets.dat");
    }

    public bool SetSecret(string secretId, string plaintextValue)
    {
        ValidateSecretId(secretId);
        if (string.IsNullOrEmpty(plaintextValue))
            return false;

        lock (_lock)
        {
            var fileContent = LoadStoreFile();

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintextValue);
            try
            {
                var hashBytes = SHA256.HashData(plaintextBytes);
                var fingerprint = Convert.ToHexStringLower(hashBytes)[..16]; // 16-char sanitized thumbprint
                var encryptedBytes = _protector.Protect(plaintextBytes);
                var encryptedB64 = Convert.ToBase64String(encryptedBytes);

                var entry = new SecretEntryPayload(
                    secretId,
                    DateTime.UtcNow,
                    plaintextValue.Length,
                    fingerprint,
                    encryptedB64);

                fileContent.Secrets[secretId] = entry;
                SaveStoreFile(fileContent);
                return true;
            }
            finally
            {
                Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
            }
        }
    }

    public SecretStatus GetStatus(string secretId)
    {
        ValidateSecretId(secretId);

        lock (_lock)
        {
            var fileContent = LoadStoreFile();
            if (!fileContent.Secrets.TryGetValue(secretId, out var entry))
            {
                return new SecretStatus(false, secretId, null, 0, null);
            }

            return new SecretStatus(true, entry.SecretId, entry.LastUpdatedUtc, entry.Length, entry.Sha256Fingerprint);
        }
    }

    public bool RotateSecret(string secretId, string newPlaintextValue)
    {
        return SetSecret(secretId, newPlaintextValue);
    }

    public bool RemoveSecret(string secretId)
    {
        ValidateSecretId(secretId);

        lock (_lock)
        {
            var fileContent = LoadStoreFile();
            if (!fileContent.Secrets.Remove(secretId))
                return false;

            SaveStoreFile(fileContent);
            return true;
        }
    }

    public string? GetSecretValueInMemory(string secretId)
    {
        ValidateSecretId(secretId);

        lock (_lock)
        {
            var fileContent = LoadStoreFile();
            if (!fileContent.Secrets.TryGetValue(secretId, out var entry))
                return null;

            try
            {
                var encryptedBytes = Convert.FromBase64String(entry.EncryptedDataB64);
                var decryptedBytes = _protector.Unprotect(encryptedBytes);
                try
                {
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
                finally
                {
                    Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
                }
            }
            catch
            {
                return null;
            }
        }
    }

    private static void ValidateSecretId(string secretId)
    {
        if (string.IsNullOrWhiteSpace(secretId))
            throw new ArgumentException("Secret ID cannot be null or empty.", nameof(secretId));

        if (!secretId.All(c => char.IsLetterOrDigit(c) || c == '_' || c == '-'))
            throw new ArgumentException("Secret ID contains invalid characters.", nameof(secretId));
    }

    private SecretStoreFileContent LoadStoreFile()
    {
        if (!File.Exists(_storeFilePath))
        {
            return new SecretStoreFileContent(Version, new Dictionary<string, SecretEntryPayload>(StringComparer.OrdinalIgnoreCase));
        }

        try
        {
            var json = File.ReadAllText(_storeFilePath);
            var parsed = JsonSerializer.Deserialize<SecretStoreFileContent>(json);
            if (parsed is null || parsed.Version != Version || parsed.Secrets is null)
            {
                return new SecretStoreFileContent(Version, new Dictionary<string, SecretEntryPayload>(StringComparer.OrdinalIgnoreCase));
            }

            return parsed with
            {
                Secrets = new Dictionary<string, SecretEntryPayload>(parsed.Secrets, StringComparer.OrdinalIgnoreCase)
            };
        }
        catch
        {
            return new SecretStoreFileContent(Version, new Dictionary<string, SecretEntryPayload>(StringComparer.OrdinalIgnoreCase));
        }
    }

    private void SaveStoreFile(SecretStoreFileContent content)
    {
        var directory = Path.GetDirectoryName(_storeFilePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var options = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(content, options);
        File.WriteAllText(_storeFilePath, json);
    }
}
