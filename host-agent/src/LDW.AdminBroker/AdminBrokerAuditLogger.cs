using System.Text.Json;

namespace LDW.AdminBroker;

public sealed record AuditRecord(
    DateTime TimestampUtc,
    string RequestId,
    string Operation,
    string TargetIdentity,
    string? CallerSid,
    bool Success,
    string ResultState,
    string? ErrorCode,
    string Summary);

public sealed class AdminBrokerAuditLogger
{
    private readonly string _auditLogPath;
    private readonly object _lock = new();
    private const long MaximumLogSizeBytes = 5 * 1024 * 1024; // 5 MB limit

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public AdminBrokerAuditLogger(string? customPath = null)
    {
        _auditLogPath = !string.IsNullOrWhiteSpace(customPath)
            ? customPath
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LowcountryDigitalWorks",
                "AdminBroker",
                "audit-log.jsonl");
    }

    public void Log(AuditRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        lock (_lock)
        {
            try
            {
                var directory = Path.GetDirectoryName(_auditLogPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Rotate if too large
                if (File.Exists(_auditLogPath) && new FileInfo(_auditLogPath).Length > MaximumLogSizeBytes)
                {
                    var backupPath = _auditLogPath + ".1";
                    if (File.Exists(backupPath))
                        File.Delete(backupPath);
                    File.Move(_auditLogPath, backupPath);
                }

                var jsonLine = JsonSerializer.Serialize(record, JsonOptions) + Environment.NewLine;
                File.AppendAllText(_auditLogPath, jsonLine);
            }
            catch
            {
                // Fail closed gracefully without breaking operation pipeline
            }
        }
    }

    public IReadOnlyList<AuditRecord> ReadRecords()
    {
        lock (_lock)
        {
            if (!File.Exists(_auditLogPath))
                return Array.Empty<AuditRecord>();

            var list = new List<AuditRecord>();
            try
            {
                foreach (var line in File.ReadLines(_auditLogPath))
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    try
                    {
                        var record = JsonSerializer.Deserialize<AuditRecord>(line, JsonOptions);
                        if (record is not null)
                            list.Add(record);
                    }
                    catch { }
                }
            }
            catch { }

            return list;
        }
    }
}
