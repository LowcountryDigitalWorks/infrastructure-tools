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

    private static readonly HashSet<string> SafeResultStates = new(StringComparer.Ordinal)
    {
        "InvalidRequest",
        "Unavailable",
        "DuplicateRequest"
    };

    private static readonly HashSet<string> SafeErrorCodes = new(StringComparer.Ordinal)
    {
        "INVALID_REQUEST_ID",
        "NOT_IMPLEMENTED",
        "DUPLICATE_REQUEST"
    };

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
            {
                if (!Guid.TryParseExact(record.RequestId, "D", out _) || !AdminBrokerContract.Operations.IsValid(record.Operation) ||
                    (record.CallerSid?.Length ?? 0) > 184 || !SafeResultStates.Contains(record.ResultState) ||
                    (record.ErrorCode is not null && !SafeErrorCodes.Contains(record.ErrorCode)))
                    throw new InvalidOperationException("Audit record contains unsupported fields.");
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

                // Never persist caller-controlled target or summary text.
                var safeRecord = record with { TargetIdentity = "redacted", Summary = "Operation audit record." };
                var jsonLine = JsonSerializer.Serialize(safeRecord, JsonOptions) + Environment.NewLine;
                File.AppendAllText(_auditLogPath, jsonLine);
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
