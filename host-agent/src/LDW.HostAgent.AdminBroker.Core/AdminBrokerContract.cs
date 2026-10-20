using System.Text.Json;
using System.Text.RegularExpressions;

namespace LDW.HostAgent.AdminBroker.Core;

public enum AdminBrokerOperation
{
    CodyncBotCreate,
    CodyncBotUpdate,
    CodyncBotDelete,
    HostAgentStatus,
    HostAgentRestartReviewedComponent,
    HostAgentRepairReviewedInstall
}

public sealed record AdminBrokerRequest(
    int Version,
    string RequestId,
    AdminBrokerOperation Operation,
    string TargetId,
    IReadOnlyDictionary<string, string> Inputs);

public sealed record AdminBrokerAuditRecord(
    int Version,
    string RequestId,
    string Operation,
    string TargetId,
    string Outcome,
    string ResultCode,
    DateTimeOffset CompletedAtUtc);

public static partial class AdminBrokerContract
{
    public const int Version = 1;
    public const int MaximumRequestCharacters = 4096;
    public const int MaximumInputCharacters = 2048;
    public const int MaximumAuditResultCharacters = 64;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static bool TryParseRequest(string? json, out AdminBrokerRequest? request)
    {
        request = null;
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaximumRequestCharacters)
            return false;

        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !HasExactProperties(root, "version", "requestId", "operation", "targetId", "inputs"))
                return false;

            if (!root.TryGetProperty("version", out var version)
                || version.ValueKind != JsonValueKind.Number
                || !version.TryGetInt32(out var versionNumber)
                || versionNumber != Version
                || !root.TryGetProperty("requestId", out var requestIdElement)
                || requestIdElement.ValueKind != JsonValueKind.String
                || !Guid.TryParseExact(requestIdElement.GetString(), "D", out var requestId)
                || !root.TryGetProperty("operation", out var operationElement)
                || operationElement.ValueKind != JsonValueKind.String
                || !TryParseOperation(operationElement.GetString(), out var operation)
                || !root.TryGetProperty("targetId", out var targetElement)
                || targetElement.ValueKind != JsonValueKind.String
                || !TryParseTarget(operation, targetElement.GetString(), out var targetId)
                || !root.TryGetProperty("inputs", out var inputsElement)
                || inputsElement.ValueKind != JsonValueKind.Object)
                return false;

            var inputs = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in inputsElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String
                    || property.Value.GetString() is not { Length: <= MaximumInputCharacters } value
                    || !inputs.TryAdd(property.Name, value))
                    return false;
            }

            if (!InputsMatch(operation, inputs))
                return false;

            request = new AdminBrokerRequest(Version, requestId.ToString("D"), operation, targetId, inputs);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static string CreateAuditJson(AdminBrokerAuditRecord record)
    {
        var hasOperation = TryParseOperation(record.Operation, out var operation);
        if (record.Version != Version
            || !Guid.TryParseExact(record.RequestId, "D", out _)
            || !hasOperation
            || !TryParseTarget(operation, record.TargetId, out _)
            || record.Outcome is not ("succeeded" or "rejected" or "failed")
            || !IsSafeResultCode(record.ResultCode))
            throw new ArgumentException("Audit record is outside the bounded result contract.", nameof(record));

        return JsonSerializer.Serialize(record, JsonOptions);
    }

    public static bool TryParseOperation(string? value, out AdminBrokerOperation operation)
    {
        operation = value switch
        {
            "CODYNC_BOT_CREATE" => AdminBrokerOperation.CodyncBotCreate,
            "CODYNC_BOT_UPDATE" => AdminBrokerOperation.CodyncBotUpdate,
            "CODYNC_BOT_DELETE" => AdminBrokerOperation.CodyncBotDelete,
            "HOST_AGENT_STATUS" => AdminBrokerOperation.HostAgentStatus,
            "HOST_AGENT_RESTART_REVIEWED_COMPONENT" => AdminBrokerOperation.HostAgentRestartReviewedComponent,
            "HOST_AGENT_REPAIR_REVIEWED_INSTALL" => AdminBrokerOperation.HostAgentRepairReviewedInstall,
            _ => (AdminBrokerOperation)(-1)
        };
        return Enum.IsDefined(operation);
    }

    private static bool InputsMatch(AdminBrokerOperation operation, IReadOnlyDictionary<string, string> inputs)
    {
        string[] expected = operation switch
        {
            AdminBrokerOperation.CodyncBotCreate => ["definitionId"],
            AdminBrokerOperation.CodyncBotUpdate => ["botId", "definitionId"],
            AdminBrokerOperation.CodyncBotDelete => ["botId"],
            AdminBrokerOperation.HostAgentStatus => [],
            AdminBrokerOperation.HostAgentRestartReviewedComponent => ["componentId"],
            AdminBrokerOperation.HostAgentRepairReviewedInstall => ["releaseId"],
            _ => []
        };

        if (inputs.Count != expected.Length || expected.Any(key => !inputs.ContainsKey(key)))
            return false;

        return operation switch
        {
            AdminBrokerOperation.CodyncBotCreate => inputs["definitionId"] == "codync-smoke-test",
            AdminBrokerOperation.CodyncBotUpdate => IsExactLocalId(inputs["botId"]) && inputs["definitionId"] == "codync-smoke-test",
            AdminBrokerOperation.CodyncBotDelete => IsExactLocalId(inputs["botId"]),
            AdminBrokerOperation.HostAgentStatus => true,
            AdminBrokerOperation.HostAgentRestartReviewedComponent => inputs["componentId"] is "host-agent-tray" or "hyperv-observer",
            AdminBrokerOperation.HostAgentRepairReviewedInstall => IsReleaseId(inputs["releaseId"]),
            _ => false
        };
    }

    private static bool TryParseTarget(AdminBrokerOperation operation, string? value, out string target)
    {
        target = value ?? string.Empty;
        var allowed = operation switch
        {
            AdminBrokerOperation.CodyncBotCreate or AdminBrokerOperation.CodyncBotUpdate or AdminBrokerOperation.CodyncBotDelete => "codync",
            AdminBrokerOperation.HostAgentStatus => "ldw01",
            AdminBrokerOperation.HostAgentRestartReviewedComponent or AdminBrokerOperation.HostAgentRepairReviewedInstall => "host-agent",
            _ => string.Empty
        };
        return string.Equals(value, allowed, StringComparison.Ordinal);
    }

    private static bool HasExactProperties(JsonElement element, params string[] expected)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
                return false;
        return seen.Count == expected.Length;
    }

    private static bool IsExactLocalId(string value) => LocalIdRegex().IsMatch(value);
    private static bool IsReleaseId(string value) => ReleaseIdRegex().IsMatch(value);
    private static bool IsSafeResultCode(string value) => ResultCodeRegex().IsMatch(value);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex LocalIdRegex();

    [GeneratedRegex("^[a-f0-9]{16}$", RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseIdRegex();

    [GeneratedRegex("^[a-z0-9-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ResultCodeRegex();
}
