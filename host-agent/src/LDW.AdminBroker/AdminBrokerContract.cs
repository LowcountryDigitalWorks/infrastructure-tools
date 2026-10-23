using System.Text.Json;

namespace LDW.AdminBroker;

public sealed record AdminBrokerRequest(
    int Version,
    string RequestId,
    string Operation,
    string TargetIdentity,
    IReadOnlyDictionary<string, JsonElement>? Parameters);

public sealed record AdminBrokerResponse(
    int Version,
    string RequestId,
    string Operation,
    bool Success,
    string TargetIdentity,
    string ResultState,
    string Summary,
    string? ErrorCode,
    DateTime TimestampUtc,
    IReadOnlyDictionary<string, string>? Details);

public static class AdminBrokerContract
{
    public const int Version = 1;
    public const string PipeName = "LDW.AdminBroker.v1";
    public const int MaximumRequestCharacters = 16384;
    public const int MaximumResponseCharacters = 32768;

    public static class Operations
    {
        public const string CodyncBotCreate = "CODYNC_BOT_CREATE";
        public const string CodyncBotUpdate = "CODYNC_BOT_UPDATE";
        public const string CodyncBotDelete = "CODYNC_BOT_DELETE";
        public const string HostAgentStatus = "HOST_AGENT_STATUS";
        public const string HostAgentRestartReviewedComponent = "HOST_AGENT_RESTART_REVIEWED_COMPONENT";
        public const string HostAgentRepairReviewedInstall = "HOST_AGENT_REPAIR_REVIEWED_INSTALL";

        public static readonly HashSet<string> All = new(StringComparer.Ordinal)
        {
            CodyncBotCreate,
            CodyncBotUpdate,
            CodyncBotDelete,
            HostAgentStatus,
            HostAgentRestartReviewedComponent,
            HostAgentRepairReviewedInstall
        };

        public static bool IsValid(string? operation) =>
            !string.IsNullOrWhiteSpace(operation) && All.Contains(operation);
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static string CreateRequestJson(AdminBrokerRequest request) =>
        JsonSerializer.Serialize(request, JsonOptions);

    public static bool TryParseRequest(string json, out AdminBrokerRequest? request)
    {
        request = null;
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaximumRequestCharacters)
            return false;

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            // Validate names and reject duplicates before interpreting any value.
            var propertyNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (property.Name is not ("version" or "requestId" or "operation" or "targetIdentity" or "parameters"))
                    return false;
                if (!propertyNames.Add(property.Name))
                    return false;
            }

            if (!root.TryGetProperty("version", out var versionProp)
                || versionProp.ValueKind != JsonValueKind.Number
                || versionProp.GetInt32() != Version)
                return false;

            if (!root.TryGetProperty("requestId", out var reqIdProp)
                || reqIdProp.ValueKind != JsonValueKind.String
                || !Guid.TryParseExact(reqIdProp.GetString(), "D", out _))
                return false;

            if (!root.TryGetProperty("operation", out var opProp)
                || opProp.ValueKind != JsonValueKind.String
                || !Operations.IsValid(opProp.GetString()))
                return false;

            if (!root.TryGetProperty("targetIdentity", out var targetProp)
                || targetProp.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(targetProp.GetString()))
                return false;

            IReadOnlyDictionary<string, JsonElement>? parameters = null;
            if (root.TryGetProperty("parameters", out var paramsProp))
            {
                if (paramsProp.ValueKind != JsonValueKind.Object && paramsProp.ValueKind != JsonValueKind.Null)
                    return false;

                if (paramsProp.ValueKind == JsonValueKind.Object)
                {
                    var dict = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                    foreach (var p in paramsProp.EnumerateObject())
                    {
                        if (!dict.TryAdd(p.Name, p.Value.Clone())) return false;
                    }
                    parameters = dict;
                }
            }

            request = new AdminBrokerRequest(
                Version,
                reqIdProp.GetString()!,
                opProp.GetString()!,
                targetProp.GetString()!,
                parameters);

            var expected = opProp.GetString() switch
            {
                Operations.CodyncBotCreate or Operations.CodyncBotUpdate => new[] { "name", "description", "endpointUrl", "capabilities" },
                Operations.CodyncBotDelete or Operations.HostAgentStatus or Operations.HostAgentRestartReviewedComponent or Operations.HostAgentRepairReviewedInstall => Array.Empty<string>(),
                _ => Array.Empty<string>()
            };
            var supplied = parameters?.Keys.ToHashSet(StringComparer.Ordinal) ?? new HashSet<string>(StringComparer.Ordinal);
            if (!supplied.SetEquals(expected)) return false;
            if (expected.Length > 0 && (parameters!["name"].ValueKind != JsonValueKind.String || parameters["description"].ValueKind != JsonValueKind.String || parameters["endpointUrl"].ValueKind != JsonValueKind.String || parameters["capabilities"].ValueKind != JsonValueKind.Array)) return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string CreateResponseJson(AdminBrokerResponse response) =>
        JsonSerializer.Serialize(response, JsonOptions);

    public static bool TryParseResponse(string json, out AdminBrokerResponse? response)
    {
        response = null;
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaximumResponseCharacters)
            return false;

        try
        {
            var parsed = JsonSerializer.Deserialize<AdminBrokerResponse>(json, JsonOptions);
            if (parsed is null
                || parsed.Version != Version
                || string.IsNullOrWhiteSpace(parsed.RequestId)
                || !Operations.IsValid(parsed.Operation)
                || string.IsNullOrWhiteSpace(parsed.TargetIdentity))
                return false;

            response = parsed;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
