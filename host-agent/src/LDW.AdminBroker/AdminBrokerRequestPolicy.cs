using System.Text.Json;

namespace LDW.AdminBroker;

/// <summary>Fixed value bounds applied after exact JSON schema parsing and before any handler invocation.</summary>
public static class AdminBrokerRequestPolicy
{
    public static bool IsAllowed(AdminBrokerRequest request)
    {
        if (request is null || request.Version != AdminBrokerContract.Version
            || !Guid.TryParseExact(request.RequestId, "D", out _)
            || !AdminBrokerContract.Operations.IsValid(request.Operation)
            || !IsBoundedText(request.TargetIdentity, 128))
            return false;

        var parameters = request.Parameters;
        if (request.Operation is AdminBrokerContract.Operations.CodyncBotCreate or AdminBrokerContract.Operations.CodyncBotUpdate)
        {
            if (parameters is null
                || !TryText(parameters, "name", 96)
                || !TryText(parameters, "description", 512)
                || !TryText(parameters, "endpointUrl", 2048)
                || !TryEndpoint(parameters["endpointUrl"].GetString()!)
                || !TryCapabilities(parameters))
                return false;
        }
        else if (CiJitControlContract.IsOperation(request.Operation))
        {
            if (!string.Equals(request.TargetIdentity, CiJitControlContract.TargetIdentity, StringComparison.Ordinal))
                return false;

            if (request.Operation == AdminBrokerContract.Operations.CiJitRetireStale)
            {
                if (parameters is null
                    || parameters.Count != 1
                    || !parameters.TryGetValue("runId", out var runId)
                    || runId.ValueKind != JsonValueKind.Number
                    || !runId.TryGetInt64(out var value)
                    || value <= 0)
                    return false;
            }
            else if (request.Operation == AdminBrokerContract.Operations.CiJitGetOperationResult)
            {
                if (parameters is null
                    || parameters.Count != 1
                    || !parameters.TryGetValue("operationId", out var operationId)
                    || operationId.ValueKind != JsonValueKind.String
                    || !Guid.TryParseExact(operationId.GetString(), "D", out _))
                    return false;
            }
            else if (parameters is { Count: > 0 })
            {
                return false;
            }
        }
        else if (parameters is { Count: > 0 })
        {
            return false;
        }

        return true;
    }

    private static bool TryText(IReadOnlyDictionary<string, JsonElement> parameters, string name, int maximumLength) =>
        parameters.TryGetValue(name, out var value)
        && value.ValueKind == JsonValueKind.String
        && IsBoundedText(value.GetString(), maximumLength);

    private static bool IsBoundedText(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= maximumLength
        && !value.Any(char.IsControl);

    private static bool TryEndpoint(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
        && string.IsNullOrEmpty(uri.UserInfo)
        && string.IsNullOrEmpty(uri.Fragment);

    private static bool TryCapabilities(IReadOnlyDictionary<string, JsonElement> parameters)
    {
        if (!parameters.TryGetValue("capabilities", out var value) || value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 32)
            return false;
        foreach (var item in value.EnumerateArray())
            if (item.ValueKind != JsonValueKind.String || !IsBoundedText(item.GetString(), 64))
                return false;
        return true;
    }
}
