using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace LDW.HostAgent.Core;

public sealed record HyperVObservationRequest(int Version, string Operation);

public sealed record HyperVObservationResponse(
    int Version,
    bool Authorized,
    bool VmExists,
    string State,
    bool Running,
    IReadOnlyList<string> AddressCandidates,
    string? ErrorCode = null);

public static class HyperVObserverContract
{
    public const int Version = 1;
    public const string AllowedVmName = "CI-RUNNER-001";
    public const string Operation = "observe-ci-runner-001";
    public const string PipeName = "LDW.HostAgent.HyperVObserver.v1";
    public const int MaximumRequestCharacters = 256;
    public const int MaximumResponseCharacters = 4096;
    public const int MaximumSshCandidates = 4;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static string CreateRequestJson() =>
        JsonSerializer.Serialize(new HyperVObservationRequest(Version, Operation), JsonOptions);

    public static bool TryParseRequest(string json, out HyperVObservationRequest? request)
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

            var propertyCount = 0;
            foreach (var property in root.EnumerateObject())
            {
                propertyCount++;
                if (property.Name is not ("version" or "operation"))
                    return false;
            }

            if (propertyCount != 2
                || !root.TryGetProperty("version", out var version)
                || version.ValueKind != JsonValueKind.Number
                || version.GetInt32() != Version
                || !root.TryGetProperty("operation", out var operation)
                || operation.ValueKind != JsonValueKind.String
                || !string.Equals(operation.GetString(), Operation, StringComparison.Ordinal))
                return false;

            request = new HyperVObservationRequest(Version, Operation);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string CreateResponseJson(HyperVObservationResponse response) =>
        JsonSerializer.Serialize(response, JsonOptions);

    public static bool TryParseResponse(string json, out HyperVObservationResponse? response)
    {
        response = null;
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaximumResponseCharacters)
            return false;

        try
        {
            var parsed = JsonSerializer.Deserialize<HyperVObservationResponse>(json, JsonOptions);
            if (parsed is null
                || parsed.Version != Version
                || parsed.AddressCandidates is null
                || parsed.AddressCandidates.Count > 32)
                return false;

            response = parsed with
            {
                State = SanitizeState(parsed.State),
                AddressCandidates = HyperVGuestAddressPolicy.Filter(parsed.AddressCandidates)
            };
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static IReadOnlyList<string> SelectSshCandidates(HyperVObservationResponse response)
    {
        if (response.Version != Version || !response.Authorized || !response.VmExists || !response.Running)
            return Array.Empty<string>();

        return HyperVGuestAddressPolicy.Filter(response.AddressCandidates)
            .Take(MaximumSshCandidates)
            .ToArray();
    }

    private static string SanitizeState(string? state) => state switch
    {
        "Running" => "Running",
        "Off" => "Off",
        "Paused" => "Paused",
        "Saved" => "Saved",
        "Starting" => "Starting",
        "Stopping" => "Stopping",
        _ => "Unknown"
    };
}

public static class HyperVGuestAddressPolicy
{
    public static IReadOnlyList<string> Filter(IEnumerable<string?> candidates)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate) || !IPAddress.TryParse(candidate.Trim(), out var address))
                continue;
            if (!IsUsable(address))
                continue;

            var canonical = address.ToString();
            if (seen.Add(canonical))
                result.Add(canonical);
        }

        return result;
    }

    public static bool IsUsable(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return false;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] != 0
                && bytes[0] != 127
                && !(bytes[0] == 169 && bytes[1] == 254)
                && bytes[0] < 224
                && !address.Equals(IPAddress.Broadcast);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return !address.Equals(IPAddress.IPv6Any)
                && !address.IsIPv6LinkLocal
                && !address.IsIPv6Multicast;

        return false;
    }
}

public static class HyperVObserverAuthorizationPolicy
{
    private static readonly HashSet<string> RejectedBroadSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",       // Everyone
        "S-1-5-4",       // Interactive
        "S-1-5-11",      // Authenticated Users
        "S-1-5-32-545"   // Builtin Users
    };

    public static bool IsSafeExplicitUserSid(string? sid) =>
        !string.IsNullOrWhiteSpace(sid)
        && !RejectedBroadSids.Contains(sid)
        && sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
        && sid.Split('-').Length == 8
        && sid.Split('-').Skip(4).All(part => uint.TryParse(part, out _));

    public static bool IsPermittedCaller(string? callerSid, IEnumerable<string> configuredCallerSids) =>
        IsSafeExplicitUserSid(callerSid)
        && configuredCallerSids
            .Where(IsSafeExplicitUserSid)
            .Any(configured => string.Equals(configured, callerSid, StringComparison.OrdinalIgnoreCase));
}
