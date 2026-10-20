namespace LDW.HostAgent.AdminBroker.Core;

public sealed record AdminBrokerAllowlist(
    IReadOnlyList<string> PermittedOwnerSids,
    IReadOnlyList<string> CodyncBotIds,
    IReadOnlyList<string> HostAgentComponentIds,
    IReadOnlyList<string> ReviewedReleaseIds);

public static class AdminBrokerAuthorizationPolicy
{
    private static readonly HashSet<string> RejectedBroadSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",
        "S-1-5-4",
        "S-1-5-11",
        "S-1-5-32-545"
    };

    public static bool IsSafeExplicitUserSid(string? sid) =>
        !string.IsNullOrWhiteSpace(sid)
        && !RejectedBroadSids.Contains(sid)
        && sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
        && sid.Split('-').Length == 8
        && sid.Split('-').Skip(4).All(part => uint.TryParse(part, out _));

    public static bool IsPermittedCaller(string? callerSid, AdminBrokerAllowlist allowlist) =>
        IsSafeExplicitUserSid(callerSid)
        && allowlist.PermittedOwnerSids.Where(IsSafeExplicitUserSid)
            .Any(configured => string.Equals(configured, callerSid, StringComparison.OrdinalIgnoreCase));

    public static bool IsAllowedTarget(AdminBrokerRequest request, AdminBrokerAllowlist allowlist) => request.Operation switch
    {
        AdminBrokerOperation.CodyncBotCreate => request.TargetId == "codync"
            && request.Inputs.TryGetValue("definitionId", out var createDefinition)
            && createDefinition == "codync-smoke-test",
        AdminBrokerOperation.CodyncBotUpdate or AdminBrokerOperation.CodyncBotDelete => request.TargetId == "codync"
            && request.Inputs.TryGetValue("botId", out var botId)
            && allowlist.CodyncBotIds.Contains(botId, StringComparer.Ordinal),
        AdminBrokerOperation.HostAgentStatus => request.TargetId == "ldw01",
        AdminBrokerOperation.HostAgentRestartReviewedComponent => request.TargetId == "host-agent"
            && request.Inputs.TryGetValue("componentId", out var componentId)
            && allowlist.HostAgentComponentIds.Contains(componentId, StringComparer.Ordinal),
        AdminBrokerOperation.HostAgentRepairReviewedInstall => request.TargetId == "host-agent"
            && request.Inputs.TryGetValue("releaseId", out var releaseId)
            && allowlist.ReviewedReleaseIds.Contains(releaseId, StringComparer.Ordinal),
        _ => false
    };
}
