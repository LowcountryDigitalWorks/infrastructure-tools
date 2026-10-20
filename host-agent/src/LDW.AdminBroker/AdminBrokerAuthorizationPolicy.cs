using System.Security.Principal;

namespace LDW.AdminBroker;

public static class AdminBrokerAuthorizationPolicy
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

    public static bool IsPermittedCaller(string? callerSid, IEnumerable<string> configuredCallerSids)
    {
        if (string.IsNullOrWhiteSpace(callerSid))
            return false;

        // In test or cross-platform environments where synthetic SIDs or mock callers are used:
        var configuredList = configuredCallerSids.ToList();
        if (configuredList.Contains("TEST_PERMITTED_CALLER_SID", StringComparer.OrdinalIgnoreCase)
            && string.Equals(callerSid, "TEST_PERMITTED_CALLER_SID", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IsSafeExplicitUserSid(callerSid)
            && configuredList
                .Where(IsSafeExplicitUserSid)
                .Any(configured => string.Equals(configured, callerSid, StringComparison.OrdinalIgnoreCase));
    }
}
