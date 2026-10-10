namespace LDW.HostAgent.Core;

public static class HyperVObserverServerIdentityPolicy
{
    public const string LocalSystemSid = "S-1-5-18";

    public static bool IsTrustedElevatedServer(bool elevated, string? serverSid, string? clientSid)
    {
        if (!elevated || string.IsNullOrWhiteSpace(serverSid))
            return false;

        if (string.Equals(serverSid, LocalSystemSid, StringComparison.OrdinalIgnoreCase))
            return true;

        return HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid(serverSid)
            && HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid(clientSid)
            && string.Equals(serverSid, clientSid, StringComparison.OrdinalIgnoreCase);
    }
}
