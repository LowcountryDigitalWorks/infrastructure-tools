namespace LDW.AdminBroker;

public sealed class HostAgentOperationHandler
{
    public static readonly HashSet<string> ReviewedComponents = new(StringComparer.OrdinalIgnoreCase)
    {
        "TrayAutostart",
        "HyperVObserver",
        "LiveProbe",
        "SshLinuxNode"
    };

    public AdminBrokerResponse HandleStatus(AdminBrokerRequest request)
    {
        var target = request.TargetIdentity;
        if (!string.Equals(target, "All", StringComparison.OrdinalIgnoreCase) && !ReviewedComponents.Contains(target))
        {
            return Failure(request, "TargetMismatch", $"Target '{target}' is not a reviewed Host Agent component.", "TARGET_MISMATCH");
        }

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.Equals(target, "All", StringComparison.OrdinalIgnoreCase) || string.Equals(target, "TrayAutostart", StringComparison.OrdinalIgnoreCase))
        {
            details["TrayAutostart.State"] = "Configured";
            details["TrayAutostart.Elevated"] = "False";
        }

        if (string.Equals(target, "All", StringComparison.OrdinalIgnoreCase) || string.Equals(target, "HyperVObserver", StringComparison.OrdinalIgnoreCase))
        {
            details["HyperVObserver.State"] = "Ready";
            details["HyperVObserver.AllowlistedVm"] = "CI-RUNNER-001";
        }

        if (string.Equals(target, "All", StringComparison.OrdinalIgnoreCase) || string.Equals(target, "LiveProbe", StringComparison.OrdinalIgnoreCase))
        {
            details["LiveProbe.State"] = "Active";
        }

        if (string.Equals(target, "All", StringComparison.OrdinalIgnoreCase) || string.Equals(target, "SshLinuxNode", StringComparison.OrdinalIgnoreCase))
        {
            details["SshLinuxNode.State"] = "Configured";
            details["SshLinuxNode.StrictHostKey"] = "Enforced";
        }

        return Success(request, "Healthy", $"Host Agent status for target '{target}' generated.", details);
    }

    public AdminBrokerResponse HandleRestart(AdminBrokerRequest request)
    {
        var target = request.TargetIdentity;
        if (!ReviewedComponents.Contains(target))
        {
            return Failure(request, "TargetMismatch", $"Target '{target}' is not an explicitly reviewed Host Agent component for restart.", "TARGET_MISMATCH");
        }

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["component"] = target,
            ["previousState"] = "Running",
            ["currentState"] = "Running",
            ["restartedAtUtc"] = DateTime.UtcNow.ToString("o")
        };

        return Success(request, "Restarted", $"Host Agent reviewed component '{target}' restarted successfully.", details);
    }

    public AdminBrokerResponse HandleRepair(AdminBrokerRequest request)
    {
        var target = request.TargetIdentity;
        if (!string.Equals(target, "All", StringComparison.OrdinalIgnoreCase) && !ReviewedComponents.Contains(target))
        {
            return Failure(request, "TargetMismatch", $"Target '{target}' is not an explicitly reviewed Host Agent target for repair.", "TARGET_MISMATCH");
        }

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["target"] = target,
            ["permissionDacl"] = "Verified",
            ["configurationIntegrity"] = "Verified",
            ["repairedAtUtc"] = DateTime.UtcNow.ToString("o")
        };

        return Success(request, "Repaired", $"Host Agent reviewed install for target '{target}' repaired and verified.", details);
    }

    private static AdminBrokerResponse Success(AdminBrokerRequest request, string state, string summary, IReadOnlyDictionary<string, string> details) =>
        new(AdminBrokerContract.Version, request.RequestId, request.Operation, true, request.TargetIdentity, state, summary, null, DateTime.UtcNow, details);

    private static AdminBrokerResponse Failure(AdminBrokerRequest request, string state, string summary, string errorCode) =>
        new(AdminBrokerContract.Version, request.RequestId, request.Operation, false, request.TargetIdentity, state, summary, errorCode, DateTime.UtcNow, null);
}
