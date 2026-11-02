using System.Text.Json;

namespace LDW.AdminBroker;

public static class AdminPrivilegedRequestPolicy
{
    public static bool IsAllowed(AdminBrokerRequest request)
    {
        if (request is null) return false;
        if (request.Version != AdminBrokerContract.Version) return false;
        if (!Guid.TryParseExact(request.RequestId, "D", out _)) return false;
        if (!string.Equals(request.TargetIdentity, AdminPrivilegedControlContract.TargetIdentity, StringComparison.Ordinal))
            return false;

        if (request.Operation == AdminBrokerContract.Operations.AdminReviewedOperationRun)
        {
            if (request.Parameters is null) return false;
            if (request.Parameters.Count != 1) return false;

            string? opName = null;
            if (request.Parameters.TryGetValue("operationId", out var opVal) && opVal.ValueKind == JsonValueKind.String)
            {
                opName = opVal.GetString();
            }
            else if (request.Parameters.TryGetValue("reviewedOperation", out var revVal) && revVal.ValueKind == JsonValueKind.String)
            {
                opName = revVal.GetString();
            }
            else
            {
                return false;
            }

            if (!AdminReviewedOperationRegistry.IsValidOperation(opName))
                return false;

            return true;
        }

        if (request.Operation == AdminBrokerContract.Operations.AdminReviewedOperationGetResult)
        {
            if (request.Parameters is null) return false;
            if (request.Parameters.Count != 1) return false;

            string? corrId = null;
            if (request.Parameters.TryGetValue("correlationId", out var corrVal) && corrVal.ValueKind == JsonValueKind.String)
            {
                corrId = corrVal.GetString();
            }
            else if (request.Parameters.TryGetValue("operationId", out var opIdVal) && opIdVal.ValueKind == JsonValueKind.String)
            {
                corrId = opIdVal.GetString();
            }
            else
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(corrId) || !Guid.TryParseExact(corrId, "D", out _))
                return false;

            return true;
        }

        return false;
    }
}
