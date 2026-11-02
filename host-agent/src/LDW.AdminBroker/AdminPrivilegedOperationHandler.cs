namespace LDW.AdminBroker;

public sealed class AdminPrivilegedOperationHandler
{
    private readonly IAdminPrivilegedControlAdapter _adapter;

    public AdminPrivilegedOperationHandler()
        : this(new UnavailableAdminPrivilegedControlAdapter())
    {
    }

    public AdminPrivilegedOperationHandler(IAdminPrivilegedControlAdapter adapter)
    {
        _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
    }

    public AdminBrokerResponse Process(AdminBrokerRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(request);

        if (!AdminPrivilegedControlContract.IsOperation(request.Operation)
            || !string.Equals(request.TargetIdentity, AdminPrivilegedControlContract.TargetIdentity, StringComparison.Ordinal))
        {
            return Failure(request, "BLOCKED", "TARGET_REFUSED");
        }

        if (!AdminPrivilegedRequestPolicy.IsAllowed(request))
        {
            return Failure(request, "BLOCKED", "POLICY_REJECTED");
        }

        AdminPrivilegedControlResult result;
        try
        {
            if (request.Operation == AdminBrokerContract.Operations.AdminReviewedOperationRun)
            {
                var opId = request.Parameters!.ContainsKey("operationId")
                    ? request.Parameters["operationId"].GetString()!
                    : request.Parameters["reviewedOperation"].GetString()!;
                var correlationId = Guid.ParseExact(request.RequestId, "D");
                result = _adapter.RunReviewedOperation(opId, correlationId, cancellationToken);
            }
            else if (request.Operation == AdminBrokerContract.Operations.AdminReviewedOperationGetResult)
            {
                var corrStr = request.Parameters!.ContainsKey("correlationId")
                    ? request.Parameters["correlationId"].GetString()!
                    : request.Parameters["operationId"].GetString()!;
                var correlationId = Guid.ParseExact(corrStr, "D");
                result = _adapter.GetOperationResult(correlationId, cancellationToken);
            }
            else
            {
                result = new AdminPrivilegedControlResult(false, "BLOCKED", "TARGET_REFUSED");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return Failure(request, "FAILED", "FAILED");
        }

        if (!AdminPrivilegedControlContract.IsSafeResult(result))
        {
            return Failure(request, "FAILED", "INVALID_ADAPTER_RESULT");
        }

        return new AdminBrokerResponse(
            AdminBrokerContract.Version,
            request.RequestId,
            request.Operation,
            result.Success,
            AdminPrivilegedControlContract.TargetIdentity,
            result.ResultState,
            result.Success ? "Privileged operation completed." : "Privileged operation refused.",
            result.Success ? null : result.ReasonCode,
            DateTime.UtcNow,
            AdminPrivilegedControlContract.CreateDetails(result));
    }

    private static AdminBrokerResponse Failure(AdminBrokerRequest request, string state, string code) =>
        new(
            AdminBrokerContract.Version,
            request.RequestId,
            request.Operation,
            false,
            AdminPrivilegedControlContract.TargetIdentity,
            state,
            "Privileged operation refused.",
            code,
            DateTime.UtcNow,
            null);
}
