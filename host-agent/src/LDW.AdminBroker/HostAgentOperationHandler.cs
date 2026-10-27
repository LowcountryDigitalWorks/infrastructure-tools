namespace LDW.AdminBroker;

/// <summary>
/// Closed Host Agent CI/JIT operation boundary. The default adapter is intentionally unavailable;
/// a separately reviewed local adapter must be injected before any runtime mutation is possible.
/// </summary>
public sealed class HostAgentOperationHandler
{
    private readonly ICiJitControlAdapter _ciJit;

    public HostAgentOperationHandler()
        : this(new UnavailableCiJitControlAdapter())
    {
    }

    public HostAgentOperationHandler(ICiJitControlAdapter ciJit)
    {
        _ciJit = ciJit ?? throw new ArgumentNullException(nameof(ciJit));
    }

    public AdminBrokerResponse Process(AdminBrokerRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(request);

        if (!CiJitControlContract.IsOperation(request.Operation)
            || !string.Equals(request.TargetIdentity, CiJitControlContract.TargetIdentity, StringComparison.Ordinal))
            return Failure(request, "BLOCKED", "TARGET_REFUSED");

        CiJitControlResult result;
        try
        {
            result = request.Operation switch
            {
                AdminBrokerContract.Operations.CiJitStatus => _ciJit.GetStatus(cancellationToken),
                AdminBrokerContract.Operations.CiJitDiscover => _ciJit.Discover(cancellationToken),
                AdminBrokerContract.Operations.CiJitRunOnce => _ciJit.RunOnce(cancellationToken),
                AdminBrokerContract.Operations.CiJitRecover => _ciJit.Recover(cancellationToken),
                AdminBrokerContract.Operations.CiJitAbortActive => _ciJit.AbortActive(cancellationToken),
                AdminBrokerContract.Operations.CiJitListStale => _ciJit.ListStale(cancellationToken),
                AdminBrokerContract.Operations.CiJitRetireStale => _ciJit.RetireStale(
                    request.Parameters!["runId"].GetInt64(), cancellationToken),
                AdminBrokerContract.Operations.CiJitGetOperationResult => _ciJit.GetOperationResult(
                    Guid.ParseExact(request.Parameters!["operationId"].GetString()!, "D"), cancellationToken),
                _ => new CiJitControlResult(false, "BLOCKED", "TARGET_REFUSED")
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return Failure(request, "FAILED", "FAILED");
        }

        if (!CiJitControlContract.IsSafeResult(result))
            return Failure(request, "FAILED", "INVALID_ADAPTER_RESULT");

        return new AdminBrokerResponse(
            AdminBrokerContract.Version,
            request.RequestId,
            request.Operation,
            result.Success,
            CiJitControlContract.TargetIdentity,
            result.ResultState,
            result.Success ? "CI/JIT operation completed." : "CI/JIT operation refused.",
            result.Success ? null : result.ReasonCode,
            DateTime.UtcNow,
            CiJitControlContract.CreateDetails(result));
    }

    private static AdminBrokerResponse Failure(AdminBrokerRequest request, string state, string code) =>
        new(
            AdminBrokerContract.Version,
            request.RequestId,
            request.Operation,
            false,
            CiJitControlContract.TargetIdentity,
            state,
            "CI/JIT operation refused.",
            code,
            DateTime.UtcNow,
            null);
}
