using System.Collections.Concurrent;

namespace LDW.AdminBroker;

public sealed class AdminBrokerEngine : IAdminBrokerEngine
{
    private readonly ConcurrentDictionary<string, (DateTime Expires, AdminBrokerResponse Response)> _requests = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _requestLock = new();
    private readonly HostAgentOperationHandler _hostAgentHandler;
    private static readonly TimeSpan ReplayTtl = TimeSpan.FromMinutes(2);

    public AdminBrokerEngine(CodyncBotHandler botHandler, HostAgentOperationHandler hostAgentHandler)
    {
        ArgumentNullException.ThrowIfNull(botHandler);
        _hostAgentHandler = hostAgentHandler ?? throw new ArgumentNullException(nameof(hostAgentHandler));
    }

    public Task<AdminBrokerResponse> ProcessRequestAsync(AdminBrokerRequest request, string? callerSid, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (!Guid.TryParseExact(request.RequestId, "D", out _))
            return Task.FromResult(Failure(request, "InvalidRequest", "Request ID must be a UUID.", "INVALID_REQUEST_ID"));
        if (CiJitControlContract.IsOperation(request.Operation) && !AdminBrokerRequestPolicy.IsAllowed(request))
            return Task.FromResult(Failure(request, "InvalidRequest", "Request rejected.", "POLICY_REJECTED"));

        lock (_requestLock)
        {
            var now = DateTime.UtcNow;
            foreach (var item in _requests)
                if (item.Value.Expires <= now) _requests.TryRemove(item.Key, out _);
            if (_requests.TryGetValue(request.RequestId, out var prior))
                return Task.FromResult(prior.Response with { ResultState = "DuplicateRequest", Summary = "Request ID already processed.", ErrorCode = "DUPLICATE_REQUEST" });

            var response = CiJitControlContract.IsOperation(request.Operation)
                ? _hostAgentHandler.Process(request, cancellationToken)
                : Failure(request, "Unavailable", "No reviewed local adapter or broker transport is available.", "NOT_IMPLEMENTED");
            _requests[request.RequestId] = (now + ReplayTtl, response);
            return Task.FromResult(response);
        }
    }

    private static AdminBrokerResponse Failure(AdminBrokerRequest r, string state, string summary, string code) =>
        new(AdminBrokerContract.Version, r.RequestId, r.Operation, false, r.TargetIdentity, state, summary, code, DateTime.UtcNow, null);
}
