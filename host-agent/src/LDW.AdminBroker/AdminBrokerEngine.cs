namespace LDW.AdminBroker;

public sealed class AdminBrokerEngine : IAdminBrokerEngine
{
    private readonly CodyncBotHandler _botHandler;
    private readonly HostAgentOperationHandler _hostAgentHandler;

    public AdminBrokerEngine(
        CodyncBotHandler botHandler,
        HostAgentOperationHandler hostAgentHandler)
    {
        _botHandler = botHandler ?? throw new ArgumentNullException(nameof(botHandler));
        _hostAgentHandler = hostAgentHandler ?? throw new ArgumentNullException(nameof(hostAgentHandler));
    }

    public Task<AdminBrokerResponse> ProcessRequestAsync(
        AdminBrokerRequest request,
        string? callerSid,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            return Task.FromResult(new AdminBrokerResponse(
                AdminBrokerContract.Version,
                "unknown",
                "UNKNOWN",
                false,
                "unknown",
                "InvalidRequest",
                "Null request received.",
                "NULL_REQUEST",
                DateTime.UtcNow,
                null));
        }

        AdminBrokerResponse response = request.Operation switch
        {
            AdminBrokerContract.Operations.CodyncBotCreate => _botHandler.HandleCreate(request),
            AdminBrokerContract.Operations.CodyncBotUpdate => _botHandler.HandleUpdate(request),
            AdminBrokerContract.Operations.CodyncBotDelete => _botHandler.HandleDelete(request),
            AdminBrokerContract.Operations.HostAgentStatus => _hostAgentHandler.HandleStatus(request),
            AdminBrokerContract.Operations.HostAgentRestartReviewedComponent => _hostAgentHandler.HandleRestart(request),
            AdminBrokerContract.Operations.HostAgentRepairReviewedInstall => _hostAgentHandler.HandleRepair(request),
            _ => new AdminBrokerResponse(
                AdminBrokerContract.Version,
                request.RequestId,
                request.Operation,
                false,
                request.TargetIdentity,
                "UnrecognizedOperation",
                $"Operation '{request.Operation}' is not supported by Admin Broker.",
                "UNRECOGNIZED_OPERATION",
                DateTime.UtcNow,
                null)
        };

        return Task.FromResult(response);
    }
}
