using System.IO.Pipes;

namespace LDW.AdminBroker;

public interface IAdminBrokerEngine
{
    Task<AdminBrokerResponse> ProcessRequestAsync(AdminBrokerRequest request, string? callerSid, CancellationToken cancellationToken);
}

/// <summary>Transport placeholder. No pipe listener or ACL is implemented in this version.</summary>
public sealed class AdminBrokerPipeServer
{
    public AdminBrokerPipeServer(IReadOnlyList<string> permittedCallerSids, IAdminBrokerEngine engine, AdminBrokerAuditLogger auditLogger)
    {
        ArgumentNullException.ThrowIfNull(permittedCallerSids);
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(auditLogger);
    }

    public Task ServeOneAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken) =>
        Task.FromException(new NotSupportedException("Named-pipe transport is unavailable; no ACL-backed listener is implemented."));

    public static string? TryGetCallerSid(NamedPipeServerStream pipe) => null;
}
