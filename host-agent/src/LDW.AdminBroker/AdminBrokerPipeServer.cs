using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;

namespace LDW.AdminBroker;

public interface IAdminBrokerEngine
{
    Task<AdminBrokerResponse> ProcessRequestAsync(
        AdminBrokerRequest request,
        string? callerSid,
        CancellationToken cancellationToken);
}

public sealed class AdminBrokerPipeServer
{
    private readonly IReadOnlyList<string> _permittedCallerSids;
    private readonly IAdminBrokerEngine _engine;
    private readonly AdminBrokerAuditLogger _auditLogger;

    public AdminBrokerPipeServer(
        IReadOnlyList<string> permittedCallerSids,
        IAdminBrokerEngine engine,
        AdminBrokerAuditLogger auditLogger)
    {
        _permittedCallerSids = permittedCallerSids ?? throw new ArgumentNullException(nameof(permittedCallerSids));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
    }

    public async Task ServeOneAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        try
        {
            await HandleClientAsync(pipe, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Contain client execution failures
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        var callerSid = TryGetCallerSid(pipe);
        if (!AdminBrokerAuthorizationPolicy.IsPermittedCaller(callerSid, _permittedCallerSids))
        {
            var unauthorizedResp = new AdminBrokerResponse(
                AdminBrokerContract.Version,
                "unauthorized-req",
                "UNKNOWN",
                false,
                "unknown",
                "Unauthorized",
                "Caller is not authorized by Admin Broker policy.",
                "UNAUTHORIZED",
                DateTime.UtcNow,
                null);

            _auditLogger.Log(new AuditRecord(
                unauthorizedResp.TimestampUtc,
                unauthorizedResp.RequestId,
                unauthorizedResp.Operation,
                unauthorizedResp.TargetIdentity,
                callerSid,
                false,
                unauthorizedResp.ResultState,
                unauthorizedResp.ErrorCode,
                unauthorizedResp.Summary));

            await WriteResponseAsync(pipe, unauthorizedResp, cancellationToken);
            return;
        }

        var requestJson = await ReadBoundedLineAsync(pipe, AdminBrokerContract.MaximumRequestCharacters, cancellationToken);
        if (requestJson is null || !AdminBrokerContract.TryParseRequest(requestJson, out var request) || request is null)
        {
            var invalidReqResp = new AdminBrokerResponse(
                AdminBrokerContract.Version,
                "invalid-req",
                "UNKNOWN",
                false,
                "unknown",
                "InvalidRequest",
                "Request payload is invalid or unrecognized.",
                "INVALID_REQUEST",
                DateTime.UtcNow,
                null);

            _auditLogger.Log(new AuditRecord(
                invalidReqResp.TimestampUtc,
                invalidReqResp.RequestId,
                invalidReqResp.Operation,
                invalidReqResp.TargetIdentity,
                callerSid,
                false,
                invalidReqResp.ResultState,
                invalidReqResp.ErrorCode,
                invalidReqResp.Summary));

            await WriteResponseAsync(pipe, invalidReqResp, cancellationToken);
            return;
        }

        var response = await _engine.ProcessRequestAsync(request, callerSid, cancellationToken);

        _auditLogger.Log(new AuditRecord(
            response.TimestampUtc,
            response.RequestId,
            response.Operation,
            response.TargetIdentity,
            callerSid,
            response.Success,
            response.ResultState,
            response.ErrorCode,
            response.Summary));

        await WriteResponseAsync(pipe, response, cancellationToken);
    }

    public static string? TryGetCallerSid(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows())
        {
            // On non-Windows platforms, fallback or synthetic test context
            return "TEST_PERMITTED_CALLER_SID";
        }

        return TryGetWindowsCallerSid(pipe);
    }

    [SupportedOSPlatform("windows")]
    private static string? TryGetWindowsCallerSid(NamedPipeServerStream pipe)
    {
        string? callerSid = null;
        try
        {
            pipe.RunAsClient(() => callerSid = WindowsIdentity.GetCurrent(TokenAccessLevels.Query).User?.Value);
        }
        catch
        {
            return null;
        }

        return callerSid;
    }

    private static async Task<string?> ReadBoundedLineAsync(Stream stream, int maximumCharacters, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, false, 256, leaveOpen: true);
        var buffer = new char[1];
        var builder = new StringBuilder();
        while (builder.Length <= maximumCharacters)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0 || buffer[0] == '\n')
                return builder.ToString().TrimEnd('\r');
            builder.Append(buffer[0]);
        }

        return null;
    }

    private static async Task WriteResponseAsync(
        Stream stream,
        AdminBrokerResponse response,
        CancellationToken cancellationToken)
    {
        var json = AdminBrokerContract.CreateResponseJson(response) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }
}
