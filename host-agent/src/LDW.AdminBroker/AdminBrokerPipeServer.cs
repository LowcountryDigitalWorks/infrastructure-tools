using System.IO.Pipes;
using System.Security.Principal;
using System.Text;

namespace LDW.AdminBroker;

public interface IAdminBrokerEngine
{
    Task<AdminBrokerResponse> ProcessRequestAsync(AdminBrokerRequest request, string? callerSid, CancellationToken cancellationToken);
}

/// <summary>One-request-at-a-time, current-user-only local transport. Operations remain unavailable.</summary>
public sealed class AdminBrokerPipeServer
{
    private readonly string _ownerSid;
    private readonly IAdminBrokerEngine _engine;
    private readonly AdminBrokerAuditLogger _auditLogger;

    public AdminBrokerPipeServer(IReadOnlyList<string> permittedCallerSids, IAdminBrokerEngine engine, AdminBrokerAuditLogger auditLogger)
        : this(permittedCallerSids, engine, auditLogger, allowElevatedTestProcess: false)
    {
    }

    // The hosted contract test runs on a Windows runner whose account is elevated. This
    // internal test-only seam lets that suite exercise pipe framing and caller checks;
    // the production constructor always enforces the unelevated-process requirement.
    internal AdminBrokerPipeServer(IReadOnlyList<string> permittedCallerSids, IAdminBrokerEngine engine,
        AdminBrokerAuditLogger auditLogger, bool allowElevatedTestProcess)
    {
        ArgumentNullException.ThrowIfNull(permittedCallerSids);
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The Admin Broker transport requires Windows.");

        var processIdentity = WindowsIdentity.GetCurrent();
        if (!allowElevatedTestProcess && new WindowsPrincipal(processIdentity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("The Admin Broker transport must run unelevated.");
        var currentSid = processIdentity.User?.Value;
        if (currentSid is null || !AdminBrokerAuthorizationPolicy.IsSafeExplicitUserSid(currentSid)
            || permittedCallerSids.Count != 1
            || !string.Equals(permittedCallerSids[0], currentSid, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The broker must be bound to the current explicit owner SID.");

        _ownerSid = currentSid;
    }

    public NamedPipeServerStream CreateServerPipe() => new(
        AdminBrokerContract.PipeName,
        PipeDirection.InOut,
        1,
        PipeTransmissionMode.Byte,
        PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
        4096,
        4096);

    public Task ServeOneAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken) =>
        ServeOneAsync(pipe, cancellationToken, TryGetCallerSid);

    internal async Task ServeOneAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken,
        Func<NamedPipeServerStream, string?> callerSidResolver)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(callerSidResolver);
        if (!pipe.IsConnected)
            await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

        var callerSid = callerSidResolver(pipe);
        if (!AdminBrokerAuthorizationPolicy.IsPermittedCaller(callerSid, [_ownerSid]))
            return;

        var framed = await ReadFrameAsync(pipe, AdminBrokerContract.MaximumRequestCharacters, cancellationToken).ConfigureAwait(false);
        if (framed is null || !AdminBrokerContract.TryParseRequest(framed, out var request) || request is null)
        {
            var invalid = new AdminBrokerResponse(AdminBrokerContract.Version, Guid.NewGuid().ToString("D"),
                "CODYNC_BOT_CREATE", false, "redacted", "InvalidRequest", "Request rejected.",
                "MALFORMED_REQUEST", DateTime.UtcNow, null);
            _auditLogger.Log(new AuditRecord(DateTime.UtcNow, invalid.RequestId, invalid.Operation, "redacted", callerSid,
                false, invalid.ResultState, invalid.ErrorCode, invalid.Summary));
            await WriteResponseAsync(pipe, invalid, cancellationToken).ConfigureAwait(false);
            return;
        }

        // Caller identity, parsing, policy and schema validation all complete before the engine sees the request.
        if (!AdminBrokerRequestPolicy.IsAllowed(request))
        {
            var rejected = new AdminBrokerResponse(AdminBrokerContract.Version, request.RequestId, request.Operation,
                false, "redacted", "InvalidRequest", "Request rejected.", "POLICY_REJECTED", DateTime.UtcNow, null);
            _auditLogger.Log(new AuditRecord(DateTime.UtcNow, request.RequestId, request.Operation, request.TargetIdentity,
                callerSid, false, rejected.ResultState, rejected.ErrorCode, rejected.Summary));
            await WriteResponseAsync(pipe, rejected, cancellationToken).ConfigureAwait(false);
            return;
        }

        var response = await _engine.ProcessRequestAsync(request, callerSid, cancellationToken).ConfigureAwait(false);
        _auditLogger.Log(new AuditRecord(DateTime.UtcNow, response.RequestId, response.Operation, request.TargetIdentity,
            callerSid, response.Success, response.ResultState, response.ErrorCode, response.Summary));
        await WriteResponseAsync(pipe, response, cancellationToken).ConfigureAwait(false);
    }

    public static string? TryGetCallerSid(NamedPipeServerStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!OperatingSystem.IsWindows() || !pipe.IsConnected)
            return null;

        try { return GetWindowsCallerSid(pipe); }
        catch
        {
            return null;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? GetWindowsCallerSid(NamedPipeServerStream pipe)
    {
        string? value = null;
        pipe.RunAsClient(() => value = WindowsIdentity.GetCurrent(false)?.User?.Value);
        return AdminBrokerAuthorizationPolicy.IsSafeExplicitUserSid(value) ? value : null;
    }

    private static async Task<string?> ReadFrameAsync(Stream stream, int maximumCharacters, CancellationToken cancellationToken)
    {
        var maximumBytes = checked(maximumCharacters * 4 + 1);
        var buffer = new byte[maximumBytes];
        var count = 0;
        while (count < maximumBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(count, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return null;
            if (buffer[count++] == (byte)'\n')
            {
                try
                {
                    var text = new UTF8Encoding(false, true).GetString(buffer, 0, count - 1);
                    return text.Length <= maximumCharacters ? text : null;
                }
                catch (DecoderFallbackException) { return null; }
            }
        }

        return null;
    }

    private static async Task WriteResponseAsync(Stream stream, AdminBrokerResponse response, CancellationToken cancellationToken)
    {
        var json = AdminBrokerContract.CreateResponseJson(response);
        if (json.Length > AdminBrokerContract.MaximumResponseCharacters)
            throw new InvalidOperationException("The broker response exceeds its fixed bound.");
        var bytes = Encoding.UTF8.GetBytes(json + "\n");
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
