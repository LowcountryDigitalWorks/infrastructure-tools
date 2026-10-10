using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using LDW.HostAgent.Core;
using Microsoft.Win32.SafeHandles;

namespace LDW.HostAgent.Windows;

internal interface IHyperVObservationClient
{
    ValueTask<HyperVObservationResponse?> ObserveAsync(CancellationToken cancellationToken);
}

internal sealed class HyperVObservationClient : IHyperVObservationClient
{
    public async ValueTask<HyperVObservationResponse?> ObserveAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        await using var pipe = new NamedPipeClientStream(
            ".",
            HyperVObserverContract.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);

        try
        {
            await pipe.ConnectAsync(750, timeout.Token);
            if (!HyperVObserverServerIdentityVerifier.IsTrusted(pipe))
                return null;

            var request = Encoding.UTF8.GetBytes(HyperVObserverContract.CreateRequestJson() + "\n");
            await pipe.WriteAsync(request, timeout.Token);
            await pipe.FlushAsync(timeout.Token);
            var responseLine = await ReadBoundedLineAsync(
                pipe, HyperVObserverContract.MaximumResponseCharacters, timeout.Token);
            return responseLine is not null && HyperVObserverContract.TryParseResponse(responseLine, out var response)
                ? response
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<string?> ReadBoundedLineAsync(
        Stream stream,
        int maximumCharacters,
        CancellationToken cancellationToken)
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
}

internal static class HyperVObserverServerIdentityVerifier
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenElevationClass = 20;

    public static bool IsTrusted(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var processId) || processId == 0)
            return false;

        using var processHandle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (processHandle.IsInvalid)
            return false;
        if (!OpenProcessToken(processHandle, TokenQuery, out var tokenHandle))
            return false;
        using (tokenHandle)
        {
            if (!GetTokenInformation(
                    tokenHandle,
                    TokenElevationClass,
                    out var elevation,
                    Marshal.SizeOf<TokenElevation>(),
                    out _))
                return false;

            string? serverSid;
            try
            {
                using var serverIdentity = new WindowsIdentity(tokenHandle.DangerousGetHandle());
                serverSid = serverIdentity.User?.Value;
            }
            catch
            {
                return false;
            }

            string? clientSid;
            try
            {
                using var clientIdentity = WindowsIdentity.GetCurrent();
                clientSid = clientIdentity.User?.Value;
            }
            catch
            {
                return false;
            }

            return HyperVObserverServerIdentityPolicy.IsTrustedElevatedServer(
                elevation.TokenIsElevated != 0,
                serverSid,
                clientSid);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenElevation
    {
        public int TokenIsElevated;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        out TokenElevation tokenInformation,
        int tokenInformationLength,
        out int returnLength);
}
