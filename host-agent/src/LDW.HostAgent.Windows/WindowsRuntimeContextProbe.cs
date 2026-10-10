using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal static class WindowsPrivilege
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

internal sealed class WindowsRuntimeContextProbe
{
    public RuntimeContext Observe()
    {
        var sessionId = Process.GetCurrentProcess().SessionId;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WtsInfoClass.WTSConnectState,
                out var buffer, out var bytes) || buffer == IntPtr.Zero || bytes < sizeof(int))
            return new RuntimeContext(OwnerSessionState.Unknown);
        try
        {
            var state = Marshal.ReadInt32(buffer);
            return new RuntimeContext(OwnerSessionStateMapper.FromWtsConnectState(state));
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private enum WtsInfoClass
    {
        WTSInitialProgram,
        WTSApplicationName,
        WTSWorkingDirectory,
        WTSOEMId,
        WTSSessionId,
        WTSUserName,
        WTSWinStationName,
        WTSDomainName,
        WTSConnectState
    }

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(
        IntPtr serverHandle,
        int sessionId,
        WtsInfoClass infoClass,
        out IntPtr buffer,
        out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
