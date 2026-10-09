using System.Diagnostics;
using System.Runtime.InteropServices;
using LDW.HostAgent.Core;

namespace LDW.HostAgent.Windows;

internal sealed class WindowsSystemProbe : ISystemProbe
{
    private DateTimeOffset? _pressureSince;

    public async ValueTask<SystemTelemetry> ObserveAsync(CancellationToken cancellationToken)
    {
        var memory = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        if (!GlobalMemoryStatusEx(ref memory))
            throw new InvalidOperationException($"GlobalMemoryStatusEx failed: {Marshal.GetLastWin32Error()}");
        var performance = new PerformanceInformation { Size = (uint)Marshal.SizeOf<PerformanceInformation>() };
        if (!GetPerformanceInfo(ref performance, performance.Size))
            throw new InvalidOperationException($"GetPerformanceInfo failed: {Marshal.GetLastWin32Error()}");

        var before = ReadCpuTimes();
        await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
        var after = ReadCpuTimes();
        var total = after.Kernel + after.User - before.Kernel - before.User;
        var idle = after.Idle - before.Idle;
        double? cpu = total == 0 ? null : Math.Clamp((total - idle) * 100d / total, 0, 100);

        var disks = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType is DriveType.Fixed)
            .Select(d => new DiskTelemetry(d.Name, (ulong)d.TotalSize, (ulong)d.AvailableFreeSpace))
            .ToArray();
        var observedAt = DateTimeOffset.UtcNow;
        var commitLimit = performance.CommitLimit.ToUInt64();
        var commitTotal = performance.CommitTotal.ToUInt64();
        var pageSize = performance.PageSize.ToUInt64();
        var commitLimitBytes = commitLimit * pageSize;
        var commitTotalBytes = commitTotal * pageSize;
        var commitHeadroom = commitLimitBytes == 0 ? (double?)null
            : Math.Clamp((commitLimitBytes - Math.Min(commitLimitBytes, commitTotalBytes)) * 100d / commitLimitBytes, 0, 100);
        var lowAvailable = memory.TotalPhysical > 0 && memory.AvailablePhysical * 100d / memory.TotalPhysical < 10;
        var lowCommitHeadroom = commitHeadroom is < 10;
        if (lowAvailable || lowCommitHeadroom)
            _pressureSince ??= observedAt;
        else
            _pressureSince = null;
        var sustainedFor = _pressureSince is { } since ? observedAt - since : TimeSpan.Zero;
        return new SystemTelemetry(
            observedAt,
            memory.TotalPhysical,
            memory.AvailablePhysical,
            cpu,
            disks,
            new MemoryPressureTelemetry(commitHeadroom, null, null, null, null, sustainedFor,
                "Windows available memory and commit headroom are sampled; paging rates are not yet available."));
    }

    private static CpuTimes ReadCpuTimes()
    {
        if (!GetSystemTimes(out var idle, out var kernel, out var user))
            throw new InvalidOperationException($"GetSystemTimes failed: {Marshal.GetLastWin32Error()}");
        return new CpuTimes(ToUInt64(idle), ToUInt64(kernel), ToUInt64(user));
    }

    private static ulong ToUInt64(NativeFileTime value) => ((ulong)value.High << 32) | value.Low;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PerformanceInformation
    {
        public uint Size;
        public UIntPtr CommitTotal;
        public UIntPtr CommitLimit;
        public UIntPtr CommitPeak;
        public UIntPtr PhysicalTotal;
        public UIntPtr PhysicalAvailable;
        public UIntPtr SystemCache;
        public UIntPtr KernelTotal;
        public UIntPtr KernelPaged;
        public UIntPtr KernelNonpaged;
        public UIntPtr PageSize;
        public uint HandleCount;
        public uint ProcessCount;
        public uint ThreadCount;
    }

    private readonly record struct CpuTimes(ulong Idle, ulong Kernel, ulong User);
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime { public uint Low; public uint High; }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetPerformanceInfo(ref PerformanceInformation performanceInformation, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out NativeFileTime idle,
        out NativeFileTime kernel,
        out NativeFileTime user);
}
