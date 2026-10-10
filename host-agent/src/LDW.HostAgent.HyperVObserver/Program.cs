using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using LDW.HostAgent.Core;
using Microsoft.Win32.SafeHandles;

namespace LDW.HostAgent.HyperVObserver;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || !HelperPrivilege.IsElevated())
            return 2;

        var configPath = HelperSettingsLoader.ResolvePath(args);
        var settings = HelperSettingsLoader.Load(configPath);
        if (settings is null)
            return 3;

        var server = new HyperVObserverPipeServer(settings.PermittedCallerSids, new FixedHyperVObservationSource());
        await server.RunAsync(CancellationToken.None);
        return 0;
    }
}

internal sealed record HelperSettings(IReadOnlyList<string> PermittedCallerSids);

internal static class HelperSettingsLoader
{
    private const string FileName = "hyperv-observer.Local.json";

    public static string ResolvePath(string[] args)
    {
        if (args.Length == 2 && string.Equals(args[0], "--config", StringComparison.Ordinal))
            return Path.GetFullPath(args[1]);
        if (args.Length != 0)
            return string.Empty;

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "LowcountryDigitalWorks",
            "HostAgent",
            FileName);
    }

    public static HelperSettings? Load(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.EnumerateObject().Any(property => property.Name != "permittedCallerSids")
                || !root.TryGetProperty("permittedCallerSids", out var sids)
                || sids.ValueKind != JsonValueKind.Array)
                return null;

            var configured = sids.EnumerateArray()
                .Where(value => value.ValueKind == JsonValueKind.String)
                .Select(value => value.GetString())
                .Where(HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid)
                .Select(value => value!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return configured is { Length: > 0 and <= 4 } ? new HelperSettings(configured) : null;
        }
        catch
        {
            return null;
        }
    }
}

internal static class HelperPrivilege
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true
            || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

internal interface IHyperVObservationSource
{
    ValueTask<HyperVObservationResponse> ObserveAsync(CancellationToken cancellationToken);
}

internal sealed class FixedHyperVObservationSource : IHyperVObservationSource
{
    private const int MaximumCapturedCharacters = 32 * 1024;
    internal const string FixedObservationScript = """
        $vm = Get-VM -Name 'CI-RUNNER-001' -ErrorAction SilentlyContinue
        if ($null -eq $vm) { Write-Output 'EXISTS=0'; exit 0 }
        Write-Output 'EXISTS=1'
        Write-Output ('STATE=' + $vm.State.ToString())
        if ($vm.State.ToString() -eq 'Running') {
            Get-VMNetworkAdapter -VMName 'CI-RUNNER-001' -ErrorAction SilentlyContinue |
                ForEach-Object { $_.IPAddresses } |
                ForEach-Object { Write-Output ('ADDRESS=' + $_) }
        }
        """;

    public async ValueTask<HyperVObservationResponse> ObserveAsync(CancellationToken cancellationToken)
    {
        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var executable = Path.Combine(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(executable))
            return Failure("observation-unavailable");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
        process.StartInfo.ArgumentList.Add("-NoLogo");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-Command");
        process.StartInfo.ArgumentList.Add(FixedObservationScript);

        try
        {
            if (!process.Start())
                return Failure("observation-unavailable");

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await process.WaitForExitAsync(timeout.Token);
            var stdout = Limit(await stdoutTask);
            _ = Limit(await stderrTask);
            if (process.ExitCode != 0)
                return Failure("observation-unavailable");

            return Parse(stdout);
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            return Failure("observation-unavailable");
        }
    }

    internal static HyperVObservationResponse Parse(string output)
    {
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var exists = lines.Contains("EXISTS=1", StringComparer.Ordinal);
        if (!exists)
            return new(HyperVObserverContract.Version, true, false, "Unknown", false, Array.Empty<string>());

        var rawState = lines.FirstOrDefault(line => line.StartsWith("STATE=", StringComparison.Ordinal));
        var state = rawState is null ? "Unknown" : rawState[6..];
        var running = string.Equals(state, "Running", StringComparison.Ordinal);
        var addresses = lines
            .Where(line => line.StartsWith("ADDRESS=", StringComparison.Ordinal))
            .Select(line => line[8..]);

        return new(
            HyperVObserverContract.Version,
            true,
            true,
            state,
            running,
            HyperVGuestAddressPolicy.Filter(addresses));
    }

    private static HyperVObservationResponse Failure(string errorCode) =>
        new(HyperVObserverContract.Version, true, false, "Unknown", false, Array.Empty<string>(), errorCode);

    private static string Limit(string value) =>
        value.Length <= MaximumCapturedCharacters ? value : value[..MaximumCapturedCharacters];
}

internal sealed class HyperVObserverPipeServer(
    IReadOnlyList<string> permittedCallerSids,
    IHyperVObservationSource observationSource)
{
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
            await ServeOneAsync(cancellationToken);
    }

    internal async Task ServeOneAsync(CancellationToken cancellationToken)
    {
        await using var pipe = SecurePipeFactory.CreateServer(permittedCallerSids);
        await pipe.WaitForConnectionAsync(cancellationToken);
        await HandleClientAsync(pipe, cancellationToken);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        var callerSid = TryGetCallerSid(pipe);
        if (!HyperVObserverAuthorizationPolicy.IsPermittedCaller(callerSid, permittedCallerSids))
        {
            await WriteResponseAsync(pipe, new(
                HyperVObserverContract.Version, false, false, "Unknown", false, Array.Empty<string>(), "unauthorized"), cancellationToken);
            return;
        }

        var request = await ReadBoundedLineAsync(pipe, HyperVObserverContract.MaximumRequestCharacters, cancellationToken);
        if (request is null || !HyperVObserverContract.TryParseRequest(request, out _))
        {
            await WriteResponseAsync(pipe, new(
                HyperVObserverContract.Version, true, false, "Unknown", false, Array.Empty<string>(), "invalid-request"), cancellationToken);
            return;
        }

        var response = await observationSource.ObserveAsync(cancellationToken);
        await WriteResponseAsync(pipe, response, cancellationToken);
    }

    private static string? TryGetCallerSid(NamedPipeServerStream pipe)
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
        HyperVObservationResponse response,
        CancellationToken cancellationToken)
    {
        var json = HyperVObserverContract.CreateResponseJson(response) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }
}

internal static class SecurePipeFactory
{
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint PipeTypeByte = 0x00000000;
    private const uint PipeReadModeByte = 0x00000000;
    private const uint PipeWait = 0x00000000;
    private const uint PipeRejectRemoteClients = 0x00000008;
    private const uint UnlimitedInstances = 1;
    private const int SddlRevision1 = 1;

    public static NamedPipeServerStream CreateServer(IReadOnlyList<string> permittedCallerSids)
    {
        var accessEntries = string.Concat(permittedCallerSids.Select(sid => $"(A;;GRGW;;;{sid})"));
        var sddl = $"D:P(A;;GA;;;SY)(A;;GA;;;BA){accessEntries}";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SddlRevision1, out var descriptor, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor,
                InheritHandle = false
            };
            var pipePath = $@"\\.\pipe\{HyperVObserverContract.PipeName}";
            var handle = CreateNamedPipe(
                pipePath,
                PipeAccessDuplex | FileFlagFirstPipeInstance | FileFlagOverlapped,
                PipeTypeByte | PipeReadModeByte | PipeWait | PipeRejectRemoteClients,
                UnlimitedInstances,
                4096,
                4096,
                0,
                ref attributes);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        int stringSdRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maximumInstances,
        uint outBufferSize,
        uint inBufferSize,
        uint defaultTimeout,
        ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
