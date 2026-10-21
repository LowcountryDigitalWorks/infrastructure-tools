using System.IO.Pipes;
using System.Net;
using System.Security.Principal;
using System.Text;
using LDW.HostAgent.Core;
using LDW.HostAgent.HyperVObserver;

var assertions = 0;

Assert(HyperVObserverContract.TryParseRequest(HyperVObserverContract.CreateRequestJson(), out _),
    "fixed observation request round-trips");
Assert(!HyperVObserverContract.TryParseRequest("{\"version\":1,\"operation\":\"observe-other-vm\"}", out _),
    "unknown VM operation is rejected");
Assert(!HyperVObserverContract.TryParseRequest(
        "{\"version\":1,\"operation\":\"observe-ci-runner-001\",\"command\":\"Get-VM\"}", out _),
    "request contract rejects arbitrary command fields");

var filtered = HyperVGuestAddressPolicy.Filter([
    null, "", "not-an-address", "0.0.0.0", "127.0.0.1", "169.254.1.2", "224.0.0.1",
    "::", "::1", "fe80::1", "ff02::1", "192.0.2.10", "2001:db8::10", "192.0.2.10"
]);
Assert(filtered.SequenceEqual(["192.0.2.10", "2001:db8::10"]),
    "address policy rejects unusable candidates and de-duplicates usable candidates");

var running = new HyperVObservationResponse(
    HyperVObserverContract.Version, true, true, "Running", true,
    ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"]);
Assert(HyperVObserverContract.SelectSshCandidates(running).Count == HyperVObserverContract.MaximumSshCandidates,
    "SSH candidate selection is bounded");
Assert(HyperVObserverContract.SelectSshCandidates(running with { Running = false }).Count == 0,
    "non-running VM fails closed");
Assert(HyperVObserverContract.SelectSshCandidates(running with { Authorized = false }).Count == 0,
    "unauthorized response fails closed");

const string ownerSid = "S-1-5-21-1-2-3-1001";
const string otherSid = "S-1-5-21-1-2-3-1002";
Assert(HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid(ownerSid),
    "explicit account SID is accepted");
Assert(HyperVObserverAuthorizationPolicy.IsPermittedCaller(ownerSid, [ownerSid]),
    "matching configured caller SID is authorized");
Assert(!HyperVObserverAuthorizationPolicy.IsPermittedCaller(otherSid, [ownerSid]),
    "unknown caller SID is denied");
Assert(!HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid("S-1-1-0")
       && !HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid("S-1-5-11")
       && !HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid("S-1-5-32-545"),
    "broad well-known groups cannot be configured");
Assert(HyperVObserverServerIdentityPolicy.IsTrustedElevatedServer(true, ownerSid, ownerSid),
    "tray trusts an elevated helper under its own explicit user SID");
Assert(HyperVObserverServerIdentityPolicy.IsTrustedElevatedServer(true, HyperVObserverServerIdentityPolicy.LocalSystemSid, ownerSid),
    "tray can trust an elevated LocalSystem helper for a future separately gated install");
Assert(!HyperVObserverServerIdentityPolicy.IsTrustedElevatedServer(false, ownerSid, ownerSid),
    "tray rejects a same-user non-elevated pipe server");
Assert(!HyperVObserverServerIdentityPolicy.IsTrustedElevatedServer(true, otherSid, ownerSid),
    "tray rejects an elevated helper running under an unexpected user SID");

var configPath = Path.Combine(Path.GetTempPath(), $"ldw-hyperv-observer-{Guid.NewGuid():N}.json");
try
{
    await File.WriteAllTextAsync(configPath,
        "{\"permittedCallerSids\":[\"S-1-5-21-1-2-3-1001\",\"S-1-5-11\"]}");
    var settings = HelperSettingsLoader.Load(configPath);
    Assert(settings?.PermittedCallerSids.SequenceEqual([ownerSid]) == true,
        "helper config keeps explicit owner SID and rejects broad group entries");
}
finally
{
    try { File.Delete(configPath); } catch { }
}

var fixedScript = FixedHyperVObservationSource.FixedObservationScript;
Assert(fixedScript.Contains("Get-VM -Name 'CI-RUNNER-001'", StringComparison.Ordinal)
       && fixedScript.Contains("Get-VMNetworkAdapter -VMName 'CI-RUNNER-001'", StringComparison.Ordinal),
    "privileged source hardcodes the only allowlisted VM");
foreach (var prohibited in new[]
         {
             "Start-VM", "Stop-VM", "Restart-VM", "Set-VM", "Checkpoint-VM", "Remove-VM", "New-VM",
             "Set-VMNetworkAdapter", "Enable-VM", "Disable-VM", "Invoke-Command", "Start-Process"
         })
{
    Assert(!fixedScript.Contains(prohibited, StringComparison.OrdinalIgnoreCase),
        $"fixed script excludes {prohibited}");
}

var parsed = FixedHyperVObservationSource.Parse(
    "EXISTS=1\r\nSTATE=Running\r\nADDRESS=192.0.2.25\r\nADDRESS=fe80::1\r\n");
Assert(parsed.Authorized && parsed.VmExists && parsed.Running,
    "fixed source parser maps running state");
Assert(parsed.AddressCandidates.SequenceEqual(["192.0.2.25"]),
    "fixed source parser filters before IPC");
var absent = FixedHyperVObservationSource.Parse("EXISTS=0\r\n");
Assert(!absent.VmExists && HyperVObserverContract.SelectSshCandidates(absent).Count == 0,
    "absent allowlisted VM cannot supply SSH candidates");
var malformed = FixedHyperVObservationSource.Parse("STATE=Running\r\n");
Assert(!malformed.VmExists && HyperVObserverContract.SelectSshCandidates(malformed).Count == 0,
    "missing existence evidence remains fail-closed for SSH candidate selection");

if (OperatingSystem.IsWindows())
{
    using var identity = WindowsIdentity.GetCurrent();
    var currentSid = identity.User?.Value ?? throw new InvalidOperationException("Current SID unavailable.");
    Assert(HyperVObserverAuthorizationPolicy.IsSafeExplicitUserSid(currentSid),
        "test caller is an explicit account SID");

    var fake = new FakeObservationSource(running with { AddressCandidates = ["192.0.2.44"] });
    var server = new HyperVObserverPipeServer([currentSid], fake);
    var serverTask = server.ServeOneAsync(CancellationToken.None);
    var response = await RoundTripAsync(HyperVObserverContract.CreateRequestJson());
    await serverTask;
    Assert(fake.Calls == 1, "authorized fixed request invokes observation once");
    Assert(HyperVObserverContract.TryParseResponse(response, out var ipc)
           && ipc?.AddressCandidates.SequenceEqual(["192.0.2.44"]) == true,
        "explicit-ACL local pipe returns the narrow response to permitted caller");

    var rejectedFake = new FakeObservationSource(running);
    var rejectedServer = new HyperVObserverPipeServer([currentSid], rejectedFake);
    var rejectedTask = rejectedServer.ServeOneAsync(CancellationToken.None);
    var rejected = await RoundTripAsync("{\"version\":1,\"operation\":\"observe-other-vm\"}");
    await rejectedTask;
    Assert(rejectedFake.Calls == 0, "invalid request never reaches privileged observation");
    Assert(HyperVObserverContract.TryParseResponse(rejected, out var rejectedResponse)
           && rejectedResponse?.ErrorCode == "invalid-request"
           && HyperVObserverContract.SelectSshCandidates(rejectedResponse).Count == 0,
        "invalid request returns no candidate data");

    using var recoveryTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var recoverySource = new ThrowOnceObservationSource(running with { AddressCandidates = ["192.0.2.55"] });
    var resilientServer = new HyperVObserverPipeServer([currentSid], recoverySource);
    var resilientTask = resilientServer.RunAsync(recoveryTimeout.Token);
    var failedClientResponse = await RoundTripAsync(HyperVObserverContract.CreateRequestJson());
    Assert(string.IsNullOrEmpty(failedClientResponse),
        "a per-client observation exception closes only that client without leaking exception details");
    var recoveredClientResponse = await RoundTripAsync(HyperVObserverContract.CreateRequestJson());
    Assert(HyperVObserverContract.TryParseResponse(recoveredClientResponse, out var recovered)
           && recovered?.AddressCandidates.SequenceEqual(["192.0.2.55"]) == true,
        "a later valid client is served after the preceding client faults");
    recoveryTimeout.Cancel();
    await resilientTask;
    Assert(recoverySource.Calls == 2, "server survived one client fault and observed the next valid request exactly once");

    using var brokenPipeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var disconnectSource = new BlockingObservationSource(running with { AddressCandidates = ["192.0.2.66"] });
    var disconnectServer = new HyperVObserverPipeServer([currentSid], disconnectSource);
    var disconnectServerTask = disconnectServer.RunAsync(brokenPipeTimeout.Token);
    await DisconnectBeforeResponseAsync(disconnectSource);
    var postDisconnectResponse = await RoundTripAsync(HyperVObserverContract.CreateRequestJson());
    Assert(HyperVObserverContract.TryParseResponse(postDisconnectResponse, out var postDisconnect)
           && postDisconnect?.AddressCandidates.SequenceEqual(["192.0.2.66"]) == true,
        "server serves a later authorized client after the preceding client disconnects before response write");
    brokenPipeTimeout.Cancel();
    await disconnectServerTask;
    Assert(disconnectSource.Calls == 2,
        "broken response pipe is contained to one client and the next request is observed exactly once");

    using var immediateDisconnectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var immediateDisconnectSource = new FakeObservationSource(running with { AddressCandidates = ["192.0.2.77"] });
    var immediateDisconnectServer = new HyperVObserverPipeServer([currentSid], immediateDisconnectSource);
    var immediateDisconnectTask = immediateDisconnectServer.RunAsync(immediateDisconnectTimeout.Token);
    await ImmediateDisconnectAsync();
    var postImmediateDisconnectResponse = await RoundTripAsync(HyperVObserverContract.CreateRequestJson());
    Assert(HyperVObserverContract.TryParseResponse(postImmediateDisconnectResponse, out var postImmediate)
           && postImmediate?.AddressCandidates.SequenceEqual(["192.0.2.77"]) == true,
        "server serves a later authorized client after the preceding client disconnects immediately upon connection");
    immediateDisconnectTimeout.Cancel();
    await immediateDisconnectTask;
    Assert(immediateDisconnectSource.Calls == 1,
        "immediate disconnect is contained and the next valid request is observed exactly once");

    using var partialDisconnectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var partialDisconnectSource = new FakeObservationSource(running with { AddressCandidates = ["192.0.2.88"] });
    var partialDisconnectServer = new HyperVObserverPipeServer([currentSid], partialDisconnectSource);
    var partialDisconnectTask = partialDisconnectServer.RunAsync(partialDisconnectTimeout.Token);
    await PartialRequestDisconnectAsync();
    var postPartialDisconnectResponse = await RoundTripAsync(HyperVObserverContract.CreateRequestJson());
    Assert(HyperVObserverContract.TryParseResponse(postPartialDisconnectResponse, out var postPartial)
           && postPartial?.AddressCandidates.SequenceEqual(["192.0.2.88"]) == true,
        "server serves a later authorized client after the preceding client disconnects during request write");
    partialDisconnectTimeout.Cancel();
    await partialDisconnectTask;
    Assert(partialDisconnectSource.Calls == 1,
        "partial request disconnect is contained and the next valid request is observed exactly once");

    var invalidServer = new HyperVObserverPipeServer(["invalid-sid-string"], new FakeObservationSource(running));
    try
    {
        await invalidServer.ServeOneAsync(CancellationToken.None);
        Assert(false, "invalid caller SID configuration in SecurePipeFactory.CreateServer must throw and fail closed");
    }
    catch (Exception)
    {
        Assert(true, "invalid security descriptor/ACL configuration fails closed out of ServeOneAsync");
    }
}

Console.WriteLine($"Hyper-V observer tests passed ({assertions} assertions).");

async Task ImmediateDisconnectAsync()
{
    await using var pipe = new NamedPipeClientStream(
        ".", HyperVObserverContract.PipeName, PipeDirection.InOut,
        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    await pipe.ConnectAsync(2000, timeout.Token);
    pipe.Close();
}

async Task PartialRequestDisconnectAsync()
{
    await using var pipe = new NamedPipeClientStream(
        ".", HyperVObserverContract.PipeName, PipeDirection.InOut,
        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    await pipe.ConnectAsync(2000, timeout.Token);
    var bytes = Encoding.UTF8.GetBytes("{\"ver");
    await pipe.WriteAsync(bytes, timeout.Token);
    await pipe.FlushAsync(timeout.Token);
    pipe.Close();
}

async Task DisconnectBeforeResponseAsync(BlockingObservationSource source)
{
    await using var pipe = new NamedPipeClientStream(
        ".", HyperVObserverContract.PipeName, PipeDirection.InOut,
        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    await pipe.ConnectAsync(2000, timeout.Token);
    var bytes = Encoding.UTF8.GetBytes(HyperVObserverContract.CreateRequestJson() + "\n");
    await pipe.WriteAsync(bytes, timeout.Token);
    await pipe.FlushAsync(timeout.Token);
    await source.Entered.WaitAsync(timeout.Token);
    pipe.Close();
    source.Release();
}

async Task<string> RoundTripAsync(string request)
{
    await using var pipe = new NamedPipeClientStream(
        ".", HyperVObserverContract.PipeName, PipeDirection.InOut,
        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    await pipe.ConnectAsync(2000, timeout.Token);
    var bytes = Encoding.UTF8.GetBytes(request + "\n");
    await pipe.WriteAsync(bytes, timeout.Token);
    await pipe.FlushAsync(timeout.Token);
    using var reader = new StreamReader(pipe, Encoding.UTF8, false, 256, leaveOpen: true);
    return await reader.ReadLineAsync(timeout.Token) ?? string.Empty;
}

void Assert(bool condition, string description)
{
    assertions++;
    if (!condition)
        throw new InvalidOperationException($"FAILED: {description}");
}

sealed class FakeObservationSource(HyperVObservationResponse response) : IHyperVObservationSource
{
    public int Calls { get; private set; }

    public ValueTask<HyperVObservationResponse> ObserveAsync(CancellationToken cancellationToken)
    {
        Calls++;
        return ValueTask.FromResult(response);
    }
}

sealed class BlockingObservationSource(HyperVObservationResponse response) : IHyperVObservationSource
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public int Calls { get; private set; }
    public Task Entered => _entered.Task;

    public async ValueTask<HyperVObservationResponse> ObserveAsync(CancellationToken cancellationToken)
    {
        Calls++;
        if (Calls == 1)
        {
            _entered.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
        }
        return response;
    }

    public void Release() => _release.TrySetResult();
}

sealed class ThrowOnceObservationSource(HyperVObservationResponse response) : IHyperVObservationSource
{
    public int Calls { get; private set; }

    public ValueTask<HyperVObservationResponse> ObserveAsync(CancellationToken cancellationToken)
    {
        Calls++;
        if (Calls == 1)
            throw new InvalidOperationException("synthetic per-client failure");
        return ValueTask.FromResult(response);
    }
}
