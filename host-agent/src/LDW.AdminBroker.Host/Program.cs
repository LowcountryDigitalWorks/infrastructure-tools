using System.Security.Principal;
using LDW.AdminBroker;
using LDW.LocalSecretStore;

if (args.Length != 0)
{
    Console.Error.WriteLine("This interactive tool accepts no command-line arguments.");
    return 2;
}
if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("This tool requires Windows.");
    return 2;
}

var callerSid = WindowsIdentity.GetCurrent().User?.Value;
if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)
    || !AdminBrokerAuthorizationPolicy.IsSafeExplicitUserSid(callerSid))
{
    Console.Error.WriteLine("The current Windows user identity could not be validated.");
    return 2;
}

var secretStore = new LocalSecretStore();
var audit = new AdminBrokerAuditLogger();
var broker = new AdminBrokerPipeServer([callerSid!],
    new AdminBrokerEngine(new CodyncBotHandler(), new HostAgentOperationHandler()), audit);
var launcher = new CorsairNeonLauncher(secretStore);
using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; shutdown.Cancel(); };

while (!shutdown.IsCancellationRequested)
{
    Console.WriteLine();
    Console.WriteLine("LDW Admin Broker (normal-user, local only)");
    Console.WriteLine("1. Serve one local broker request at a time");
    Console.WriteLine("2. Show fixed secret status");
    Console.WriteLine("3. Add or replace fixed secret");
    Console.WriteLine("4. Remove fixed secret");
    Console.WriteLine("5. Run fixed synthetic secret-presence proof");
    Console.WriteLine("0. Exit");
    Console.Write("Select: ");
    var choice = Console.ReadLine();
    try
    {
        switch (choice)
        {
            case "1": await ServeBrokerAsync(); break;
            case "2": ShowSecretStatus(); break;
            case "3": SetSecret(); break;
            case "4": RemoveSecret(); break;
            case "5": await RunProbeAsync(); break;
            case "0": return 0;
            default: Console.WriteLine("Selection not recognized."); break;
        }
    }
    catch (OperationCanceledException) { }
    catch
    {
        Console.WriteLine("The requested operation failed safely. See the local sanitized audit record when available.");
    }
}
return 0;

async Task ServeBrokerAsync()
{
    Console.WriteLine("Listening on the fixed current-user-only local pipe. Press Ctrl+C to stop.");
    while (!shutdown.IsCancellationRequested)
    {
        using var pipe = broker.CreateServerPipe();
        await broker.ServeOneAsync(pipe, shutdown.Token);
    }
}

void ShowSecretStatus()
{
    var status = secretStore.GetStatus(LocalSecretStore.FixedSecretIdCorsairNeon);
    audit.Log(Audit("LOCAL_SECRET_STORE", status.Exists ? "SecretStatus" : "SecretStatus", null));
    Console.WriteLine(status.Exists ? "Fixed secret is present." : "Fixed secret is absent.");
}

void SetSecret()
{
    var first = ReadHidden("Enter the fixed secret value: ");
    var second = ReadHidden("Enter it again to confirm: ");
    try
    {
        if (first.Length == 0 || !first.SequenceEqual(second))
        {
            Console.WriteLine("Values did not match or were empty; nothing was stored.");
            return;
        }
        var value = new string(first);
        var stored = secretStore.SetSecret(LocalSecretStore.FixedSecretIdCorsairNeon, value);
        value = string.Empty;
        audit.Log(Audit("LOCAL_SECRET_STORE", stored ? "SecretStored" : "SecretStatus", null));
        Console.WriteLine(stored ? "Fixed secret stored with CurrentUser DPAPI." : "No value was stored.");
    }
    finally
    {
        Array.Clear(first, 0, first.Length);
        Array.Clear(second, 0, second.Length);
    }
}

void RemoveSecret()
{
    Console.Write("Remove the fixed local secret? Type Y to confirm: ");
    if (!string.Equals(Console.ReadLine(), "Y", StringComparison.Ordinal))
    {
        Console.WriteLine("No change made.");
        return;
    }
    var removed = secretStore.RemoveSecret(LocalSecretStore.FixedSecretIdCorsairNeon);
    audit.Log(Audit("LOCAL_SECRET_STORE", removed ? "SecretRemoved" : "SecretStatus", null));
    Console.WriteLine(removed ? "Fixed secret removed." : "Fixed secret was already absent.");
}

async Task RunProbeAsync()
{
    var result = await launcher.LaunchProofProcessAsync(shutdown.Token);
    audit.Log(Audit("FIXED_SECRET_PROBE", result.Success ? "ProbeSuccess" : "ProbeFailure", result.ErrorCode));
    Console.WriteLine(result.Success ? "Synthetic secret-presence proof passed." : "Synthetic proof did not pass: " + (result.ErrorCode ?? "PROBE_FAILED"));
}

AuditRecord Audit(string operation, string state, string? error) => new(
    DateTime.UtcNow, Guid.NewGuid().ToString("D"), operation, "redacted", callerSid,
    state is "SecretStored" or "SecretRemoved" or "ProbeSuccess", state, error, "Local operation audit record.");

static char[] ReadHidden(string prompt)
{
    Console.Write(prompt);
    var chars = new List<char>();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key is ConsoleKey.Enter) { Console.WriteLine(); break; }
        if (key.Key is ConsoleKey.Backspace)
        {
            if (chars.Count > 0) chars.RemoveAt(chars.Count - 1);
            continue;
        }
        if (!char.IsControl(key.KeyChar) && chars.Count < 4096) chars.Add(key.KeyChar);
    }
    return chars.ToArray();
}
