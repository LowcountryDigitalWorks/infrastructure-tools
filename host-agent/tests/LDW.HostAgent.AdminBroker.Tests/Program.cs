using LDW.HostAgent.AdminBroker.Core;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

var checks = 0;
void Check(bool condition, string message)
{
    checks++;
    if (!condition) throw new InvalidOperationException($"FAILED: {message}");
}

var allowlist = new AdminBrokerAllowlist(
    ["S-1-5-21-111111111-222222222-333333333-1001"],
    ["ldw-disposable-bot-123"],
    ["host-agent-tray", "hyperv-observer"],
    ["0123456789abcdef"]);

string Request(string operation, string target, string inputs) =>
    $$"""{"version":1,"requestId":"00000000-0000-0000-0000-000000000001","operation":"{{operation}}","targetId":"{{target}}","inputs":{{inputs}}}""";

Check(AdminBrokerContract.TryParseRequest(Request("CODYNC_BOT_CREATE", "codync", "{\"definitionId\":\"codync-smoke-test\"}"), out var create), "known typed create request parses");
Check(create is not null && AdminBrokerAuthorizationPolicy.IsAllowedTarget(create, allowlist), "approved disposable create target is allowed");
Check(AdminBrokerContract.TryParseRequest(Request("CODYNC_BOT_UPDATE", "codync", "{\"botId\":\"ldw-disposable-bot-123\",\"definitionId\":\"codync-smoke-test\"}"), out var update), "known typed update request parses");
Check(update is not null && AdminBrokerAuthorizationPolicy.IsAllowedTarget(update, allowlist), "exact configured bot id is allowed");
Check(AdminBrokerContract.TryParseRequest(Request("CODYNC_BOT_DELETE", "codync", "{\"botId\":\"ldw-disposable-bot-123\"}"), out var delete), "known typed delete request parses");
Check(delete is not null && AdminBrokerAuthorizationPolicy.IsAllowedTarget(delete, allowlist), "exact configured delete target is allowed");
Check(AdminBrokerContract.TryParseRequest(Request("HOST_AGENT_STATUS", "ldw01", "{}"), out var status), "known status request parses");
Check(status is not null && AdminBrokerAuthorizationPolicy.IsAllowedTarget(status, allowlist), "exact host status target is allowed");
Check(AdminBrokerContract.TryParseRequest(Request("HOST_AGENT_RESTART_REVIEWED_COMPONENT", "host-agent", "{\"componentId\":\"hyperv-observer\"}"), out var restart), "known restart request parses");
Check(restart is not null && AdminBrokerAuthorizationPolicy.IsAllowedTarget(restart, allowlist), "reviewed component id is allowed");
Check(AdminBrokerContract.TryParseRequest(Request("HOST_AGENT_REPAIR_REVIEWED_INSTALL", "host-agent", "{\"releaseId\":\"0123456789abcdef\"}"), out var repair), "known repair request parses");
Check(repair is not null && AdminBrokerAuthorizationPolicy.IsAllowedTarget(repair, allowlist), "reviewed release id is allowed");

Check(!AdminBrokerContract.TryParseRequest(Request("RUN_SHELL", "host-agent", "{}"), out _), "unrecognized operations fail closed");
Check(!AdminBrokerContract.TryParseRequest(Request("HOST_AGENT_STATUS", "other-host", "{}"), out _), "caller target mismatch fails closed");
Check(!AdminBrokerContract.TryParseRequest(Request("HOST_AGENT_STATUS", "ldw01", "{\"command\":\"whoami\"}"), out _), "unrecognized fields fail closed");
Check(!AdminBrokerContract.TryParseRequest(Request("HOST_AGENT_STATUS", "ldw01", "{}" )[..^1] + ",\"extra\":true}", out _), "unknown root field fails closed");
Check(AdminBrokerContract.TryParseRequest(Request("CODYNC_BOT_DELETE", "codync", "{\"botId\":\"some-other-bot\"}"), out var otherBot), "valid-shaped but unconfigured bot id is syntactically parsed");
Check(otherBot is not null && !AdminBrokerAuthorizationPolicy.IsAllowedTarget(otherBot, allowlist), "unconfigured bot target fails authorization");
Check(AdminBrokerContract.TryParseRequest(Request("HOST_AGENT_REPAIR_REVIEWED_INSTALL", "host-agent", "{\"releaseId\":\"ffffffffffffffff\"}"), out var unreviewedRelease), "release input follows fixed typed schema");
Check(unreviewedRelease is not null && !AdminBrokerAuthorizationPolicy.IsAllowedTarget(unreviewedRelease, allowlist), "unreviewed release fails authorization");

Check(AdminBrokerAuthorizationPolicy.IsPermittedCaller(allowlist.PermittedOwnerSids[0], allowlist), "configured explicit owner SID is allowed");
Check(!AdminBrokerAuthorizationPolicy.IsPermittedCaller("S-1-1-0", allowlist), "Everyone SID is rejected");
Check(!AdminBrokerAuthorizationPolicy.IsPermittedCaller("S-1-5-21-1-2-3-4", allowlist), "non-configured owner SID is rejected");

var audit = new AdminBrokerAuditRecord(1, "00000000-0000-0000-0000-000000000001", "HOST_AGENT_STATUS", "ldw01", "succeeded", "status-ready", DateTimeOffset.UnixEpoch);
var auditJson = AdminBrokerContract.CreateAuditJson(audit);
Check(!auditJson.Contains("secret", StringComparison.OrdinalIgnoreCase), "bounded audit result does not carry secret material");
Check(!auditJson.Contains("command", StringComparison.OrdinalIgnoreCase), "bounded audit result does not carry command text");
var unsafeAuditRejected = false;
try
{
    _ = AdminBrokerContract.CreateAuditJson(audit with { TargetId = "secret-value-should-not-be-an-audit-target" });
}
catch (ArgumentException)
{
    unsafeAuditRejected = true;
}
Check(unsafeAuditRejected, "audit target must use a fixed non-secret identity");

var secretRoot = Path.Combine(Path.GetTempPath(), "ldw-admin-broker-tests-" + Guid.NewGuid().ToString("N"));
var vault = new LocalSecretVault(secretRoot);
const string syntheticSecret = "synthetic-corsair-neon-secret-sentinel";
using var syntheticValue = new SecureString();
foreach (var character in syntheticSecret) syntheticValue.AppendChar(character);
syntheticValue.MakeReadOnly();
try
{
    Check(!vault.IsPresent, "secret status reports absent without returning a value");
    vault.Store(syntheticValue);
    Check(vault.IsPresent, "secret status reports present after store");
    var protectedFile = Path.Combine(secretRoot, "corsair-neon-database-url.dpapi");
    var ciphertext = File.ReadAllBytes(protectedFile);
    Check(!Encoding.UTF8.GetString(ciphertext).Contains(syntheticSecret, StringComparison.Ordinal), "DPAPI file does not contain plaintext secret");
    using var restored = vault.Load();
    var restoredPointer = Marshal.SecureStringToGlobalAllocUnicode(restored);
    try
    {
        Check(Marshal.PtrToStringUni(restoredPointer) == syntheticSecret, "current owner can read back protected secret");
    }
    finally
    {
        Marshal.ZeroFreeGlobalAllocUnicode(restoredPointer);
    }
    vault.Remove();
    Check(!vault.IsPresent, "remove clears the fixed protected secret identity");
}
finally
{
    if (Directory.Exists(secretRoot)) Directory.Delete(secretRoot, recursive: true);
}

Console.WriteLine($"Admin broker contract assertions PASS: {checks}");
