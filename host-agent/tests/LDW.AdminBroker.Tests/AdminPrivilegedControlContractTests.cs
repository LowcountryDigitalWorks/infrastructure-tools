using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using LDW.AdminBroker;

internal static class AdminPrivilegedControlContractTests
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        Run();
    }

    private static void Run()
    {
        var assertions = 0;
        void Assert(bool condition, string message)
        {
            if (!condition) throw new Exception("Privileged control contract assertion failed: " + message);
            assertions++;
        }

        var fixedTarget = AdminPrivilegedControlContract.TargetIdentity;

        // 1. ADMIN_REVIEWED_OPERATION_RUN with allowed operationId
        var runJson = "{\"version\":1,\"requestId\":\"11111111-1111-1111-1111-111111111111\",\"operation\":\"ADMIN_REVIEWED_OPERATION_RUN\",\"targetIdentity\":\""
            + fixedTarget + "\",\"parameters\":{\"operationId\":\"ELEVATED_IDENTITY_PROOF\"}}";
        Assert(AdminBrokerContract.TryParseRequest(runJson, out var runRequest) && runRequest is not null,
            "ADMIN_REVIEWED_OPERATION_RUN parses with operationId");
        Assert(AdminPrivilegedRequestPolicy.IsAllowed(runRequest!), "allowed reviewed operation passes policy");

        // 2. ADMIN_REVIEWED_OPERATION_RUN with reviewedOperation alternative key rejected
        var runAltJson = "{\"version\":1,\"requestId\":\"11111111-1111-1111-1111-111111111111\",\"operation\":\"ADMIN_REVIEWED_OPERATION_RUN\",\"targetIdentity\":\""
            + fixedTarget + "\",\"parameters\":{\"reviewedOperation\":\"ELEVATED_IDENTITY_PROOF\"}}";
        Assert(!AdminBrokerContract.TryParseRequest(runAltJson, out _),
            "ADMIN_REVIEWED_OPERATION_RUN rejects reviewedOperation alias");

        // 3. Unknown operation ID fails closed before execution
        var unknownOpJson = "{\"version\":1,\"requestId\":\"11111111-1111-1111-1111-111111111111\",\"operation\":\"ADMIN_REVIEWED_OPERATION_RUN\",\"targetIdentity\":\""
            + fixedTarget + "\",\"parameters\":{\"operationId\":\"UNKNOWN_UNREVIEWED_OP\"}}";
        Assert(AdminBrokerContract.TryParseRequest(unknownOpJson, out var unknownOpRequest) && unknownOpRequest is not null,
            "unknown operationId parses at contract level if formatted as identifier");
        Assert(!AdminPrivilegedRequestPolicy.IsAllowed(unknownOpRequest!), "unknown operationId fails closed in policy");

        // 4. Caller-provided command/path/args/url/env rejected
        var injectionAttempts = new[]
        {
            "{\"operationId\":\"ELEVATED_IDENTITY_PROOF\",\"command\":\"whoami\"}",
            "{\"operationId\":\"ELEVATED_IDENTITY_PROOF\",\"path\":\"C:\\\\Windows\\\\System32\"}",
            "{\"operationId\":\"ELEVATED_IDENTITY_PROOF\",\"arguments\":[\"-flag\"]}",
            "{\"operationId\":\"ELEVATED_IDENTITY_PROOF\",\"environment\":{\"FOO\":\"BAR\"}}",
            "{\"operationId\":\"ELEVATED_IDENTITY_PROOF\",\"url\":\"https://example.com/\"}",
            "{\"command\":\"whoami\"}",
            "{\"scriptPath\":\"test.ps1\"}"
        };
        foreach (var injection in injectionAttempts)
        {
            var injectionJson = "{\"version\":1,\"requestId\":\"11111111-1111-1111-1111-111111111111\",\"operation\":\"ADMIN_REVIEWED_OPERATION_RUN\",\"targetIdentity\":\""
                + fixedTarget + "\",\"parameters\":" + injection + "}";
            Assert(!AdminBrokerContract.TryParseRequest(injectionJson, out _),
                "arbitrary parameter rejected by contract: " + injection);
        }

        // 5. Malformed operation identifiers rejected
        var invalidOpIdentifiers = new[] { "evil;calc", "whoami & dir", "op with spaces", "../traversal", string.Empty };
        foreach (var invalidOp in invalidOpIdentifiers)
        {
            var invalidJson = "{\"version\":1,\"requestId\":\"11111111-1111-1111-1111-111111111111\",\"operation\":\"ADMIN_REVIEWED_OPERATION_RUN\",\"targetIdentity\":\""
                + fixedTarget + "\",\"parameters\":{\"operationId\":" + JsonSerializer.Serialize(invalidOp) + "}}";
            Assert(!AdminBrokerContract.TryParseRequest(invalidJson, out _),
                "invalid operationId string rejected by contract: " + invalidOp);
        }

        // 6. Target identity mismatch rejected
        Assert(!AdminPrivilegedRequestPolicy.IsAllowed(runRequest! with { TargetIdentity = "other-target" }),
            "target identity mismatch rejected");

        // 7. ADMIN_REVIEWED_OPERATION_GET_RESULT with correlationId
        var getResultJson = "{\"version\":1,\"requestId\":\"22222222-2222-2222-2222-222222222222\",\"operation\":\"ADMIN_REVIEWED_OPERATION_GET_RESULT\",\"targetIdentity\":\""
            + fixedTarget + "\",\"parameters\":{\"correlationId\":\"11111111-1111-1111-1111-111111111111\"}}";
        Assert(AdminBrokerContract.TryParseRequest(getResultJson, out var getResultRequest) && getResultRequest is not null,
            "ADMIN_REVIEWED_OPERATION_GET_RESULT parses with correlationId");
        Assert(AdminPrivilegedRequestPolicy.IsAllowed(getResultRequest!), "valid correlationId passes policy");

        // 8. ADMIN_REVIEWED_OPERATION_GET_RESULT with operationId alternative key rejected
        var getResultAltJson = "{\"version\":1,\"requestId\":\"22222222-2222-2222-2222-222222222222\",\"operation\":\"ADMIN_REVIEWED_OPERATION_GET_RESULT\",\"targetIdentity\":\""
            + fixedTarget + "\",\"parameters\":{\"operationId\":\"11111111-1111-1111-1111-111111111111\"}}";
        Assert(!AdminBrokerContract.TryParseRequest(getResultAltJson, out _),
            "ADMIN_REVIEWED_OPERATION_GET_RESULT rejects operationId alias");

        // 9. Non-UUID correlationId rejected
        var nonUuidResultJson = "{\"version\":1,\"requestId\":\"22222222-2222-2222-2222-222222222222\",\"operation\":\"ADMIN_REVIEWED_OPERATION_GET_RESULT\",\"targetIdentity\":\""
            + fixedTarget + "\",\"parameters\":{\"correlationId\":\"not-a-uuid\"}}";
        Assert(!AdminBrokerContract.TryParseRequest(nonUuidResultJson, out _),
            "non-UUID correlationId rejected by contract");

        // 10. Safe result validation
        var validResult = new AdminPrivilegedControlResult(
            true, "PASS", "NONE", "11111111-1111-1111-1111-111111111111", "ELEVATED_IDENTITY_PROOF",
            new Dictionary<string, string> { ["identityState"] = "ELEVATED_ADMINISTRATOR" });
        Assert(AdminPrivilegedControlContract.IsSafeResult(validResult), "valid result passes safety check");
        var details = AdminPrivilegedControlContract.CreateDetails(validResult);
        Assert(details is not null && details["identityState"] == "ELEVATED_ADMINISTRATOR", "CreateDetails preserves safe details");

        // 11. Contradictory states fail safe result validation
        var contradictory1 = validResult with { Success = true, ResultState = "FAILED" };
        var contradictory2 = validResult with { Success = false, ResultState = "PASS" };
        var invalidState = validResult with { ResultState = "RANDOM_STATE" };
        var invalidReason = validResult with { ReasonCode = "MALICIOUS_REASON" };
        Assert(!AdminPrivilegedControlContract.IsSafeResult(contradictory1), "success=true with FAILED rejected");
        Assert(!AdminPrivilegedControlContract.IsSafeResult(contradictory2), "success=false with PASS rejected");
        Assert(!AdminPrivilegedControlContract.IsSafeResult(invalidState), "invalid result state rejected");
        Assert(!AdminPrivilegedControlContract.IsSafeResult(invalidReason), "invalid reason code rejected");

        // 12. Unsafe details rejected
        var unsafeKeyResult = validResult with
        {
            Details = new Dictionary<string, string> { ["bad key with space"] = "value" }
        };
        var unsafeValueResult = validResult with
        {
            Details = new Dictionary<string, string> { ["key"] = "value\nwith\nnewlines;evil" }
        };
        Assert(!AdminPrivilegedControlContract.IsSafeResult(unsafeKeyResult), "unsafe detail key rejected");
        Assert(!AdminPrivilegedControlContract.IsSafeResult(unsafeValueResult), "unsafe detail value rejected");

        // 13. STARTED in-flight result is safe
        var inFlightResult = new AdminPrivilegedControlResult(
            true, "STARTED", "NONE", "11111111-1111-1111-1111-111111111111", "ELEVATED_IDENTITY_PROOF");
        Assert(AdminPrivilegedControlContract.IsSafeResult(inFlightResult), "STARTED in-flight result passes safety check");

        // 14. Registry consistency: C# reviewed operation IDs == PowerShell helper registry
        var baseDir = AppContext.BaseDirectory;
        var cursor = new DirectoryInfo(baseDir);
        string? workerScriptPath = null;
        while (cursor is not null)
        {
            var candidate = Path.Combine(cursor.FullName, "host-agent", "deploy", "Invoke-AdminPrivilegedOperation.ps1");
            if (File.Exists(candidate))
            {
                workerScriptPath = candidate;
                break;
            }
            cursor = cursor.Parent;
        }
        Assert(workerScriptPath is not null && File.Exists(workerScriptPath), "found Invoke-AdminPrivilegedOperation.ps1");

        var workerContent = File.ReadAllText(workerScriptPath!);
        var registryMatch = Regex.Match(workerContent, @"\$ReviewedOperationRegistry\s*=\s*@\{(?<bodycontent>.*?)\n\}", RegexOptions.Singleline);
        Assert(registryMatch.Success, "found $ReviewedOperationRegistry block in worker script");

        var psOps = new HashSet<string>(StringComparer.Ordinal);
        var opMatches = Regex.Matches(registryMatch.Groups["bodycontent"].Value, @"'([A-Z0-9_]+)'\s*=");
        foreach (Match m in opMatches)
        {
            psOps.Add(m.Groups[1].Value);
        }

        Assert(psOps.SetEquals(AdminReviewedOperationRegistry.All),
            "C# reviewed operation registry exactly equals PowerShell reviewed operation registry");

        Console.WriteLine($"Privileged control contract tests: {assertions} assertions passed.");
    }
}
