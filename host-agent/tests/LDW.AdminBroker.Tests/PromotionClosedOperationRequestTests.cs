using System.Runtime.CompilerServices;
using System.Text;
using LDW.AdminBroker;

// Shape-only proof. No broker, task, file, Git, network, or publisher is invoked.
internal static class PromotionClosedOperationRequestTests
{
    [ModuleInitializer]
    internal static void Initialize() => Run();

    private static void Run()
    {
        int assertions = 0;
        void Assert(bool condition, string label)
        {
            if (!condition) throw new Exception("Closed operation request shape: " + label);
            assertions++;
        }

        static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

        PromotionClosedOperationRequestResult Check(string text) =>
            PromotionClosedOperationRequest.Validate(Bytes(text));

        void Block(string text, string reason)
        {
            var result = Check(text);
            Assert(result.Classification == "BLOCKED", reason + " blocked");
            Assert(result.ReasonCode == reason, reason);
            Assert(result.Classification is not ("AUTHORIZED" or "READY" or "PASS"), reason + " not authorized");
        }

        void BlockBytes(byte[] input, string reason)
        {
            var result = PromotionClosedOperationRequest.Validate(input);
            Assert(result.Classification == "BLOCKED", reason + " blocked");
            Assert(result.ReasonCode == reason, reason);
            Assert(result.Classification is not ("AUTHORIZED" or "READY" or "PASS"), reason + " not authorized");
        }

        static byte[] Utf8WithBom(string text)
        {
            var payload = Encoding.UTF8.GetBytes(text);
            var combined = new byte[3 + payload.Length];
            combined[0] = 0xEF;
            combined[1] = 0xBB;
            combined[2] = 0xBF;
            Buffer.BlockCopy(payload, 0, combined, 3, payload.Length);
            return combined;
        }

        const string intent = "DRAGONFLY_V2_PUBLISH_REVIEWED";
        var positive = Check(
            "{\"arguments\":[],\"intent\":\"" + intent + "\",\"schema\":1}");
        Assert(positive.Classification == "DATA_ONLY_REQUEST_SHAPE_NOT_AUTHORIZED", "fixed zero-arg shape");
        Assert(positive.ReasonCode == "EXTERNAL_TRUST_GATES_REQUIRED", "trust gates remain");
        Assert(positive.Classification is not ("AUTHORIZED" or "READY" or "PASS"), "shape is not launch authority");

        Assert(!AdminReviewedOperationRegistry.IsValidOperation(intent), "intent is not a registered operation");
        Assert(AdminReviewedOperationRegistry.All.Count == 1 &&
            AdminReviewedOperationRegistry.All.Contains(
                AdminReviewedOperationRegistry.ElevatedIdentityProof),
            "V1 registry unchanged");

        Block("{\"schema\":1,\"intent\":\"ELEVATED_IDENTITY_PROOF\",\"arguments\":[]}", "OPERATION_MISMATCH");
        Block("{\"schema\":1,\"intent\":\"dragonfly_v2_publish_reviewed\",\"arguments\":[]}", "OPERATION_MISMATCH");
        Block("{\"schema\":1,\"intent\":\"" + intent + " \",\"arguments\":[]}", "OPERATION_MISMATCH");
        Block("{\"schema\":1,\"arguments\":[]}", "OPERATION_MISMATCH");
        Block("{\"schema\":1,\"intent\":1,\"arguments\":[]}", "OPERATION_MISMATCH");

        Block("{\"schema\":1,\"intent\":\"" + intent + "\"}", "ARGUMENTS_AMBIGUOUS");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":null}", "ARGUMENTS_AMBIGUOUS");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":{}}", "ARGUMENTS_AMBIGUOUS");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[\"C:\\\\Tools\\\\pwsh.exe\"]}",
            "CALLER_SELECTED_ARGUMENTS");

        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"executable\":\"pwsh.exe\"}",
            "CALLER_SELECTED_EXECUTABLE");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"script\":\"publish.ps1\"}",
            "CALLER_SELECTED_SCRIPT");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"path\":\"C:\\\\LDW\"}",
            "CALLER_SELECTED_PATH");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"gitRef\":\"6116ad2\"}",
            "CALLER_SELECTED_GIT_REF");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"url\":\"https://example.invalid/pkg\"}",
            "CALLER_SELECTED_URL");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"packageDigest\":\"" + new string('a', 64) + "\"}",
            "CALLER_SELECTED_PACKAGE_DIGEST");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"providerAuthorization\":\"allow\"}",
            "PROVIDER_AUTHORIZATION_NOT_ACCEPTED");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"environmentExecutable\":\"C:\\\\WindowsApps\\\\pwsh.exe\"}",
            "ENVIRONMENT_PROVIDED_EXECUTABLE");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"manifest\":\"catalog.json\"}",
            "UNKNOWN_FIELD");

        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"requestId\":\"11111111-1111-1111-1111-111111111111\"}",
            "IDENTITY_REPLAY_OR_TTL_AMBIGUOUS");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"replay\":\"\"}",
            "IDENTITY_REPLAY_OR_TTL_AMBIGUOUS");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"ttl\":10}",
            "IDENTITY_REPLAY_OR_TTL_AMBIGUOUS");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"requestId\":\"abc\",\"replay\":\"once\",\"ttl\":\"PT5M\"}",
            "IDENTITY_REPLAY_OR_TTL_AMBIGUOUS");

        Block("{\"schema\":1,\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[]}",
            "DUPLICATE_OR_INVALID_FIELD");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"arguments\":[]}",
            "DUPLICATE_OR_INVALID_FIELD");
        Block("{\"schema\":2,\"intent\":\"" + intent + "\",\"arguments\":[]}", "SCHEMA_MISMATCH");
        Block("[]", "REQUEST_NOT_OBJECT");
        Block("{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[]}{}", "REQUEST_TRAILING_DATA");

        var oversized = PromotionClosedOperationRequest.Validate(
            new byte[PromotionClosedOperationRequest.MaxDocumentBytes + 1]);
        Assert(oversized.Classification == "BLOCKED" &&
            oversized.ReasonCode == "REQUEST_ABSENT_OR_OVERSIZED", "oversized");
        var empty = PromotionClosedOperationRequest.Validate(null);
        Assert(empty.Classification == "BLOCKED" &&
            empty.ReasonCode == "REQUEST_ABSENT_OR_OVERSIZED", "absent");

        var minimalShape =
            "{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[]}";
        BlockBytes(Utf8WithBom(minimalShape), "REQUEST_ENCODING_REJECTED");
        Block(
            "{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],\"nest\":{\"l2\":{\"l3\":{\"l4\":{\"l5\":1}}}}}",
            "REQUEST_MALFORMED");
        Block(
            "{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[]/*disallowed*/}",
            "REQUEST_MALFORMED");
        Block(
            "{\"schema\":1,\"intent\":\"" + intent + "\",\"arguments\":[],}",
            "REQUEST_MALFORMED");
        Block(
            "{\"schema\":1,\"intent\":\"" + intent + "\\u\",\"arguments\":[]}",
            "REQUEST_MALFORMED");
        Block(
            "{\"schema\":1,\"\\u12\":\"x\",\"intent\":\"" + intent + "\",\"arguments\":[]}",
            "REQUEST_MALFORMED");

        Console.WriteLine($"Closed operation request shape tests: {assertions} assertions passed.");
    }
}
