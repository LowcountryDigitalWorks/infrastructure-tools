using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using LDW.AdminBroker;

// All data is synthetic; this test does not load protected state, launch a
// broker/helper, access GitHub, or promote an Administrator operation.
internal static class PromotionProtectedStateJsonTests
{
    [ModuleInitializer]
    internal static void Initialize() => Run();

    private static void Run()
    {
        int count = 0;
        void Assert(bool condition, string label)
        {
            if (!condition) throw new Exception("Promotion state JSON: " + label);
            count++;
        }

        var change = "a2d552af-d311-4afe-b827-620c9ef4c831";
        string Valid(bool enabled = true, string reason = "NONE") =>
            JsonSerializer.Serialize(new
            {
                schema_version = 1,
                promotion_enabled = enabled,
                control_generation = 7,
                reason_code = reason,
                active_generation = 4,
                active_digest_sha256 = new string('a', 64),
                last_change_id = change
            });
        static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);
        PromotionProtectedStateJsonResult Parse(string text) =>
            PromotionProtectedStateJson.Parse(Bytes(text));
        var closedReasons = new HashSet<string>(StringComparer.Ordinal)
        {
            "STATE_BYTES_OUT_OF_BOUNDS", "STATE_DOCUMENT_INVALID",
            "STATE_SCHEMA_REFUSED", "STATE_VALUES_REFUSED",
            "STATE_REASON_INCONSISTENT", "STATE_CHANGE_ID_INVALID"
        };
        void Block(string candidate, string name)
        {
            var result = Parse(candidate);
            Assert(result.Classification == "BLOCKED" &&
                   result.State is null &&
                   result.LastChangeId is null,
                   name);
            Assert(result.ReasonCode.Length is > 0 and <= 80 &&
                   closedReasons.Contains(result.ReasonCode),
                   name + " bounded refusal");
        }

        string valid = Valid();
        var result = Parse(valid);
        Assert(result.Classification == "DATA_ONLY_PARSED_NOT_AUTHORIZED",
            "valid synthetic state never authorizes promotion");
        Assert(result.ReasonCode == "EXTERNAL_PROTECTED_READBACK_REQUIRED",
            "untrusted bytes require privileged source/readback checks");
        Assert(result.State is { PromotionEnabled: true, ControlGeneration: 7,
                                 ActiveGeneration: 4, ReasonCode: "NONE" },
            "validated synthetic enabled fields");
        Assert(result.State?.ActiveDigestSha256 == new string('a', 64),
            "canonical synthetic digest preserved");
        Assert(result.LastChangeId == change, "canonical change identity");

        var disabled = Parse(Valid(false, "INCIDENT_DISABLED"));
        Assert(disabled.Classification == "DATA_ONLY_PARSED_NOT_AUTHORIZED" &&
               disabled.State is { PromotionEnabled: false,
                                   ReasonCode: "INCIDENT_DISABLED" },
               "disabled emergency state parses, but never authorizes");
        var denied = PromotionDataPreflight.Check(
            null, disabled.State, disabled.State, 9001,
            new DateTimeOffset(2026, 11, 5, 5, 0, 0, TimeSpan.Zero));
        Assert(denied.Classification == "BLOCKED",
            "parsed emergency state cannot pass promotion preflight");
        Assert(result.State is not null && disabled.State is not null &&
               result.State.ActiveGeneration == disabled.State.ActiveGeneration,
            "state parse does not mutate active generations");

        // Pre/post readback equality binds the change ID as well as
        // PromotionProtectedState's legacy fields.
        var stable = PromotionProtectedStateJson.CheckStable(result, Parse(valid));
        Assert(stable.Classification == "DATA_ONLY_STATE_STABLE_NOT_AUTHORIZED" &&
               stable.ReasonCode == "EXTERNAL_PROTECTED_READBACK_REQUIRED",
               "matching snapshots are only data evidence, never privilege");
        var alternateId = "b2d552af-d311-4afe-b827-620c9ef4c831";
        var movedId = Parse(valid.Replace(change, alternateId));
        Assert(movedId.Classification == "DATA_ONLY_PARSED_NOT_AUTHORIZED" &&
               movedId.State == result.State,
               "changed change ID is invisible to legacy state comparison");
        Assert(PromotionProtectedStateJson.CheckStable(result, movedId)
                   .Classification == "BLOCKED",
               "changed readback identity fails closed");
        Assert(PromotionProtectedStateJson.CheckStable(result, disabled)
                   .Classification == "BLOCKED",
               "emergency-disable change fails closed");
        Assert(PromotionProtectedStateJson.CheckStable(null, result)
                   .Classification == "BLOCKED",
               "missing initial readback");
        Assert(PromotionProtectedStateJson.CheckStable(result, null)
                   .Classification == "BLOCKED",
               "missing final readback");
        Assert(PromotionProtectedStateJson.CheckStable(
                   result, Parse(valid.Replace("\"control_generation\":7",
                         "\"control_generation\":8"))).Classification == "BLOCKED",
               "control-state generation drift fails closed");
        var callerMutable = Bytes(valid);
        var snap = PromotionProtectedStateJson.Parse(callerMutable);
        Array.Fill(callerMutable, (byte)0);
        Assert(snap.Classification == "DATA_ONLY_PARSED_NOT_AUTHORIZED" &&
               snap.LastChangeId == change &&
               snap.State?.ActiveDigestSha256 == new string('a', 64),
               "later caller mutation does not affect parsed result");

        var recoveryHold = Parse(Valid(false, "RECOVERY_HOLD"));
        Assert(recoveryHold.Classification == "DATA_ONLY_PARSED_NOT_AUTHORIZED" &&
               recoveryHold.State is { PromotionEnabled: false,
                                       ReasonCode: "RECOVERY_HOLD" },
               "disabled recovery hold parses but never authorizes");
        Assert(PromotionProtectedStateJson.CheckStable(result, recoveryHold)
                   .Classification == "BLOCKED",
               "recovery hold prevents data-stability acceptance");
        Block(Valid(true, "RECOVERY_HOLD"), "enabled recovery hold forbidden");

        Block("[]", "non-object root");
        Block("null", "null root");
        Block(valid + " {}", "multiple document roots");
        Block(valid + " /* comment */", "JSON comment forbidden");
        Block(valid[..^1] + ",}", "trailing comma forbidden");
        Block(valid.Replace("\"schema_version\":1,",
              "\"schema_version\":1,\"schema_version\":1,"),
            "duplicate key");
        Block(valid.Replace("\"schema_version\":1,",
              "\"schema_version\":1,\"unknown\":true,"),
            "extra key");
        Block(valid.Replace("\"schema_version\":1,", ""),
            "missing mandatory key");
        Block(valid.Replace("\"schema_version\":1",
              "\"Schema_version\":1"),
            "case-drifted key");
        Block(valid.Replace("\"schema_version\":1",
              "\"schema_version\":2"),
            "unknown schema version");
        Block(valid.Replace("\"promotion_enabled\":true",
              "\"promotion_enabled\":\"true\""),
            "wrong boolean type");
        Block(valid.Replace("\"control_generation\":7",
              "\"control_generation\":0"),
            "nonpositive control generation");
        Block(valid.Replace("\"control_generation\":7",
              "\"control_generation\":1.5"),
            "fractional generation");
        Block(valid.Replace("\"active_generation\":4",
              "\"active_generation\":-1"),
            "negative active generation");
        Block(valid.Replace("\"active_generation\":4",
              "\"active_generation\":9223372036854775807"),
            "unsafe maximal generation");
        Block(valid.Replace(new string('a', 64), new string('A', 64)),
            "uppercase SHA256 digest");
        Block(valid.Replace(new string('a', 64), new string('x', 64)),
            "nonhex SHA256 digest");
        Block(Valid(true, "INCIDENT_DISABLED"),
            "cannot claim enabled during incident disable");
        Block(Valid(false, "NONE"),
            "cannot claim disabled with active NONE reason");
        Block(Valid(false, "UNKNOWN_REASON"),
            "reject unknown reason enum");
        Block(valid.Replace(change, Guid.Empty.ToString("D")),
            "reject empty change identity");
        Block(valid.Replace(change, change.ToUpperInvariant()),
            "reject noncanonical GUID case");
        Block(valid.Replace(change, "untrusted-owner-id"),
            "reject non-GUID change identity");
        Block(valid.Replace(change, change[..35]),
            "reject truncated change identity");

        var oversized = PromotionProtectedStateJson.Parse(
            new byte[PromotionProtectedStateJson.MaxDocumentBytes + 1]);
        Assert(oversized.Classification == "BLOCKED" &&
               oversized.ReasonCode == "STATE_BYTES_OUT_OF_BOUNDS",
            "reject >4KiB before parsing");
        var empty = PromotionProtectedStateJson.Parse(null);
        Assert(empty.Classification == "BLOCKED" &&
               empty.ReasonCode == "STATE_BYTES_OUT_OF_BOUNDS",
            "reject missing bytes");
        var malformedUtf8 = PromotionProtectedStateJson.Parse(
            [0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);
        Assert(malformedUtf8.Classification == "BLOCKED" &&
               malformedUtf8.State is null,
            "reject undecodable UTF-8 without replacement");

        Assert(result.Classification != "PASS" &&
               result.Classification != "PROMOTED" &&
               result.Classification != "AUTHORIZED",
            "source decoder never emits privileged success");
        Console.WriteLine($"Promotion state JSON SOURCE-ONLY: {count} assertions PASS.");
    }
}
