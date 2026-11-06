using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LDW.AdminBroker;

/// <summary>
/// #186 Gate B proposal: decode ONE bounded synthetic snapshot of the future
/// protected promotion-control.json. This does NOT read paths, attest ACLs,
/// authenticate any process, or authorize a package promotion.
/// </summary>
internal static class PromotionProtectedStateJson
{
    internal const int MaxDocumentBytes = 4096;
    private const string DataOnly = "DATA_ONLY_PARSED_NOT_AUTHORIZED";
    private const string StableDataOnly = "DATA_ONLY_STATE_STABLE_NOT_AUTHORIZED";
    private static readonly string[] ExactNames =
    [
        "schema_version", "promotion_enabled", "control_generation",
        "reason_code", "active_generation", "active_digest_sha256",
        "last_change_id"
    ];

    private static PromotionProtectedStateJsonResult Block(string reason) =>
        new("BLOCKED", reason, null, null);

    private static bool LowerHex64(string? value) =>
        value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>
    /// Accept only canonical unsigned decimal notation for nonnegative
    /// generations. Reject -0, exponents, decimals, leading zeros, and overflow.
    /// Parsing the same decimal value by different JSON encodings is not enough
    /// for a source-identity or protected-file trust decision.
    /// </summary>
    private static bool TryCanonicalGeneration(JsonElement value, out long generation)
    {
        generation = 0;
        if (value.ValueKind != JsonValueKind.Number)
            return false;
        var raw = value.GetRawText();
        if (raw.Length is < 1 or > 19 ||
            (raw.Length > 1 && raw[0] == '0') ||
            raw.Any(c => c is < '0' or > '9'))
            return false;
        return long.TryParse(raw, NumberStyles.None,
            CultureInfo.InvariantCulture, out generation);
    }

    /// <summary>
    /// DATA_ONLY means schema validation, never authentication of caller bytes.
    /// No privileged file access, provider call, environment or dispatcher.
    /// JSON key names are compared AFTER JSON unescaping; no claim is made
    /// that all semantically identical JSON has identical bytes.
    /// </summary>
    internal static PromotionProtectedStateJsonResult Parse(byte[]? input)
    {
        if (input is null || input.Length is < 2 or > MaxDocumentBytes)
            return Block("STATE_BYTES_OUT_OF_BOUNDS");

        // One copy prevents the parser and UTF-8 verifier from observing
        // different versions of a concurrently mutable caller-owned byte[].
        // A stable *protected file* handle remains a separate future gate.
        byte[] snapshot = input.ToArray();
        try
        {
            if (snapshot.Length >= 3 && snapshot[0] == 0xEF &&
                snapshot[1] == 0xBB && snapshot[2] == 0xBF)
                return Block("STATE_DOCUMENT_INVALID");
            _ = new UTF8Encoding(false, true).GetString(snapshot);
            using var document = JsonDocument.Parse(
                snapshot,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Block("STATE_SCHEMA_REFUSED");

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!ExactNames.Contains(property.Name, StringComparer.Ordinal) ||
                    !seen.Add(property.Name))
                    return Block("STATE_SCHEMA_REFUSED");
            }
            if (seen.Count != ExactNames.Length ||
                root.GetProperty("schema_version").GetRawText() != "1" ||
                !TryCanonicalGeneration(root.GetProperty("control_generation"),
                    out long controlGeneration) ||
                !TryCanonicalGeneration(root.GetProperty("active_generation"),
                    out long activeGeneration))
                return Block("STATE_SCHEMA_REFUSED");

            bool enabled = root.GetProperty("promotion_enabled").GetBoolean();
            string? reason = root.GetProperty("reason_code").GetString();
            string? activeDigest = root.GetProperty("active_digest_sha256").GetString();
            string? changeId = root.GetProperty("last_change_id").GetString();

            if (controlGeneration <= 0 ||
                activeGeneration == long.MaxValue ||
                !LowerHex64(activeDigest))
                return Block("STATE_VALUES_REFUSED");

            if (reason is not ("NONE" or "INCIDENT_DISABLED" or "RECOVERY_HOLD") ||
                (enabled && reason != "NONE") ||
                (!enabled && reason == "NONE"))
                return Block("STATE_REASON_INCONSISTENT");

            if (changeId is null || changeId.Length != 36 ||
                !Guid.TryParseExact(changeId, "D", out var parsed) ||
                parsed == Guid.Empty ||
                !string.Equals(parsed.ToString("D"), changeId, StringComparison.Ordinal))
                return Block("STATE_CHANGE_ID_INVALID");

            return new PromotionProtectedStateJsonResult(
                DataOnly, "EXTERNAL_PROTECTED_READBACK_REQUIRED",
                new PromotionProtectedState(
                    enabled, controlGeneration, reason!, activeGeneration, activeDigest!),
                changeId);
        }
        catch (Exception ex) when (ex is JsonException or DecoderFallbackException
                                   or InvalidOperationException or FormatException
                                   or OverflowException or ArgumentException)
        {
            return Block("STATE_DOCUMENT_INVALID");
        }
    }

    /// <summary>
    /// Model the pre/post readback comparison including last_change_id, which
    /// is NOT present in the older PromotionProtectedState record. This pure
    /// comparison does not hold an OS lock and cannot replace a trusted
    /// protected re-read immediately before a future atomic pointer swap.
    /// </summary>
    internal static PromotionDataCheck CheckStable(
        PromotionProtectedStateJsonResult? initial,
        PromotionProtectedStateJsonResult? beforeSwap)
    {
        if (initial?.Classification != DataOnly ||
            beforeSwap?.Classification != DataOnly ||
            initial.State is null || beforeSwap.State is null ||
            initial.State.PromotionEnabled != true ||
            beforeSwap.State.PromotionEnabled != true ||
            initial.State != beforeSwap.State ||
            initial.LastChangeId is null ||
            !string.Equals(initial.LastChangeId, beforeSwap.LastChangeId,
                StringComparison.Ordinal))
            return new PromotionDataCheck("BLOCKED", "STATE_CHANGED_OR_DISABLED");

        return new PromotionDataCheck(StableDataOnly,
            "EXTERNAL_PROTECTED_READBACK_REQUIRED");
    }
}

internal sealed record PromotionProtectedStateJsonResult(
    string Classification,
    string ReasonCode,
    PromotionProtectedState? State,
    string? LastChangeId);
