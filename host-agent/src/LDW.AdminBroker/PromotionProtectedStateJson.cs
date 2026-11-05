using System.Text;
using System.Text.Json;

namespace LDW.AdminBroker;

/// <summary>
/// #186 Gate B proposal, source-only: decode ONE bounded synthetic snapshot of
/// the future protected promotion-control.json. This does NOT read a path,
/// establish Windows ACLs, authenticate a process, or authorize promotion.
/// A caller must first verify its own protected file/parent identity and then
/// independently perform both the pre-provider and pre-swap state readbacks.
/// </summary>
internal static class PromotionProtectedStateJson
{
    internal const int MaxDocumentBytes = 4096;
    private const string DataOnly = "DATA_ONLY_PARSED_NOT_AUTHORIZED";
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
    /// DATA_ONLY never means a caller-supplied JSON document is trusted.
    /// No filepath, elevated operation, GitHub auth, environment, or dispatcher.
    /// </summary>
    internal static PromotionProtectedStateJsonResult Parse(byte[]? input)
    {
        if (input is null || input.Length is < 2 or > MaxDocumentBytes)
            return Block("STATE_BYTES_OUT_OF_BOUNDS");
        try
        {
            // Validate UTF-8 strictly before parsing; no replacement chars
            // may collapse distinct on-disk state representations.
            _ = new UTF8Encoding(false, true).GetString(input);
            using var document = JsonDocument.Parse(
                input,
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
            if (seen.Count != ExactNames.Length)
                return Block("STATE_SCHEMA_REFUSED");

            int schema = root.GetProperty("schema_version").GetInt32();
            bool enabled = root.GetProperty("promotion_enabled").GetBoolean();
            long controlGeneration = root.GetProperty("control_generation").GetInt64();
            string? reason = root.GetProperty("reason_code").GetString();
            long activeGeneration = root.GetProperty("active_generation").GetInt64();
            string? activeDigest = root.GetProperty("active_digest_sha256").GetString();
            string? changeId = root.GetProperty("last_change_id").GetString();

            if (schema != 1 || controlGeneration <= 0 ||
                activeGeneration < 0 || activeGeneration == long.MaxValue ||
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

            // This record remains unauthenticated until a fixed privileged
            // reader obtains/attests it from the protected local state root.
            // Even an enabled record must be checked against the separately
            // authenticated pre-swap observation before any activation.
            return new PromotionProtectedStateJsonResult(
                DataOnly,
                "EXTERNAL_PROTECTED_READBACK_REQUIRED",
                new PromotionProtectedState(
                    enabled, controlGeneration, reason!, activeGeneration, activeDigest!),
                changeId);
        }
        catch (Exception ex) when (ex is JsonException or DecoderFallbackException
                                   or InvalidOperationException or FormatException
                                   or OverflowException or ArgumentException)
        {
            // No exception/JSON/input data is echoed. The caller must not use
            // this source-only decoder as an administrator trust decision.
            return Block("STATE_DOCUMENT_INVALID");
        }
    }
}

internal sealed record PromotionProtectedStateJsonResult(
    string Classification,
    string ReasonCode,
    PromotionProtectedState? State,
    string? LastChangeId);
