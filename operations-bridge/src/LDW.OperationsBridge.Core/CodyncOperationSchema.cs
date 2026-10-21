namespace LDW.OperationsBridge.Core;

public static class CodyncOperationSchema
{
    private static readonly string[] SendKeys = ["destination_id", "destination_name", "text", "mentioned_member_ids"];
    private static readonly string[] WaitKeys = ["destination_id", "destination_name", "send_dispatch_id", "client_nonce", "root_entry_id", "root_sequence", "root_turn", "root_revision", "expected_author_id", "timeout_seconds"];

    public static bool IsValid(BridgeOperation operation, IReadOnlyDictionary<string, string> args)
    {
        if (operation is BridgeOperation.CodyncHealth or BridgeOperation.CodyncListApprovedBotsGroups)
            return args.Count == 0;
        if (operation == BridgeOperation.CodyncSendExact)
        {
            if (!HasOnly(args, SendKeys) || !Has(args, "destination_id", "destination_name", "text")) return false;
            if (args["text"].Length is 0 or > BridgeProtocol.MaxArgValueLength) return false;
            var mentions = Get(args, "mentioned_member_ids").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (mentions.Distinct(StringComparer.Ordinal).Count() != mentions.Length ||
                Get(args, "text").Contains("@all", StringComparison.OrdinalIgnoreCase) ||
                Get(args, "text").Contains("@everyone", StringComparison.OrdinalIgnoreCase)) return false;
            var destination = CodyncApprovedDestinations.All.SingleOrDefault(item => item.Id == Get(args, "destination_id") && item.Name == Get(args, "destination_name"));
            if (destination is null || !destination.Enabled) return false;
            if (destination.Kind != "group") return mentions.Length == 0;
            if (mentions.Length == 0 || mentions.Any(id => !destination.Members.Contains(id, StringComparer.Ordinal))) return false;
            if (mentions.Any(id => !Get(args, "text").Contains("@" + CodyncApprovedDestinations.All.Single(item => item.Id == id).Name, StringComparison.Ordinal))) return false;
            return !destination.Members.Except(mentions, StringComparer.Ordinal).Any(id =>
                Get(args, "text").Contains("@" + CodyncApprovedDestinations.All.Single(item => item.Id == id).Name, StringComparison.Ordinal));
        }
        if (operation == BridgeOperation.CodyncWaitReadExact)
        {
            if (!HasOnly(args, WaitKeys) || !Has(args, WaitKeys)) return false;
            if (!Guid.TryParseExact(Get(args, "send_dispatch_id"), "D", out var sendId) ||
                Get(args, "client_nonce") != $"ldw-operations-{sendId:D}" ||
                !Guid.TryParseExact(Get(args, "root_entry_id"), "D", out _)) return false;
            return long.TryParse(Get(args, "root_sequence"), out var sequence) && sequence >= 0 &&
                   long.TryParse(Get(args, "root_turn"), out var turn) && turn >= 0 &&
                   long.TryParse(Get(args, "root_revision"), out var revision) && revision >= 0 &&
                   int.TryParse(Get(args, "timeout_seconds"), out var seconds) && seconds is >= 1 and <= 240;
        }
        return true;
    }

    private static bool HasOnly(IReadOnlyDictionary<string, string> args, IEnumerable<string> keys)
    {
        var allowed = new HashSet<string>(keys, StringComparer.Ordinal);
        return args.Keys.All(allowed.Contains);
    }

    private static bool Has(IReadOnlyDictionary<string, string> args, params string[] keys)
        => keys.All(key => args.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value));

    private static string Get(IReadOnlyDictionary<string, string> args, string key)
        => args.TryGetValue(key, out var value) ? value : string.Empty;
}
