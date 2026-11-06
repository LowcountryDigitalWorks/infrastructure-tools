// Gate B, source-only: data consistency is NOT promotion authorization.
// No provider access, file access, installation, privileged operation, or catalog mutation.
namespace LDW.AdminBroker;

internal sealed record PromotionCommentFacts(
    int SchemaVersion,
    string Repository,
    long LedgerIssueNumber,
    long CommentId,
    string NodeId,
    string AuthorType,
    string AuthorLogin,
    long AuthorId,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    string Decision,
    long PredecessorGeneration,
    long NextGeneration,
    string PredecessorDigestSha256,
    string SourceCommitSha1,
    string SourceTreeSha1,
    string PackageBlobSha1,
    string PackageSha256,
    long PackageLength,
    string CatalogSha256,
    IReadOnlyList<string> OperationIds,
    DateTimeOffset ExpiresUtc);

internal sealed record PromotionProtectedState(
    bool PromotionEnabled,
    long ControlGeneration,
    string ReasonCode,
    long ActiveGeneration,
    string ActiveDigestSha256);

internal sealed record PromotionDataCheck(string Classification, string ReasonCode);

/// <summary>
/// A non-authorizing, deterministic fail-closed data check for #186 Gate B.
/// Caller MUST separately verify server-returned GitHub provenance, immutable
/// package bytes, accepted CI/review, protected ACLs and the pre-swap state.
/// The ledger issue number is intentionally not a user-selected runtime input:
/// this isolated proof accepts it only to model a future compiled-in anchor.
/// Do not wire this class to an operation registry or use its output to swap.
/// </summary>
internal static class PromotionDataPreflight
{
    private const string Repo = "LowcountryDigitalWorks/infrastructure-tools";
    private const string BotType = "Bot";
    private const string BotLogin = "ldw-activepieces-165-w[bot]";
    private const long BotId = 331690200;
    private const string AcceptedDecision = "ACCEPTED_PROMOTION";
    private const string DataOnly = "DATA_ONLY_CONSISTENT_NOT_AUTHORIZED";

    private static PromotionDataCheck Block(string reason) => new("BLOCKED", reason);

    private static bool IsLowerHex(string? input, int length) =>
        input is not null && input.Length == length &&
        input.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsNodeId(string? input) =>
        input is not null && input.Length is >= 4 and <= 128 &&
        input.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z'
            or >= '0' and <= '9' or '_' or '-');

    private static bool IsStateValid(PromotionProtectedState? state) =>
        state is not null && state.PromotionEnabled &&
        state.ControlGeneration > 0 && state.ActiveGeneration >= 0 &&
        state.ActiveGeneration < long.MaxValue &&
        string.Equals(state.ReasonCode, "NONE", StringComparison.Ordinal) &&
        IsLowerHex(state.ActiveDigestSha256, 64);

    internal static PromotionDataCheck Check(
        PromotionCommentFacts? comment,
        PromotionProtectedState? beforeProviderRead,
        PromotionProtectedState? immediatelyBeforeSwap,
        long compiledLedgerIssueNumber,
        DateTimeOffset nowUtc)
    {
        // This does NOT authenticate the caller that supplied these records.
        // The later trusted launcher must source them independently from GitHub
        // and protected on-disk state. No production ledger is configured here.
        if (compiledLedgerIssueNumber <= 0)
            return Block("LEDGER_ANCHOR_UNCONFIGURED");
        if (!IsStateValid(beforeProviderRead) || !IsStateValid(immediatelyBeforeSwap))
            return Block("PROTECTED_STATE_DISABLED_OR_UNVERIFIED");

        var initial = beforeProviderRead!;
        var last = immediatelyBeforeSwap!;
        if (last != initial)
            return Block("PROTECTED_STATE_MOVED_OR_REVOKED");

        // DateTimeOffset.AddMinutes throws near the representable extremes.
        // A malformed/untrusted clock must return a bounded denial instead.
        if (nowUtc.Offset != TimeSpan.Zero ||
            nowUtc < DateTimeOffset.UnixEpoch ||
            nowUtc > DateTimeOffset.MaxValue.AddMinutes(-10))
            return Block("CLOCK_OUT_OF_RANGE");

        if (comment is null || comment.SchemaVersion != 1 ||
            !string.Equals(comment.Repository, Repo, StringComparison.Ordinal) ||
            comment.LedgerIssueNumber != compiledLedgerIssueNumber ||
            comment.CommentId <= 0 || !IsNodeId(comment.NodeId) ||
            !string.Equals(comment.AuthorType, BotType, StringComparison.Ordinal) ||
            !string.Equals(comment.AuthorLogin, BotLogin, StringComparison.Ordinal) ||
            comment.AuthorId != BotId ||
            !string.Equals(comment.Decision, AcceptedDecision, StringComparison.Ordinal))
            return Block("GITHUB_COMMENT_IDENTITY_OR_SCHEMA");

        if (!IsLowerHex(comment.PredecessorDigestSha256, 64) ||
            !IsLowerHex(comment.SourceCommitSha1, 40) ||
            !IsLowerHex(comment.SourceTreeSha1, 40) ||
            !IsLowerHex(comment.PackageBlobSha1, 40) ||
            !IsLowerHex(comment.PackageSha256, 64) ||
            !IsLowerHex(comment.CatalogSha256, 64) ||
            comment.PackageLength is <= 0 or > 16_777_216)
            return Block("IMMUTABLE_PACKAGE_IDENTITY_INVALID");

        if (comment.PredecessorGeneration != initial.ActiveGeneration ||
            comment.NextGeneration != initial.ActiveGeneration + 1 ||
            !string.Equals(comment.PredecessorDigestSha256, initial.ActiveDigestSha256,
                StringComparison.Ordinal))
            return Block("GENERATION_OR_PREDECESSOR_MISMATCH");

        // The current accepted package has one operation. A new operation ID
        // needs a separately accepted catalog change, not caller-selected text.
        if (comment.OperationIds is null || comment.OperationIds.Count != 1 ||
            !string.Equals(comment.OperationIds[0],
                AdminReviewedOperationRegistry.ElevatedIdentityProof,
                StringComparison.Ordinal))
            return Block("UNREVIEWED_OPERATION_CATALOG");

        if (comment.CreatedUtc.Offset != TimeSpan.Zero ||
            comment.UpdatedUtc.Offset != TimeSpan.Zero ||
            comment.ExpiresUtc.Offset != TimeSpan.Zero ||
            comment.CreatedUtc != comment.UpdatedUtc ||
            comment.CreatedUtc > nowUtc ||
            comment.CreatedUtc < nowUtc.AddMinutes(-10) ||
            comment.ExpiresUtc <= nowUtc ||
            comment.ExpiresUtc > comment.CreatedUtc.AddMinutes(10))
            return Block("STALE_EDITED_OR_AMBIGUOUS_AUTHORIZATION");

        // This deliberately cannot return PASS, ACCEPTED, PROMOTED or READY:
        // it has not authenticated GitHub/165-W, examined package bytes or
        // verified admin-only filesystem state or independent source review.
        return new PromotionDataCheck(DataOnly, "EXTERNAL_TRUST_GATES_REQUIRED");
    }
}
