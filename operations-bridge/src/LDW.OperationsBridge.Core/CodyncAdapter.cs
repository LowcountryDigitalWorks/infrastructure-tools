namespace LDW.OperationsBridge.Core;

public sealed record CodyncDestination(
    string Id,
    string Name,
    string Kind,
    string Provider,
    string Role,
    IReadOnlyList<string> Members,
    bool Enabled = true);

public sealed record CodyncHostHealth(bool Ready, string Version, bool Busy);

public sealed record CodyncSendReceipt(
    string DestinationId,
    string DestinationName,
    string ClientNonce,
    string RootEntryId,
    long RootSequence,
    long RootTurn,
    long RootRevision,
    DateTimeOffset SubmittedAt);

public sealed record CodyncCorrelatedReply(
    string DestinationId,
    string DestinationName,
    string RootEntryId,
    string AuthorId,
    string Text,
    long Sequence,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    bool NeedsInput);

public sealed record CodyncWaitResult(
    bool ProviderStartObserved,
    bool NeedsInput,
    CodyncCorrelatedReply? Reply,
    string State,
    string Evidence);

public interface ICodyncBridgeAdapter
{
    Task<CodyncHostHealth> GetHealthAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<CodyncDestination>> ListApprovedBotsGroupsAsync(CancellationToken cancellationToken);
    Task<CodyncSendReceipt> SendExactAsync(
        string destinationId,
        string destinationName,
        string text,
        string clientNonce,
        IReadOnlyList<string> mentionedMemberIds,
        CancellationToken cancellationToken);
    Task<CodyncWaitResult> WaitReadExactAsync(
        CodyncSendReceipt receipt,
        string expectedAuthorId,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

public static class CodyncApprovedDestinations
{
    // Identity allowlist frozen from business-operations #621/#644. Names and group
    // memberships are re-read on the live host for each destination resolution.
    public static readonly IReadOnlyList<CodyncDestination> All =
    [
        new("55a2491d-1454-478e-b44c-6f26878c95bd", "LDW IR - Cursor", "bot", "Cursor", "IR", []),
        new("a3ea9330-8fca-4c0f-afe2-7434a6e3c5c5", "LDW Cursor Challenge", "bot", "Cursor", "Challenge", []),
        new("e28c6540-c485-4aa5-9d87-022aa82ac67a", "LDW Critique - Cursor", "bot", "Cursor", "Critique", []),
        new("ac0f91e7-15eb-4b93-84d0-b665ace7f639", "LDW IR - Antigravity", "bot", "Antigravity", "IR", []),
        new("59bb9175-f1ff-4cf2-9023-31000402b098", "LDW Challenge - Antigravity", "bot", "Antigravity", "Challenge", []),
        new("da449a7a-20e3-42df-9085-0090a92af952", "LDW Critique - Antigravity", "bot", "Antigravity", "Critique", []),
        new("e6e61ff1-ca60-4d87-b468-dfdb34d1acea", "LDW Review Board — Cursor", "group", "Cursor", "Review Board", [
            "55a2491d-1454-478e-b44c-6f26878c95bd", "a3ea9330-8fca-4c0f-afe2-7434a6e3c5c5", "e28c6540-c485-4aa5-9d87-022aa82ac67a"]),
        new("7bc71416-44ba-4f0e-98e1-da0cef309a40", "LDW Review Board — Antigravity", "group", "Antigravity", "Review Board", [
            "ac0f91e7-15eb-4b93-84d0-b665ace7f639", "59bb9175-f1ff-4cf2-9023-31000402b098", "da449a7a-20e3-42df-9085-0090a92af952"]),
        new("729350f2-89cc-460e-9a6c-8af05037d0c4", "LDW Review Board — Cross-Provider", "group", "Cross-Provider", "Review Board", [
            "55a2491d-1454-478e-b44c-6f26878c95bd", "a3ea9330-8fca-4c0f-afe2-7434a6e3c5c5", "e28c6540-c485-4aa5-9d87-022aa82ac67a",
            "ac0f91e7-15eb-4b93-84d0-b665ace7f639", "59bb9175-f1ff-4cf2-9023-31000402b098", "da449a7a-20e3-42df-9085-0090a92af952"])
    ];
}
