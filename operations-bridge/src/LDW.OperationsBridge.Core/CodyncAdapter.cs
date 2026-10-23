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
    // Canonical reviewer topology frozen from business-operations #645 and
    // infrastructure-tools #69. Names and memberships are re-read on the live
    // host for each destination resolution; retired proof groups are excluded.
    public static readonly IReadOnlyList<CodyncDestination> All =
    [
        new("55a2491d-1454-478e-b44c-6f26878c95bd", "LDW IR - Cursor", "bot", "Cursor", "IR", []),
        new("a3ea9330-8fca-4c0f-afe2-7434a6e3c5c5", "LDW Cursor Challenge", "bot", "Cursor", "Challenge", []),
        new("e28c6540-c485-4aa5-9d87-022aa82ac67a", "LDW Critique - Cursor", "bot", "Cursor", "Critique", []),
        new("ac0f91e7-15eb-4b93-84d0-b665ace7f639", "LDW IR - Antigravity", "bot", "Antigravity", "IR", []),
        new("59bb9175-f1ff-4cf2-9023-31000402b098", "LDW Challenge - Antigravity", "bot", "Antigravity", "Challenge", []),
        new("da449a7a-20e3-42df-9085-0090a92af952", "LDW Critique - Antigravity", "bot", "Antigravity", "Critique", []),
        new("90c4bbdd-b099-4458-8386-7923d610c495", "LDW IR - Codex", "bot", "Codex", "IR", []),
        new("78b5c5a9-548e-4a12-93d9-c19009481e7b", "LDW Challenge — Codex", "bot", "Codex", "Challenge", []),
        new("2f0be363-adeb-48ca-acb4-5eada31b4a30", "LDW Critique — Codex", "bot", "Codex", "Critique", []),
        new("34ddaa45-7eaa-4cbc-9f8d-b3715df83b09", "Board Cursor", "group", "Cross-Provider", "Review Board", [
            "55a2491d-1454-478e-b44c-6f26878c95bd", "78b5c5a9-548e-4a12-93d9-c19009481e7b", "da449a7a-20e3-42df-9085-0090a92af952"]),
        new("5177b135-10ba-423f-ad6a-2b45a24aad60", "Board Codex", "group", "Cross-Provider", "Review Board", [
            "90c4bbdd-b099-4458-8386-7923d610c495", "59bb9175-f1ff-4cf2-9023-31000402b098", "e28c6540-c485-4aa5-9d87-022aa82ac67a"]),
        new("e7ff8ac2-f22d-4250-acc1-35126422725d", "Board Antigravity", "group", "Cross-Provider", "Review Board", [
            "ac0f91e7-15eb-4b93-84d0-b665ace7f639", "a3ea9330-8fca-4c0f-afe2-7434a6e3c5c5", "2f0be363-adeb-48ca-acb4-5eada31b4a30"])
    ];
}
