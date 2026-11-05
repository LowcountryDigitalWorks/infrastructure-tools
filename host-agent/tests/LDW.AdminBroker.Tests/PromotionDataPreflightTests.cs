using System.Runtime.CompilerServices;
using LDW.AdminBroker;

// Isolated deterministic contract proof. The production launcher, broker
// operation catalog, GitHub App, protected task and host are NOT invoked.
internal static class PromotionDataPreflightTests
{
    [ModuleInitializer]
    internal static void Initialize() => Run();

    private static void Run()
    {
        int assertions = 0;
        void Assert(bool condition, string label)
        {
            if (!condition) throw new Exception("Promotion data preflight: " + label);
            assertions++;
        }

        var now = new DateTimeOffset(2026, 11, 5, 3, 0, 0, TimeSpan.Zero);
        const int ledger = 9001; // Synthetic ONLY; not a real/frozen authority issue.
        var state = new PromotionProtectedState(
            true, 7, "NONE", 4, new string('a', 64));
        var facts = new PromotionCommentFacts(
            1, "LowcountryDigitalWorks/infrastructure-tools", ledger,
            73331, "IC_kw12345678", "Bot", "ldw-activepieces-165-w[bot]",
            331690200, now.AddMinutes(-1), now.AddMinutes(-1),
            "ACCEPTED_PROMOTION", 4, 5, new string('a', 64),
            new string('b', 40), new string('c', 40), new string('d', 40),
            new string('e', 64), 4096, new string('f', 64),
            new[] { AdminReviewedOperationRegistry.ElevatedIdentityProof },
            now.AddMinutes(4));

        PromotionDataCheck Check(
            PromotionCommentFacts? candidate,
            PromotionProtectedState? before = null,
            PromotionProtectedState? last = null,
            long configuredIssue = ledger,
            DateTimeOffset? clock = null) =>
            PromotionDataPreflight.Check(candidate, before ?? state,
                last ?? state, configuredIssue, clock ?? now);

        void Block(PromotionDataCheck result, string label)
        {
            Assert(result.Classification == "BLOCKED", label);
            Assert(result.ReasonCode.Length is > 0 and <= 80, label + " closed reason");
        }

        var matched = Check(facts);
        Assert(matched.Classification == "DATA_ONLY_CONSISTENT_NOT_AUTHORIZED",
            "valid synthetic records are never authorization");
        Assert(matched.ReasonCode == "EXTERNAL_TRUST_GATES_REQUIRED",
            "data-only state preserves external trust gate");

        // Issue anchor and immutable server-returned principal. No owner/PAT
        // identity may silently replace the exact narrowly scoped 165-W bot.
        Block(Check(facts, configuredIssue: 0), "missing compiled ledger");
        Block(Check(facts, configuredIssue: 9002), "different ledger");
        Block(Check(facts with { Repository = "someone/private" }), "repository substitution");
        Block(Check(facts with { LedgerIssueNumber = 9002 }), "issue substitution");
        Block(Check(facts with { CommentId = 0 }), "comment id missing");
        Block(Check(facts with { NodeId = "invalid space" }), "node id malformed");
        Block(Check(facts with { AuthorType = "User" }), "PAT identity");
        Block(Check(facts with { AuthorLogin = "eddie" }), "owner identity");
        Block(Check(facts with { AuthorId = 331690201 }), "bot id mismatch");
        Block(Check(facts with { Decision = "ACCEPTED_ROLLBACK" }), "unapproved decision");
        Block(Check(facts with { SchemaVersion = 2 }), "schema drift");
        Block(Check(null), "missing comment");

        // Protected local disable and pre-activation re-read are mandatory.
        Block(PromotionDataPreflight.Check(facts, null, state, ledger, now),
            "missing initial protected state");
        Block(PromotionDataPreflight.Check(facts, state, null, ledger, now),
            "missing final protected state");
        Block(Check(facts, before: state with { PromotionEnabled = false }),
            "disabled at request start");
        Block(Check(facts, last: state with { PromotionEnabled = false }),
            "disabled during request before swap");
        Block(Check(facts, last: state with { ControlGeneration = 8 }),
            "emergency control generation race");
        Block(Check(facts, last: state with { ActiveGeneration = 5 }),
            "active pointer race");
        Block(Check(facts, last: state with { ActiveDigestSha256 = new string('2', 64) }),
            "active package changed");
        Block(Check(facts, before: state with { ReasonCode = "INCIDENT_DISABLED" }),
            "incident-state tamper");
        Block(Check(facts, before: state with { ControlGeneration = 0 }),
            "initial control generation unknown");

        // Immutable package identities and exact next generation.
        Block(Check(facts with { NextGeneration = 6 }), "skip a generation");
        Block(Check(facts with { PredecessorGeneration = 3 }), "stale predecessor");
        Block(Check(facts with { PredecessorDigestSha256 = new string('0', 64) }),
            "predecessor digest mismatch");
        Block(Check(facts with { SourceCommitSha1 = new string('Z', 40) }),
            "nonhex source commit");
        Block(Check(facts with { SourceTreeSha1 = new string('1', 39) }),
            "short source tree");
        Block(Check(facts with { PackageBlobSha1 = new string('B', 40) }),
            "uppercase blob");
        Block(Check(facts with { PackageSha256 = new string('8', 63) }),
            "short SHA256");
        Block(Check(facts with { CatalogSha256 = "" }), "catalog missing");
        Block(Check(facts with { PackageLength = 0 }), "empty package");
        Block(Check(facts with { PackageLength = 16_777_217 }), "oversized package");
        Block(Check(facts with { OperationIds = Array.Empty<string>() }), "missing catalog");
        Block(Check(facts with { OperationIds = new[] { "ARBITRARY_SHELL" } }),
            "unknown operation");
        Block(Check(facts with { OperationIds = new[]
            { "ELEVATED_IDENTITY_PROOF", "DRAGONFLY_V2_PUBLISH_REVIEWED" } }),
            "unreviewed operation expansion");

        // Bounded UTC TTL, immutable comment, no replayable stale authority.
        Block(Check(facts with { CreatedUtc = now.AddMinutes(-11),
            UpdatedUtc = now.AddMinutes(-11) }), "stale creation");
        Block(Check(facts with { CreatedUtc = now.AddMinutes(1),
            UpdatedUtc = now.AddMinutes(1) }), "future comment");
        Block(Check(facts with { UpdatedUtc = now }), "edited comment");
        Block(Check(facts with { ExpiresUtc = now }), "expired");
        Block(Check(facts with { ExpiresUtc = now.AddMinutes(10) }),
            "overlong relative TTL");
        Block(Check(facts, clock: now.ToOffset(TimeSpan.FromHours(-5))),
            "ambiguous local timezone clock");

        // This module has no actual file, broker, provider, parser, execution,
        // privileged task or account installation code. Future trusted package
        // deployment must independently attest every trust boundary.
        var checker = typeof(PromotionDataPreflight).GetMethod("Check",
            System.Reflection.BindingFlags.Static |
            System.Reflection.BindingFlags.NonPublic |
            System.Reflection.BindingFlags.DeclaredOnly);
        Assert(checker is not null && checker.ReturnType == typeof(PromotionDataCheck),
            "public-style data-check entry cannot return success bool");
        Console.WriteLine($"Promotion Gate B DATA-ONLY preflight: {assertions} assertions PASS.");
    }
}
