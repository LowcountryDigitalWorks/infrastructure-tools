# Media Root Coverage and Exclusion Planner v0 - source-only design

**Status: PLAN-ONLY, INERT, SOURCE-ONLY. NOT A VERIFIER, WRITER, OR APPROVAL FOR PRIVATE DATA.**

Governing item: infrastructure-tools#341 (PLAN ONLY - no Plex cutover, source deletion, host mutation, or CI/JIT authority). This page and the two source files are the smallest fixture-only expression of the post-copy verification acceptance contract recorded in issue #341 comment 7094897149. Live private ledger/controller state remains authoritative; nothing here reads it.

## Scope

A single pure function, Get-LdwMediaCoverage, classifies a complete approved inventory into nine mutually exclusive buckets. It accepts only in-memory objects, performs no file, volume, process, network, database or torrent-client access, and emits sanitized counts, bytes, per-entry bucket and reason. It does not rank, promote, copy, delete or authorize anything.

## Identity and reconciliation

- Source key = normalized source_volume_id, normalized approved_root_id, normalized relative path. Normalization is lowercase with slash path form; absolute, drive-prefixed, dot and dotdot segments are refused.
- Destination uniqueness is checked over copy-class proofs only; a repeated destination marks every affected entry COLLISION_ERROR.
- Every inventory row yields exactly one entry; reconciled=true only when bucket counts and bytes sum to input totals. Duplicate source keys, wrong root/volume, malformed or traversal paths, non-positive size, duplicate or inconsistent proofs, unstable/changed source and missing destination are hard COLLISION_ERROR.

## Buckets

| Bucket | Meaning |
| --- | --- |
| FULLY_VERIFIED | Full source and destination SHA-256 pair; torrent pieces also required when applicable and proven. |
| LEGACY_MANIFEST_ONLY | Historical manifest match only; never promoted silently. |
| RAW_PENDING | Raw copy with destination-only SHA-256; not full-pair proof. |
| TRUSTED_NOT_COPIED | Trusted complete torrent source with no copy proof yet. |
| STABLE_NON_TORRENT_CANDIDATE | Stable non-torrent source; needs a later stability check. |
| INCOMPLETE_TORRENT | Incomplete or preallocated-only torrent; excluded regardless of byte length. |
| UNKNOWN_OR_AMBIGUOUS_TORRENT | Unknown or attribution-ambiguous torrent, or unproven pieces; excluded. |
| OTHER_EXCLUDED | Explicit exclusion marker. |
| COLLISION_ERROR | Structural refusal: duplicate key, wrong root, traversal, bad size, duplicate destination, unstable source, missing destination. |

## Determinism and refusal

Input order is preserved; there is no clock, environment, randomness or culture-dependent formatting. preallocated_only=true and torrent_state=unknown are always excluded regardless of byte length. A matching destination SHA-256 alone cannot produce FULLY_VERIFIED. full_hash_pair with an applicable complete torrent but unproven pieces stays UNKNOWN_OR_AMBIGUOUS_TORRENT. Missing qB certainty is never inferred from preallocated byte size.

## Synthetic fixtures

The test embeds made-up JSON fixtures with tokens such as VOL-SYNTH-A, ROOT-A and fixture/alpha.bin. No real paths, volume serials, torrent IDs, media titles, manifests or qB/Plex data appear anywhere. The planner reads no files; fixtures are parsed from in-memory literals.

## Non-authorization

- Does not access private manifests, P: or E: volumes, Plex/qB data, running writers, locks or checkpoints.
- Does not authorize copying, cutover, source mutation, service/ACL/task changes, or promotion of RAW_PENDING or LEGACY_MANIFEST_ONLY to FULLY_VERIFIED.
- No hosted job and no local test was executed for this design; no workflow file was modified.

## Acceptance gates for any later private operation (none satisfied here)

1. Authoritative copy supervisor STOP, chain lock released, terminal chain status and segment checkpoints proved on OfficePC.
2. Issue-specific owner authorization naming this planner and its exact reviewed blob; separate from general copy approval.
3. Independent author-excluded exact-head H0/M0 source review of the PR head and tree.
4. Synthetic-only negative tests using embedded fixtures; after writer stop, internal-disk fixture validation only, never live media.
5. Sanitized aggregate output only; private titles, paths and torrent identifiers stay local.
6. Exact-head hosted checks reviewed if they run naturally; no manual trigger, no merge, no ready-for-review.

## Cost and data

Zero incremental cost. No secrets, credentials, paid service or external integration.