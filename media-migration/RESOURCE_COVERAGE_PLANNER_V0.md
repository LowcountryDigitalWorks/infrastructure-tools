# Media Root Coverage and Exclusion Planner v0 - source-only design

**Status: PLAN-ONLY, INERT, SOURCE-ONLY. NOT A VERIFIER, WRITER, OR APPROVAL FOR PRIVATE DATA.**

Governing item: infrastructure-tools#341 (PLAN ONLY - no Plex cutover, source deletion, host mutation, or CI/JIT authority). This page and the two source files are the smallest fixture-only expression of the post-copy verification acceptance contract recorded in issue #341 comment 7094897149. Live private ledger/controller state remains authoritative; nothing here reads it.

## Scope

A single pure function, Get-LdwMediaCoverage, classifies a complete approved inventory into nine mutually exclusive buckets. It accepts only in-memory objects, performs no file, volume, process, network, database or torrent-client access, and emits sanitized counts, bytes, per-entry bucket and reason. It does not rank, promote, copy, delete or authorize anything. Every emitted bucket label, reason and aggregate is an explicitly **unvalidated assertion** about the supplied synthetic input (`evidence_status=UNVALIDATED_ASSERTIONS_ONLY`, `bucket_labels_are_assertions=true`, `private_data_authorization=NONE`), never validated evidence.

## Identity and reconciliation

- Source key = normalized source_volume_id, normalized approved_root_id, normalized relative path. IDs and paths must be strings; control characters (including separator byte 0x1f), path separators inside IDs, absolute/drive/UNC forms, ADS colons, dot and dotdot components, repeated/trailing separators are refused. Normalization is lowercase with slash path form. **M2:** every source and destination path component additionally fails closed on Windows path aliases: a trailing dot or space, or a reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM1`-`COM9`, `LPT1`-`LPT9`, plus superscript `COM¹`-`COM³` and `LPT¹`-`LPT³`) matched case-insensitively and with any extension suffix, normalizes to empty and therefore COLLISION_ERROR. This covers `a.bin.`, `a.bin space`, `.. space`, `CON.txt`, `conin$.bin` and `lpt9.foo`. Both path normalizers (relative paths and destinations) apply the same guard.
- Destination uniqueness is checked over copy-class proofs only, after a strict relative canonicalizer: drive roots, absolute/UNC paths, `.`/`..` components, ADS colons, controls, separator injection, repeated/trailing separators, and reparse/link/odd-identity metadata flags are refused. Canonical equivalents such as `stage/a.bin`, `STAGE\\A.BIN` and `stage\\a.bin` collapse to one key; a repeated destination marks every affected entry COLLISION_ERROR.
- Untrusted booleans (`piece_proof_valid`, `source_stable`, `changed_since_copy`, `preallocated_only`) are parsed strictly as typed booleans or exact `true`/`false` strings only. PowerShell truthiness is never used: a text `false` never counts true; malformed or wrong-typed values are COLLISION_ERROR. **M1:** the inventory `excluded` marker must be PRESENT and a valid strict boolean on every row; missing, null or wrong-typed values are COLLISION_ERROR and are never promoted to FULLY_VERIFIED or any accept bucket.
- **L1:** every copy-class proof (`full_hash_pair`, `full_hash_pair_plus_pieces`, `legacy_manifest`, `raw_dest_sha256`) MUST carry a present, positive-integer `size_bytes` exactly equal to the inventory size; missing, null, zero, negative, wrong-typed or mismatched proof size is COLLISION_ERROR. Non-copy-class proofs are unaffected. A proof key with no corresponding inventory source is counted in `orphan_proof_count`; it is never silently ignored.
- Every inventory row yields exactly one entry. `reconciled` means only that bucket counts and bytes sum to input totals; `reconciled_scope` states explicitly that this is **not** independent proof of full external inventory. **L2:** `root_summary` reports count, bytes and per-bucket counts for every normalized approved root, including zero-count roots (plus an `__unattributed__` bucket), and `root_reconciled` is exact over the same input totals. Two approved roots that normalize to the same id+volume are refused: `duplicate_approved_root_count` is set and every row for that root is COLLISION_ERROR. A single approved_root_id spanning two distinct source volumes is refused rather than silently merged: `root_identity_ambiguous_count` is set, every row carrying that id becomes COLLISION_ERROR with reason `AMBIGUOUS_ROOT_IDENTITY`, and `fail_closed` is true. `fail_closed` is true on any COLLISION_ERROR, orphan proof, overflow or duplicate approved root. **L3:** all Int64 sums (`input_bytes`, per-bucket bytes, per-root bytes and reconciliation totals) use checked addition; overflow sets `overflow_refused=true` and the affected row becomes COLLISION_ERROR with reason `INT64_OVERFLOW` instead of silently promoting to a double or wrapping.
- Source/root allowlists are not weakened. A raw destination SHA-256 can only produce RAW_PENDING; it can never produce FULLY_VERIFIED.

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
| COLLISION_ERROR | Structural refusal: duplicate source/destination/proof key, duplicate or volume-ambiguous approved root, wrong root/volume, malformed key or Windows alias/reserved-device component (`CONIN$`/`CONOUT$`, superscript COM/LPT, case and extension aliases), bad size, missing/malformed boolean, unsafe destination identity, missing/null/mismatched proof size, unstable source, missing destination, Int64 overflow. |

Duplicate source policy is explicit and fail-closed: **both** occurrences of a duplicated source key are COLLISION_ERROR. The prior test expectation of preserving one occurrence was wrong and has been corrected.

## Determinism and refusal

Input order is preserved; there is no clock, environment, randomness or culture-dependent formatting. preallocated_only=true and torrent_state=unknown are always excluded regardless of byte length. A matching destination SHA-256 alone cannot produce FULLY_VERIFIED. A complete torrent with an applicable full-hash proof but unproven pieces stays UNKNOWN_OR_AMBIGUOUS_TORRENT for both full-hash tiers. Missing qB certainty is never inferred from preallocated byte size.

## Synthetic fixtures

The embedded made-up JSON uses tokens such as VOL-SYNTH-A, ROOT-A and fixture/alpha.bin; no real paths, volume serials, torrent IDs, media titles, manifests or qB/Plex data appear anywhere. The planner reads no files; fixtures are parsed from in-memory literals. A main fixture covers all nine buckets and a negative fixture covers strict-boolean strings/types, 0x1f separator injection, dot-path components, absolute/UNC/ADS/control destinations, reparse metadata, proof size mismatch, destination canonicalization collisions, orphan proofs, and the raw-destination hash boundary. Control bytes are inserted from char 0x1f at runtime, never stored literally in source. A third edge fixture adds explicit missing/null `excluded` promotion negatives, Windows trailing-dot/space and `.. space` aliases, reserved device names with extension suffixes on both source and destination components, duplicate normalized approved roots and a zero-count root. A fourth overflow fixture uses `[int64]::MaxValue` plus one to exercise the L3 boundary. Three further negative fixtures cover L1 copy-class proofs with an absent or JSON-null `size_bytes`, L2 reuse of one approved root id across two distinct synthetic volumes, and `CONIN$`/`CONOUT$`/superscript COM-LPT aliases on both path normalizers. All original fixture expectations are retained with mandatory fields made explicit.

## Validation evidence

This exact correction was authored and committed through the authenticated GitHub REST API only. **No local test, build, checkout, media scan or controller command was executed in this correction, and no test result is claimed for these exact blobs.** The embedded synthetic fixtures and assertions are source-only and must be re-reviewed and allowed to run naturally in hosted checks on the exact new head; no hosted check was manually triggered. All fixture tokens are invented; no private data was read or transmitted.

## Non-authorization

- Does not access private manifests, P: or E: volumes, Plex/qB data, running writers, locks or checkpoints.
- Does not authorize copying, cutover, source mutation, service/ACL/task changes, or promotion of RAW_PENDING or LEGACY_MANIFEST_ONLY to FULLY_VERIFIED.
- No private data was read or transmitted in this correction. No workflow, runtime or CI/JIT file was modified; no hosted check was manually triggered.

## Acceptance gates for any later private operation (none satisfied here)

1. Authoritative copy supervisor STOP, chain lock released, terminal chain status and segment checkpoints proved on OfficePC.
2. Issue-specific owner authorization naming this planner and its exact reviewed blob; separate from general copy approval.
3. Fresh independent author-excluded exact-head H0/M0 source review of the corrected PR head and tree.
4. Synthetic-only negative tests using embedded fixtures; internal-disk fixture validation only, never live media.
5. Sanitized aggregate output only; private titles, paths and torrent identifiers stay local.
6. Exact-head hosted checks reviewed if they run naturally; no manual trigger, no merge, no ready-for-review.

## Cost and data

Zero incremental cost. No secrets, credentials, paid service or external integration.