# Media Root Coverage and Exclusion Planner v0 - source-only design

**Status: PLAN-ONLY, INERT, SOURCE-ONLY. NOT A VERIFIER, WRITER, OR APPROVAL FOR PRIVATE DATA.**

Governing item: infrastructure-tools#341 (PLAN ONLY - no Plex cutover, source deletion, host mutation, or CI/JIT authority). This page and the two source files are the smallest fixture-only expression of the post-copy verification acceptance contract recorded in issue #341 comment 7094897149. Live private ledger/controller state remains authoritative; nothing here reads it.

## Scope

A single pure function, Get-LdwMediaCoverage, classifies a complete approved inventory into nine mutually exclusive buckets. It accepts only in-memory objects, performs no file, volume, process, network, database or torrent-client access, and emits sanitized counts, bytes, per-entry bucket and reason. It does not rank, promote, copy, delete or authorize anything.

## Identity and reconciliation

- Source key = normalized source_volume_id, normalized approved_root_id, normalized relative path. IDs and paths must be strings; control characters (including separator byte 0x1f), path separators inside IDs, absolute/drive/UNC forms, ADS colons, dot and dotdot components, repeated/trailing separators are refused. Normalization is lowercase with slash path form.
- Destination uniqueness is checked over copy-class proofs only, after a strict relative canonicalizer: drive roots, absolute/UNC paths, `.`/`..` components, ADS colons, controls, separator injection, repeated/trailing separators, and reparse/link/odd-identity metadata flags are refused. Canonical equivalents such as `stage/a.bin`, `STAGE\\A.BIN` and `stage\\a.bin` collapse to one key; a repeated destination marks every affected entry COLLISION_ERROR.
- Untrusted booleans (`piece_proof_valid`, `source_stable`, `changed_since_copy`, `preallocated_only`, `excluded`) are parsed strictly as typed booleans or exact `true`/`false` strings only. PowerShell truthiness is never used: a text `false` never counts true; malformed or wrong-typed values are COLLISION_ERROR.
- A proof `size_bytes`, when present, must be a positive integer matching the inventory size. A proof key with no corresponding inventory source is counted in `orphan_proof_count`; it is never silently ignored.
- Every inventory row yields exactly one entry. `reconciled` means only that bucket counts and bytes sum to input totals; `reconciled_scope` states explicitly that this is **not** independent proof of full external inventory. `fail_closed` is true when any COLLISION_ERROR or orphan proof exists.
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
| COLLISION_ERROR | Structural refusal: duplicate source/destination/proof key, wrong root/volume, malformed key, bad size, malformed boolean, unsafe destination identity, proof size mismatch, unstable source, missing destination. |

Duplicate source policy is explicit and fail-closed: **both** occurrences of a duplicated source key are COLLISION_ERROR. The prior test expectation of preserving one occurrence was wrong and has been corrected.

## Determinism and refusal

Input order is preserved; there is no clock, environment, randomness or culture-dependent formatting. preallocated_only=true and torrent_state=unknown are always excluded regardless of byte length. A matching destination SHA-256 alone cannot produce FULLY_VERIFIED. A complete torrent with an applicable full-hash proof but unproven pieces stays UNKNOWN_OR_AMBIGUOUS_TORRENT for both full-hash tiers. Missing qB certainty is never inferred from preallocated byte size.

## Synthetic fixtures

The embedded made-up JSON uses tokens such as VOL-SYNTH-A, ROOT-A and fixture/alpha.bin; no real paths, volume serials, torrent IDs, media titles, manifests or qB/Plex data appear anywhere. The planner reads no files; fixtures are parsed from in-memory literals. A main fixture covers all nine buckets and a negative fixture covers strict-boolean strings/types, 0x1f separator injection, dot-path components, absolute/UNC/ADS/control destinations, reparse metadata, proof size mismatch, destination canonicalization collisions, orphan proofs, and the raw-destination hash boundary. Control bytes are inserted from char 0x1f at runtime, never stored literally in source.

## Validation evidence

A local synthetic-only run on an isolated internal C: TEMP folder with the exact source blobs, after a fresh no-writer check (no copy process, no chain lock, no STOP, no instance locks), completed with:

```
MEDIA_COVERAGE_PLANNER_V0=PASS assertions=53
MEDIA_COVERAGE_PLANNER_PRIVATE_OPERATION=NOT_AUTHORIZED
MEDIA_COVERAGE_PLANNER_PLANNER_IO=NONE
EXIT_CODE=0
```

No media, E:/P:, qB/Plex, network, service, or workflow access occurred. Hosted checks are reviewed only as they run naturally on the exact head; none was manually triggered.

## Non-authorization

- Does not access private manifests, P: or E: volumes, Plex/qB data, running writers, locks or checkpoints.
- Does not authorize copying, cutover, source mutation, service/ACL/task changes, or promotion of RAW_PENDING or LEGACY_MANIFEST_ONLY to FULLY_VERIFIED.
- No private data was read; the only local execution was the embedded synthetic fixture test described above. No workflow file was modified.

## Acceptance gates for any later private operation (none satisfied here)

1. Authoritative copy supervisor STOP, chain lock released, terminal chain status and segment checkpoints proved on OfficePC.
2. Issue-specific owner authorization naming this planner and its exact reviewed blob; separate from general copy approval.
3. Fresh independent author-excluded exact-head H0/M0 source review of the corrected PR head and tree.
4. Synthetic-only negative tests using embedded fixtures; internal-disk fixture validation only, never live media.
5. Sanitized aggregate output only; private titles, paths and torrent identifiers stay local.
6. Exact-head hosted checks reviewed if they run naturally; no manual trigger, no merge, no ready-for-review.

## Cost and data

Zero incremental cost. No secrets, credentials, paid service or external integration.
