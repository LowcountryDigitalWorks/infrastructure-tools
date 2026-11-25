# Unified Storage Migration Report v0 — source-only aggregate contract

This is a distinct source candidate for #341. It is **not** the planner, the
provenance bridge, a reviewer, a drive/migration task, or an accepted
production source. `report.py` is a pure Python standard-library (builtins-only)
adapter. It performs no I/O: no files, paths, metadata, clock, process,
network, or trust acquisition. It accepts only synthetic JSON-compatible
values supplied by the caller and is not an extractor.

## Sole public API

`build_report(planner, bridge=None)` is the only public name (`__all__ =
['build_report']`). All other module names are private implementation details
and unsupported for direct calls. The underscore prefix is a naming
convention, not a security boundary; no claim is made that private names
enforce access control or that arbitrary arguments to direct helper calls are
safe. Guarantees apply only to data passing `build_report` validation.

## Planner input schema (required, aggregate only)

Exact top-level field set — no missing or extra keys:

| Field | Type / value |
| --- | --- |
| `schema` | exact string `media-coverage-planner-v0` |
| `evidence_status` | exact string `UNVALIDATED_ASSERTIONS_ONLY` |
| `private_data_authorization` | exact string `NONE` |
| `bucket_labels_are_assertions` | bool, must be `True` |
| `reconciled` | bool |
| `reconciled_scope` | exact string `internal_partition_only_not_external_completeness` |
| `root_reconciled` | bool |
| `overflow_refused` | bool |
| `duplicate_approved_root_count` | int, 0..2^63-1 |
| `root_identity_ambiguous_count` | int, 0..2^63-1 |
| `fail_closed` | bool |
| `orphan_proof_count` | int, 0..2^63-1 |
| `input_files` | int, 0..2^63-1 |
| `input_bytes` | int, 0..2^63-1 |
| `buckets` | object with exactly the nine keys below |

Nine mutually exclusive asserted buckets, each an object with exactly
`count` and `bytes` (both int, 0..2^63-1): `FULLY_VERIFIED`,
`LEGACY_MANIFEST_ONLY`, `RAW_PENDING`, `TRUSTED_NOT_COPIED`,
`STABLE_NON_TORRENT_CANDIDATE`, `INCOMPLETE_TORRENT`,
`UNKNOWN_OR_AMBIGUOUS_TORRENT`, `OTHER_EXCLUDED`, `COLLISION_ERROR`.

Explicitly rejected anywhere in the envelope: `entries`, `root_summary`,
`source_key`, `destination_path`, `path(s)`, `internal_id`, `full_id`,
`volume`, `root`, `rows`, `bindings`, `members`, `staged`, `record(s)`,
`observed_at`, and any other extra key. Caller sanitization and root
completeness are never assumed or re-derived.

## Optional bridge aggregate input

Exact field set: `schema` = `media-provenance-bridge-v0-aggregate`;
`total_rows` and `metadata_shape_match_count`, both int 0..2^63-1 with
`match <= total`. Raw rows, identities, and positional join data are rejected.
The aggregate is reported separately; it is never joined by position, summed
with planner totals, or used as an actual-coverage denominator.

## Validation and fail-closed behavior

Exact built-in types only (`type(x) is T`, never `isinstance`); bounded string
keys; every comparison, hash, length, and container access is preceded by a
type guard, so hostile `__eq__`/`__ne__`/`__hash__`/`__str__`/`__repr__`/
`__bool__`/`__int__` hooks are never invoked on the supported path.

Fail-closed sanitized reason codes: `SCHEMA_MISMATCH`,
`CONTRACT_CONSTANT_MISMATCH`, `FIELD_TYPE_INVALID`, `FIELD_RANGE_INVALID`,
`FIELD_SET_MISMATCH`, `BUCKET_SET_MISMATCH`,
`BUCKET_FIELD_SET_MISMATCH`, `ARITHMETIC_MISMATCH`, `ARITHMETIC_OVERFLOW`,
`FLAG_CONFLICT`, `OVERFLOW_REFUSED`, `RAW_DATA_REJECTED`,
`BRIDGE_SCHEMA_MISMATCH`, `BRIDGE_FIELD_TYPE_INVALID`,
`BRIDGE_FIELD_RANGE_INVALID`, `BRIDGE_FIELD_SET_MISMATCH`,
`BRIDGE_SUBSET_MISMATCH`.

Bucket count and byte sums must equal `input_files` and `input_bytes` and stay
within int64. `reconciled` must match that computed result. `fail_closed` must
be `True` when any error signal is present (collision bucket, orphan proofs,
overflow refusal, duplicate approved roots, ambiguous root identities).
`overflow_refused=True` always fails closed. On any failure the output has no
trusted counts or buckets and carries only fixed labels plus sorted codes.

## Output schema (fixed labels, deterministic)

Both outcomes share the same top-level keys: `schema`, `report_status`,
`evidence_status`, `private_data_authorization`, `disposition`,
`promotion_action`, `eject_action`, `cutover_action`,
`external_completeness`, `independent_proof`, `freshness`,
`reconciled_scope`, `counts`, `buckets`, `bridge_aggregate`, `reason_codes`.

Valid input yields `report_status=VALID_ASSERTION_AGGREGATE`, `counts` with
`input_files_asserted`/`input_bytes_asserted`, all nine buckets with
`count_asserted`, `bytes_asserted`, and `label_is_assertion=True` (including
`FULLY_VERIFIED`), and a separate `bridge_aggregate` section. An absent
optional bridge yields status `NOT_PROVIDED` with explicit `UNKNOWN` counts,
never an invented zero.

Failure yields `report_status=FAIL_CLOSED`, `counts`/`buckets` =
`NOT_PROVIDED`, `bridge_aggregate` = `NOT_EVALUATED`, and sanitized
`reason_codes`. Every outcome carries `evidence_status=
UNVALIDATED_ASSERTIONS_ONLY`, `private_data_authorization=NONE`,
`disposition=HOLD`, all three actions `NONE`, and `external_completeness`,
`independent_proof`, `freshness` = `UNKNOWN`.

## Privacy contract and limitations

The reporting aggregate is not an extractor. No path, ID, root identity, raw
row, identity, or untrusted string is echoed; all output strings are fixed
constants or sanitized codes. No denominator, percentage, actual-migration
coverage claim, approved+staged subset sum, or planner+bridge sum is produced.
A valid report still does not establish external inventory completeness,
independent proof, data integrity, or freshness, and authorizes no promotion,
eject, cutover, copy, deletion, or other migration action.

## Validation

Run `python -m unittest test_report` from this directory. The suite uses only
synthetic JSON-compatible fixtures and test-only hostile-object probes; it
covers all nine buckets including zero counts, arithmetic mismatch/overflow,
false or missing flags, constant mismatches, raw/extra field rejection,
bridge subset/range/type/privacy cases, absent aggregate, repeatability,
input immutability, no-I/O module surface, hostile-object guard, and sole
public API scope.
