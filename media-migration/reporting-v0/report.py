"""Unified Storage Migration Report v0 — inert aggregate adapter.

SOURCE ONLY / SYNTHETIC ONLY. This module performs no I/O, opens no files,
reads no paths or metadata, starts no process, consults no clock, and acquires
no trust. Its only entry point is ``build_report`` (the sole member of
``__all__``). Everything else, including underscore-prefixed names, is an
internal implementation detail and is UNSUPPORTED for direct calls. The
underscore prefix is a naming convention, NOT a security boundary; no claim is
made that private names themselves prevent direct access, or that arbitrary
arguments to direct helper calls are safe. All guarantees below apply ONLY to
data passed through ``build_report``'s exact field validation.

INPUT CONTRACT (via ``build_report``): JSON-compatible values only
(dict/list/str/int/bool/None). No arbitrary objects, custom hooks, callables,
or other Python-specific values are accepted or invoked. Every comparison,
hash, length, and container access is preceded by an exact built-in type guard.

The planner input is an AGGREGATE ENVELOPE only: fixed top-level fields plus
nine mutually exclusive asserted bucket count/byte pairs. ``entries``,
``root_summary``, paths, IDs, raw rows, and any extra key are rejected. The
optional bridge input is a separate aggregate only (total rows and
metadata-shape-match count); raw rows and positional joins are rejected. The
caller's sanitization and root completeness are never assumed or re-derived.

OUTPUT: a deterministic fixed-label assertion aggregate. Bucket labels are
assertions — including FULLY_VERIFIED — never promotion evidence. Evidence is
UNVALIDATED_ASSERTIONS_ONLY, private_data_authorization is NONE, disposition
is HOLD, and promotion/eject/cutover actions are NONE. No denominator,
percentage, actual-coverage claim, approved+staged subset sum, planner+bridge
sum, path, ID, or untrusted string is emitted. External completeness,
independent proof, and freshness are explicitly UNKNOWN. Invalid ranges,
overflow, arithmetic mismatches, and conflicting flags fail closed with
sanitized reason codes and no trusted counts.

A passing report is still only a claim about supplied synthetic aggregates.
It does not establish external inventory completeness, independent proof,
freshness, or authorization for any migration action.
"""

__all__ = ['build_report']

_REPORT_SCHEMA = 'unified-storage-migration-report-v0'
_PLANNER_SCHEMA = 'media-coverage-planner-v0'
_BRIDGE_SCHEMA = 'media-provenance-bridge-v0-aggregate'
_EVIDENCE = 'UNVALIDATED_ASSERTIONS_ONLY'
_NO_PRIVATE = 'NONE'
_SCOPE = 'internal_partition_only_not_external_completeness'
_HOLD = 'HOLD'
_PENDING = 'PENDING'
_UNKNOWN = 'UNKNOWN'
_NOT_PROVIDED = 'NOT_PROVIDED'

_BUCKETS = (
    'FULLY_VERIFIED',
    'LEGACY_MANIFEST_ONLY',
    'RAW_PENDING',
    'TRUSTED_NOT_COPIED',
    'STABLE_NON_TORRENT_CANDIDATE',
    'INCOMPLETE_TORRENT',
    'UNKNOWN_OR_AMBIGUOUS_TORRENT',
    'OTHER_EXCLUDED',
    'COLLISION_ERROR',
)
_BUCKET_KEYS = frozenset(('count', 'bytes'))
_PLANNER_KEYS = frozenset((
    'schema', 'evidence_status', 'private_data_authorization',
    'bucket_labels_are_assertions', 'reconciled', 'reconciled_scope',
    'root_reconciled', 'overflow_refused', 'duplicate_approved_root_count',
    'root_identity_ambiguous_count', 'fail_closed', 'orphan_proof_count',
    'input_files', 'input_bytes', 'buckets',
))
_BRIDGE_KEYS = frozenset((
    'schema', 'total_rows', 'metadata_shape_match_count',
))
_BOOL_FIELDS = (
    'bucket_labels_are_assertions', 'reconciled', 'root_reconciled',
    'overflow_refused', 'fail_closed',
)
_INT_FIELDS = (
    'duplicate_approved_root_count', 'root_identity_ambiguous_count',
    'orphan_proof_count', 'input_files', 'input_bytes',
)
_RAW_TOKENS = frozenset((
    'entries', 'root_summary', 'source_key', 'destination_path', 'path',
    'paths', 'internal_id', 'full_id', 'volume', 'root', 'rows', 'bindings',
    'members', 'staged', 'record', 'records', 'observed_at',
))
_MAX_INT64 = 2**63 - 1
_MAX_KEY_LEN = 80


def _keys(value, expected, set_code, reasons, raw_code='RAW_DATA_REJECTED'):
    """Exact key set and bounded string keys; never hashes an unguarded key."""
    if len(value) != len(expected):
        reasons.add(set_code)
    for key in value:
        if type(key) is not str or len(key) > _MAX_KEY_LEN:
            reasons.add('FIELD_TYPE_INVALID')
            return False
        if key in _RAW_TOKENS:
            reasons.add(raw_code)
    if set(value) != expected:
        reasons.add(set_code)
        return False
    return True


def _bounded_int(value, reasons, type_code='FIELD_TYPE_INVALID',
                 range_code='FIELD_RANGE_INVALID'):
    if type(value) is not int:
        reasons.add(type_code)
        return None
    if value < 0 or value > _MAX_INT64:
        reasons.add(range_code)
        return None
    return value


def _fixed_str(value, expected, reasons, code):
    if type(value) is not str or value != expected:
        reasons.add(code)


def _planner(value, reasons):
    if type(value) is not dict:
        reasons.add('FIELD_TYPE_INVALID')
        return None
    if not _keys(value, _PLANNER_KEYS, 'FIELD_SET_MISMATCH', reasons):
        return None

    _fixed_str(value['schema'], _PLANNER_SCHEMA, reasons, 'SCHEMA_MISMATCH')
    _fixed_str(value['evidence_status'], _EVIDENCE, reasons,
               'CONTRACT_CONSTANT_MISMATCH')
    _fixed_str(value['private_data_authorization'], _NO_PRIVATE, reasons,
               'CONTRACT_CONSTANT_MISMATCH')
    _fixed_str(value['reconciled_scope'], _SCOPE, reasons,
               'CONTRACT_CONSTANT_MISMATCH')
    # Bucket labels are assertions by contract, never promotion evidence.
    # An explicit True is required; False, non-bool, or hostile values fail.
    if value['bucket_labels_are_assertions'] is not True:
        reasons.add('CONTRACT_CONSTANT_MISMATCH')

    fields = {}
    for name in _BOOL_FIELDS:
        flag = value[name]
        if type(flag) is not bool:
            reasons.add('FIELD_TYPE_INVALID')
        else:
            fields[name] = flag
    for name in _INT_FIELDS:
        number = _bounded_int(value[name], reasons)
        if number is not None:
            fields[name] = number

    raw_buckets = value['buckets']
    if type(raw_buckets) is not dict:
        reasons.add('FIELD_TYPE_INVALID')
    elif not _keys(raw_buckets, frozenset(_BUCKETS),
                   'BUCKET_SET_MISMATCH', reasons,
                   raw_code='RAW_DATA_REJECTED'):
        pass
    else:
        parsed = {}
        for name in _BUCKETS:
            entry = raw_buckets[name]
            if type(entry) is not dict:
                reasons.add('FIELD_TYPE_INVALID')
                continue
            if not _keys(entry, _BUCKET_KEYS, 'BUCKET_FIELD_SET_MISMATCH',
                         reasons, raw_code='RAW_DATA_REJECTED'):
                continue
            count = _bounded_int(entry['count'], reasons)
            byte_count = _bounded_int(entry['bytes'], reasons)
            if count is not None and byte_count is not None:
                parsed[name] = (count, byte_count)
        fields['buckets'] = parsed

    required = set(_BOOL_FIELDS) | set(_INT_FIELDS) | {'buckets'}
    if not required.issubset(fields) or len(fields['buckets']) != len(_BUCKETS):
        return None
    return fields


def _bridge(value, reasons):
    if type(value) is not dict:
        reasons.add('BRIDGE_FIELD_TYPE_INVALID')
        return None
    if not _keys(value, _BRIDGE_KEYS, 'BRIDGE_FIELD_SET_MISMATCH', reasons):
        return None
    _fixed_str(value['schema'], _BRIDGE_SCHEMA, reasons,
               'BRIDGE_SCHEMA_MISMATCH')
    total = _bounded_int(value['total_rows'], reasons,
                         'BRIDGE_FIELD_TYPE_INVALID',
                         'BRIDGE_FIELD_RANGE_INVALID')
    matched = _bounded_int(value['metadata_shape_match_count'], reasons,
                           'BRIDGE_FIELD_TYPE_INVALID',
                           'BRIDGE_FIELD_RANGE_INVALID')
    if total is None or matched is None:
        return None
    return {'total_rows': total, 'metadata_shape_match_count': matched}


def _fail(reasons):
    return {
        'schema': _REPORT_SCHEMA,
        'report_status': 'FAIL_CLOSED',
        'evidence_status': _EVIDENCE,
        'private_data_authorization': _NO_PRIVATE,
        'disposition': _HOLD,
        'promotion_action': _NO_PRIVATE,
        'eject_action': _NO_PRIVATE,
        'cutover_action': _NO_PRIVATE,
        'external_completeness': _UNKNOWN,
        'independent_proof': _UNKNOWN,
        'freshness': _UNKNOWN,
        'reconciled_scope': _SCOPE,
        'counts': _NOT_PROVIDED,
        'buckets': _NOT_PROVIDED,
        'bridge_aggregate': 'NOT_EVALUATED',
        'reason_codes': sorted(reasons),
    }


def _bridge_section(aggregate):
    section = {
        'status': 'SEPARATE_ASSERTION_AGGREGATE',
        'total_rows_asserted': _NOT_PROVIDED,
        'metadata_shape_match_count_asserted': _NOT_PROVIDED,
        'all_status': _HOLD,
        'all_content_proof': _PENDING,
        'authority': _EVIDENCE,
        'separate_from_planner': True,
        'positional_join': 'NOT_PERFORMED',
    }
    if aggregate is not None:
        section['total_rows_asserted'] = aggregate['total_rows']
        section['metadata_shape_match_count_asserted'] = (
            aggregate['metadata_shape_match_count'])
    else:
        section['status'] = 'NOT_PROVIDED'
        section['total_rows_asserted'] = _UNKNOWN
        section['metadata_shape_match_count_asserted'] = _UNKNOWN
    return section


def _success(planner, bridge):
    buckets = {}
    for name in _BUCKETS:
        count, byte_count = planner['buckets'][name]
        buckets[name] = {
            'count_asserted': count,
            'bytes_asserted': byte_count,
            'label_is_assertion': True,
        }
    return {
        'schema': _REPORT_SCHEMA,
        'report_status': 'VALID_ASSERTION_AGGREGATE',
        'evidence_status': _EVIDENCE,
        'private_data_authorization': _NO_PRIVATE,
        'disposition': _HOLD,
        'promotion_action': _NO_PRIVATE,
        'eject_action': _NO_PRIVATE,
        'cutover_action': _NO_PRIVATE,
        'external_completeness': _UNKNOWN,
        'independent_proof': _UNKNOWN,
        'freshness': _UNKNOWN,
        'reconciled_scope': _SCOPE,
        'counts': {
            'input_files_asserted': planner['input_files'],
            'input_bytes_asserted': planner['input_bytes'],
        },
        'buckets': buckets,
        'bridge_aggregate': _bridge_section(bridge),
        'reason_codes': [],
    }


def build_report(planner, bridge=None):
    """Return a deterministic fixed-label assertion aggregate.

    ``planner`` is the allowlisted aggregate envelope described in the module
    docstring. ``bridge`` is optional and, when present, is an allowlisted
    aggregate. Both must be JSON-compatible values. Any invalid field, raw
    data, arithmetic conflict, overflow, or conflicting flag returns a
    fail-closed report with sanitized reason codes and no trusted counts.

    No input is mutated. No I/O or trust acquisition is performed. A valid
    result remains an assertion-shaped report, never an actual migration
    coverage measurement or a promotion/eject/cutover decision.
    """
    reasons = set()
    parsed_planner = _planner(planner, reasons)
    parsed_bridge = None
    if bridge is not None:
        parsed_bridge = _bridge(bridge, reasons)

    if parsed_planner is not None:
        count_sum = sum(parsed_planner['buckets'][name][0] for name in _BUCKETS)
        byte_sum = sum(parsed_planner['buckets'][name][1] for name in _BUCKETS)
        if count_sum > _MAX_INT64 or byte_sum > _MAX_INT64:
            reasons.add('ARITHMETIC_OVERFLOW')
        else:
            reconciles = (count_sum == parsed_planner['input_files'] and
                          byte_sum == parsed_planner['input_bytes'])
            if not reconciles:
                reasons.add('ARITHMETIC_MISMATCH')
            if parsed_planner['reconciled'] != reconciles:
                reasons.add('FLAG_CONFLICT')

        error_signal = (
            parsed_planner['overflow_refused'] or
            parsed_planner['orphan_proof_count'] > 0 or
            parsed_planner['duplicate_approved_root_count'] > 0 or
            parsed_planner['root_identity_ambiguous_count'] > 0 or
            parsed_planner['buckets']['COLLISION_ERROR'][0] > 0
        )
        if error_signal and not parsed_planner['fail_closed']:
            reasons.add('FLAG_CONFLICT')
        if parsed_planner['overflow_refused']:
            reasons.add('OVERFLOW_REFUSED')

    if parsed_bridge is not None:
        if (parsed_bridge['metadata_shape_match_count'] >
                parsed_bridge['total_rows']):
            reasons.add('BRIDGE_SUBSET_MISMATCH')

    if reasons:
        return _fail(reasons)
    return _success(parsed_planner, parsed_bridge)
