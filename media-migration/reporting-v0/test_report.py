"""Synthetic regression suite for the Unified Storage Migration Report v0.

All inputs are JSON-compatible synthetic aggregates. Hostile objects are
test-only probes that record any custom hook invocation; the public adapter
must never invoke them and must fail closed.
"""
import copy
import unittest

import report
from report import build_report

BUCKETS = (
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
MAX_INT64 = 2**63 - 1


def planner_fixture():
    counts = {name: 1 for name in BUCKETS}
    bytes_ = {name: 100 for name in BUCKETS}
    counts['COLLISION_ERROR'] = 0
    bytes_['COLLISION_ERROR'] = 0
    return {
        'schema': 'media-coverage-planner-v0',
        'evidence_status': 'UNVALIDATED_ASSERTIONS_ONLY',
        'private_data_authorization': 'NONE',
        'bucket_labels_are_assertions': True,
        'reconciled': True,
        'reconciled_scope': 'internal_partition_only_not_external_completeness',
        'root_reconciled': True,
        'overflow_refused': False,
        'duplicate_approved_root_count': 0,
        'root_identity_ambiguous_count': 0,
        'fail_closed': False,
        'orphan_proof_count': 0,
        'input_files': sum(counts.values()),
        'input_bytes': sum(bytes_.values()),
        'buckets': {
            name: {'count': counts[name], 'bytes': bytes_[name]}
            for name in BUCKETS
        },
    }


def bridge_fixture():
    return {
        'schema': 'media-provenance-bridge-v0-aggregate',
        'total_rows': 20,
        'metadata_shape_match_count': 5,
    }


class Hostile:
    hits = []

    def __eq__(self, other):
        Hostile.hits.append('eq')
        return True

    def __ne__(self, other):
        Hostile.hits.append('ne')
        return False

    def __hash__(self):
        Hostile.hits.append('hash')
        return 1

    def __str__(self):
        Hostile.hits.append('str')
        return 'hostile'

    def __repr__(self):
        Hostile.hits.append('repr')
        return 'hostile'

    def __bool__(self):
        Hostile.hits.append('bool')
        return True

    def __int__(self):
        Hostile.hits.append('int')
        return 1


def values(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from values(k)
            yield from values(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from values(v)
    else:
        yield node


def keys(node):
    found = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                found.add(k)
            found |= keys(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            found |= keys(v)
    return found


class ReportTests(unittest.TestCase):
    def valid(self, bridge=False):
        return build_report(planner_fixture(),
                            bridge_fixture() if bridge else None)

    def assert_fail(self, result, code):
        self.assertEqual(result['report_status'], 'FAIL_CLOSED')
        self.assertIn(code, result['reason_codes'])

    # --- valid aggregate / fixed labels ---
    def test_all_nine_buckets_are_assertions(self):
        r = self.valid()
        self.assertEqual(r['report_status'], 'VALID_ASSERTION_AGGREGATE')
        self.assertEqual(set(r['buckets']), set(BUCKETS))
        for name in BUCKETS:
            self.assertIs(r['buckets'][name]['label_is_assertion'], True)
            self.assertIs(type(r['buckets'][name]['count_asserted']), int)
            self.assertIs(type(r['buckets'][name]['bytes_asserted']), int)

    def test_fully_verified_is_not_promotion(self):
        r = self.valid()
        fv = r['buckets']['FULLY_VERIFIED']
        self.assertIs(fv['label_is_assertion'], True)
        self.assertEqual(r['disposition'], 'HOLD')
        self.assertEqual(r['promotion_action'], 'NONE')
        self.assertEqual(r['eject_action'], 'NONE')
        self.assertEqual(r['cutover_action'], 'NONE')

    def test_fixed_evidence_and_privacy_labels(self):
        r = self.valid()
        self.assertEqual(r['schema'], 'unified-storage-migration-report-v0')
        self.assertEqual(r['evidence_status'], 'UNVALIDATED_ASSERTIONS_ONLY')
        self.assertEqual(r['private_data_authorization'], 'NONE')
        self.assertEqual(r['reason_codes'], [])

    def test_zero_counts_all_buckets(self):
        p = planner_fixture()
        for name in BUCKETS:
            p['buckets'][name]['count'] = 0
            p['buckets'][name]['bytes'] = 0
        p['input_files'] = 0
        p['input_bytes'] = 0
        r = build_report(p)
        self.assertEqual(r['report_status'], 'VALID_ASSERTION_AGGREGATE')
        self.assertEqual(len(r['buckets']), 9)
        for name in BUCKETS:
            self.assertEqual(r['buckets'][name]['count_asserted'], 0)
            self.assertEqual(r['buckets'][name]['bytes_asserted'], 0)
        self.assertEqual(r['counts'], {'input_files_asserted': 0,
                                       'input_bytes_asserted': 0})

    def test_counts_match_planner_input(self):
        r = self.valid()
        self.assertEqual(r['counts'], {'input_files_asserted': 8,
                                       'input_bytes_asserted': 800})

    def test_external_completeness_proof_freshness_unknown(self):
        r = self.valid()
        self.assertEqual(r['external_completeness'], 'UNKNOWN')
        self.assertEqual(r['independent_proof'], 'UNKNOWN')
        self.assertEqual(r['freshness'], 'UNKNOWN')
        self.assertEqual(r['reconciled_scope'],
                         'internal_partition_only_not_external_completeness')

    def test_no_derived_subset_totals(self):
        keyset = keys(self.valid())
        for banned in ('eligible', 'approved', 'staged', 'subset', 'denominator',
                       'percentage', 'percent', 'coverage'):
            self.assertNotIn(banned, '|'.join(sorted(keyset)))

    # --- arithmetic and flags ---
    def test_count_mismatch_fails_closed(self):
        p = planner_fixture()
        p['input_files'] += 1
        r = build_report(p)
        self.assert_fail(r, 'ARITHMETIC_MISMATCH')
        self.assertIn('FLAG_CONFLICT', r['reason_codes'])

    def test_bytes_mismatch_fails_closed(self):
        p = planner_fixture()
        p['input_bytes'] += 1
        self.assert_fail(build_report(p), 'ARITHMETIC_MISMATCH')

    def test_bucket_sum_overflow_fails_closed(self):
        p = planner_fixture()
        p['buckets']['FULLY_VERIFIED']['bytes'] = MAX_INT64
        p['buckets']['RAW_PENDING']['bytes'] = MAX_INT64
        p['input_bytes'] = MAX_INT64
        self.assert_fail(build_report(p), 'ARITHMETIC_OVERFLOW')

    def test_int64_range_rejected(self):
        p = planner_fixture()
        p['buckets']['FULLY_VERIFIED']['count'] = MAX_INT64 + 1
        self.assert_fail(build_report(p), 'FIELD_RANGE_INVALID')

    def test_missing_flag_rejected(self):
        p = planner_fixture()
        del p['fail_closed']
        self.assert_fail(build_report(p), 'FIELD_SET_MISMATCH')

    def test_false_assertion_flag_rejected(self):
        p = planner_fixture()
        p['bucket_labels_are_assertions'] = False
        self.assert_fail(build_report(p), 'CONTRACT_CONSTANT_MISMATCH')

    def test_overflow_refused_fails_closed(self):
        p = planner_fixture()
        p['overflow_refused'] = True
        r = build_report(p)
        self.assert_fail(r, 'OVERFLOW_REFUSED')
        self.assertIn('FLAG_CONFLICT', r['reason_codes'])

    def test_fail_closed_flag_conflict(self):
        p = planner_fixture()
        p['orphan_proof_count'] = 1
        self.assert_fail(build_report(p), 'FLAG_CONFLICT')

    def test_reconciled_flag_conflict(self):
        p = planner_fixture()
        p['reconciled'] = False
        self.assert_fail(build_report(p), 'FLAG_CONFLICT')

    def test_wrong_schema_rejected(self):
        p = planner_fixture()
        p['schema'] = 'other-planner-v9'
        self.assert_fail(build_report(p), 'SCHEMA_MISMATCH')

    def test_wrong_evidence_constant_rejected(self):
        p = planner_fixture()
        p['evidence_status'] = 'VERIFIED'
        self.assert_fail(build_report(p), 'CONTRACT_CONSTANT_MISMATCH')

    def test_wrong_private_authorization_rejected(self):
        p = planner_fixture()
        p['private_data_authorization'] = 'FULL'
        self.assert_fail(build_report(p), 'CONTRACT_CONSTANT_MISMATCH')

    def test_wrong_reconciled_scope_rejected(self):
        p = planner_fixture()
        p['reconciled_scope'] = 'external_completeness'
        self.assert_fail(build_report(p), 'CONTRACT_CONSTANT_MISMATCH')

    def test_failure_has_no_trusted_counts(self):
        p = planner_fixture()
        p['input_bytes'] += 1
        r = build_report(p)
        self.assertEqual(r['counts'], 'NOT_PROVIDED')
        self.assertEqual(r['buckets'], 'NOT_PROVIDED')
        self.assertEqual(r['bridge_aggregate'], 'NOT_EVALUATED')
        self.assertFalse(any(type(v) is int for v in values(r)))

    # --- raw / extra field rejection ---
    def test_entries_rejected(self):
        p = planner_fixture()
        p['entries'] = []
        r = build_report(p)
        self.assert_fail(r, 'RAW_DATA_REJECTED')
        self.assertIn('FIELD_SET_MISMATCH', r['reason_codes'])

    def test_root_summary_rejected(self):
        p = planner_fixture()
        p['root_summary'] = {}
        self.assert_fail(build_report(p), 'RAW_DATA_REJECTED')

    def test_raw_paths_and_ids_rejected(self):
        p = planner_fixture()
        p['source_key'] = 'vol\x1froot\x1fpath'
        p['destination_path'] = 'stage/file.bin'
        self.assert_fail(build_report(p), 'RAW_DATA_REJECTED')

    def test_observed_at_metadata_rejected(self):
        p = planner_fixture()
        p['observed_at'] = '2026-11-24T12:00:00Z'
        self.assert_fail(build_report(p), 'RAW_DATA_REJECTED')

    def test_extra_benign_key_rejected(self):
        p = planner_fixture()
        p['note'] = 'x'
        self.assert_fail(build_report(p), 'FIELD_SET_MISMATCH')

    def test_extra_bucket_rejected(self):
        p = planner_fixture()
        p['buckets']['APPROVED_SUBSET'] = {'count': 1, 'bytes': 100}
        self.assert_fail(build_report(p), 'BUCKET_SET_MISMATCH')

    def test_missing_bucket_rejected(self):
        p = planner_fixture()
        del p['buckets']['RAW_PENDING']
        self.assert_fail(build_report(p), 'BUCKET_SET_MISMATCH')

    def test_bucket_nested_extra_field_rejected(self):
        p = planner_fixture()
        p['buckets']['FULLY_VERIFIED']['note'] = 'x'
        self.assert_fail(build_report(p), 'BUCKET_FIELD_SET_MISMATCH')

    def test_bucket_raw_path_rejected(self):
        p = planner_fixture()
        p['buckets']['FULLY_VERIFIED']['destination_path'] = 'x.bin'
        r = build_report(p)
        self.assert_fail(r, 'RAW_DATA_REJECTED')
        self.assertIn('BUCKET_FIELD_SET_MISMATCH', r['reason_codes'])

    # --- optional bridge aggregate ---
    def test_bridge_valid_is_separate(self):
        r = self.valid(bridge=True)
        section = r['bridge_aggregate']
        self.assertEqual(r['report_status'], 'VALID_ASSERTION_AGGREGATE')
        self.assertEqual(section['total_rows_asserted'], 20)
        self.assertEqual(section['metadata_shape_match_count_asserted'], 5)
        self.assertEqual(section['all_status'], 'HOLD')
        self.assertEqual(section['all_content_proof'], 'PENDING')
        self.assertEqual(section['authority'], 'UNVALIDATED_ASSERTIONS_ONLY')
        self.assertIs(section['separate_from_planner'], True)
        self.assertEqual(section['positional_join'], 'NOT_PERFORMED')
        self.assertEqual(r['counts']['input_files_asserted'], 8)

    def test_bridge_missing_explicitly_unknown(self):
        r = self.valid()
        section = r['bridge_aggregate']
        self.assertEqual(section['status'], 'NOT_PROVIDED')
        self.assertEqual(section['total_rows_asserted'], 'UNKNOWN')
        self.assertEqual(section['metadata_shape_match_count_asserted'],
                         'UNKNOWN')

    def test_bridge_subset_mismatch_rejected(self):
        b = bridge_fixture()
        b['metadata_shape_match_count'] = 21
        self.assert_fail(build_report(planner_fixture(), b),
                         'BRIDGE_SUBSET_MISMATCH')

    def test_bridge_negative_total_rejected(self):
        b = bridge_fixture()
        b['total_rows'] = -1
        self.assert_fail(build_report(planner_fixture(), b),
                         'BRIDGE_FIELD_RANGE_INVALID')

    def test_bridge_raw_rows_rejected(self):
        b = bridge_fixture()
        b['rows'] = []
        self.assert_fail(build_report(planner_fixture(), b),
                         'BRIDGE_FIELD_SET_MISMATCH')

    def test_bridge_bool_count_rejected(self):
        b = bridge_fixture()
        b['total_rows'] = True
        self.assert_fail(build_report(planner_fixture(), b),
                         'BRIDGE_FIELD_TYPE_INVALID')

    def test_no_combined_totals_or_percentages(self):
        r = self.valid(bridge=True)
        self.assertNotIn('coverage', '|'.join(sorted(keys(r))))
        self.assertNotIn('combined', '|'.join(sorted(keys(r))))
        self.assertNotIn('percent', '|'.join(sorted(keys(r))))
        self.assertNotIn(28, list(values(r)))  # no 8 + 20 bridge sum

    # --- hostile objects / API scope / repeatability ---
    def test_hostile_objects_never_invoked(self):
        cases = []
        p0 = planner_fixture()
        cases.append(('planner', lambda: Hostile()))
        cases.append(('buckets', lambda: dict(p0, buckets=Hostile())))
        cases.append(('schema', lambda: dict(p0, schema=Hostile())))
        cases.append(('flag', lambda: dict(p0, reconciled=Hostile())))
        cases.append(('int', lambda: dict(p0, input_files=Hostile())))
        cases.append(('bucket_entry', lambda: dict(
            p0, buckets=dict(p0['buckets'],
                             FULLY_VERIFIED=Hostile()))))
        cases.append(('bucket_count', lambda: dict(
            p0, buckets=dict(
                p0['buckets'],
                FULLY_VERIFIED=dict(p0['buckets']['FULLY_VERIFIED'],
                                    count=Hostile())))))
        b0 = bridge_fixture()
        cases.append(('bridge', lambda: Hostile()))
        cases.append(('bridge_total', lambda: dict(b0, total_rows=Hostile())))
        hostile_key_planner = dict(p0)
        hostile_key_planner[Hostile()] = 1
        Hostile.hits.clear()
        cases.append(('hostile_key', lambda: hostile_key_planner))

        for name, make in cases:
            Hostile.hits.clear()
            if name.startswith('bridge'):
                result = build_report(planner_fixture(), make())
            else:
                result = build_report(make())
            self.assertEqual(Hostile.hits, [], 'hook invoked for ' + name)
            self.assertEqual(result['report_status'], 'FAIL_CLOSED', name)

    def test_sole_public_api(self):
        self.assertEqual(report.__all__, ['build_report'])
        defined = [(n, v) for n, v in vars(report).items()
                   if callable(v) and getattr(v, '__module__', None) == 'report']
        self.assertEqual([n for n, _ in defined if not n.startswith('_')],
                         ['build_report'])
        ns = {}
        exec('from report import *', ns)
        self.assertEqual([n for n in ns if not n.startswith('__')],
                         ['build_report'])

    def test_no_io_support_in_module(self):
        for name in ('open', 'os', 'io', 'json', 'pathlib', 'subprocess',
                     'socket', 'datetime', 'shutil'):
            self.assertNotIn(name, vars(report))

    def test_repeatable_and_input_unchanged(self):
        p = planner_fixture()
        b = bridge_fixture()
        p_before = copy.deepcopy(p)
        b_before = copy.deepcopy(b)
        first = build_report(p, b)
        second = build_report(p, b)
        self.assertEqual(first, second)
        self.assertEqual(p, p_before)
        self.assertEqual(b, b_before)


if __name__ == '__main__':
    unittest.main()
