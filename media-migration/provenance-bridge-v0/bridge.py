"""Inert synthetic metadata classifier. No I/O, trust acquisition, or promotion.

All inputs are untrusted assertions. A matched binding is a shape-consistent
claim only, not independent provenance or proof of data integrity. v0 refuses
hybrids and non-ASCII/ambiguous Windows paths rather than pretending to resolve
filesystem aliases. Not approved for private or production data.

INPUT CONTRACT: JSON-compatible values only (dict/list/str/int/bool/None).
No arbitrary user-defined objects, custom __hash__/__eq__, callables, or other
Python-specific values are accepted or relied upon. Field names are bounded
strings; scalar values are bounded by the regexes/limits below. Every value
comparison, hash, string operation and container access is preceded by an exact
type/length guard (``type(x) is T``, never ``isinstance``), so a hostile object's
hooks can never be invoked. Malformed input is always fail-closed.

`observed_at` is syntax/calendar-validated only. It is never a freshness,
recency, clock, or proof signal. MATCHED_METADATA_ASSERTION_ONLY means the
caller-supplied metadata shape matched, not that the metadata is current or
independently proven. A stale well-formed date never confers freshness.
"""
import re
from collections import Counter, defaultdict
from datetime import datetime

TOKEN = re.compile(r'[A-Za-z0-9_-]{1,80}', re.ASCII)
COMPONENT = re.compile(r'[A-Za-z0-9_(). -]{1,255}', re.ASCII)
RESERVED = re.compile(r'(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?', re.I | re.ASCII)
MAX_ROWS = 10000
MAX_SIZE = 2**63 - 1
MAX_FIELD_NAME = 80
MAX_TIER_LEN = 64
BINDING_FIELDS = frozenset({'internal_id', 'kind', 'full_id'})
MEMBER_FIELDS = frozenset({'internal_id','kind','full_id','volume','root','path','index','size','pad','completion','validation','observed_at'})
STAGED_FIELDS = frozenset({'volume','root','path','size','tier','internal_id','kind','full_id','index'})

def token(value):
    return type(value) is str and TOKEN.fullmatch(value) is not None

def digest(value, n):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{%d}' % n, value) is not None

def identity(record):
    """Exact-string kind guard before any comparison; return None fail-closed."""
    if type(record) is not dict:
        return None
    kind = record.get('kind')
    if type(kind) is not str or len(kind) != 2:
        return None
    if kind == 'v1' and digest(record.get('full_id'), 40):
        return kind, record['full_id']
    if kind == 'v2' and digest(record.get('full_id'), 64):
        return kind, record['full_id']
    return None

def size(value):
    return type(value) is int and 0 <= value <= MAX_SIZE

def exact_fields(record, expected):
    """Exact dict shape: count guard first, then bounded string keys, then set().

    Only JSON-compatible inputs are in contract. An oversized mapping is
    rejected by len() before any key traversal/allocation; a non-string or
    over-long key is rejected before set() is constructed. No custom hash or
    equality hook can run on any field name.
    """
    if type(record) is not dict or len(record) != len(expected):
        return False
    for name in record:
        if type(name) is not str or len(name) > MAX_FIELD_NAME:
            return False
    return set(record) == expected

def stamp(value):
    """Syntax/calendar only; no freshness, clock, recency, or proof inference."""
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value, re.ASCII):
        return False
    try:
        datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
        return True
    except ValueError:
        return False

def key(record):
    """All container/string accesses below are on exact built-in types only."""
    if type(record) is not dict:
        return None
    volume, root, path = (record.get(x) for x in ('volume', 'root', 'path'))
    if not token(volume) or not token(root) or type(path) is not str or not 0 < len(path) <= 1024:
        return None
    parts = path.replace('\\', '/').split('/')
    if any(not COMPONENT.fullmatch(p) or p in ('.', '..') or p[0] == ' ' or p[-1] in ' .' or RESERVED.fullmatch(p) or RESERVED.fullmatch(p.split('.')[0].rstrip(' ')) for p in parts):
        return None
    return volume.lower(), root.lower(), '/'.join(p.lower() for p in parts)

def classify(bindings, members, staged):
    """Separate binding/member/staged assertions; returns one HOLD per staged row.

    No prefix matching, implicit v2 truncation, hybrid support, disk access, or
    proof promotion. Strictly bounded fixture input of JSON-compatible values.
    Every compared scalar is type/length-guarded before comparison, so no
    user-defined equality/hash/str hook can influence a shape-only match.
    Globally reject malformed bindings/member records so incomplete input never
    produces a positive claim. A malformed staged *shape* also globally HOLDs,
    so a malformed neighbor is never silently discarded from duplicate/root/index
    accounting while its neighbor is marked matched. Well-formed rows retain
    their exact individual reason codes. `observed_at` is validated for
    syntax/calendar only; stale dates never add freshness or proof. Every row
    remains HOLD/PENDING/UNVALIDATED_ASSERTIONS_ONLY.
    """
    def result(reason, claim=False):
        return {'status': 'HOLD', 'reason': reason, 'metadata_claim': claim,
                'content_proof': 'PENDING', 'authority': 'UNVALIDATED_ASSERTIONS_ONLY'}
    if any(type(x) is not list or len(x) > MAX_ROWS for x in (bindings, members, staged)):
        raise ValueError('bounded lists required')
    def all_hold(reason):
        return [result(reason) for _ in staged]
    by_internal = {}
    by_full = {}
    for b in bindings:
        if not exact_fields(b, BINDING_FIELDS) or not token(b.get('internal_id')) or not identity(b):
            return all_hold('INVALID_BINDING')
        i, full = b['internal_id'], identity(b)
        if i in by_internal or full in by_full:
            return all_hold('DUPLICATE_OR_CONFLICTING_BINDING')
        by_internal[i], by_full[full] = full, i
    by_key = defaultdict(list)
    member_indexes = set()
    root_volumes = defaultdict(set)
    for m in members:
        if not exact_fields(m, MEMBER_FIELDS) or not token(m.get('internal_id')) or not identity(m) or not key(m) or not size(m.get('index')) or not size(m.get('size')) or type(m.get('pad')) is not bool or not stamp(m.get('observed_at')):
            return all_hold('INVALID_MEMBER')
        if type(m['completion']) is not str or m['completion'] not in ('complete','incomplete','unknown') or type(m['validation']) is not str or m['validation'] not in ('verified','seed','no_verify','unknown'):
            return all_hold('INVALID_MEMBER_STATE')
        if by_internal.get(m['internal_id']) != identity(m):
            return all_hold('MEMBER_BINDING_CONFLICT')
        idx = (m['internal_id'], m['index'])
        if idx in member_indexes:
            return all_hold('DUPLICATE_MEMBER_INDEX')
        member_indexes.add(idx)
        k = key(m)
        root_volumes[k[1]].add(k[0])
        by_key[k].append(m)
    def staged_shape(s):
        if not exact_fields(s, STAGED_FIELDS):
            return None
        if not token(s.get('internal_id')) or not size(s.get('index')) or not size(s.get('size')):
            return None
        # Exact type/bound guards before the later tier comparison and before
        # identity() compares kind; no host object hook can be reached.
        if type(s.get('kind')) is not str or type(s.get('full_id')) is not str:
            return None
        if type(s.get('tier')) is not str or len(s.get('tier')) > MAX_TIER_LEN:
            return None
        return key(s)
    staged_keys = [staged_shape(s) for s in staged]
    if any(k is None for k in staged_keys):
        return all_hold('INVALID_STAGED')
    for k in staged_keys:
        root_volumes[k[1]].add(k[0])
    counts = Counter(staged_keys)
    staged_indexes = Counter((s['internal_id'], s['index']) for s in staged)
    output = []
    for s, k in zip(staged, staged_keys):
        reason = None
        if not identity(s):
            reason = 'FULL_ID_REQUIRED'
        elif s['tier'] != 'COPIED_PENDING_VERIFICATION':
            reason = 'UNSUPPORTED_TIER'
        elif len(root_volumes[k[1]]) != 1:
            reason = 'ROOT_VOLUME_CONFLICT'
        elif counts[k] != 1 or len(by_key[k]) > 1 or staged_indexes[(s['internal_id'], s['index'])] != 1:
            reason = 'AMBIGUOUS_CANONICAL_KEY'
        elif by_internal.get(s['internal_id']) != identity(s):
            reason = 'NO_EXACT_BINDING'
        elif not by_key[k]:
            reason = 'NO_MEMBER'
        else:
            m = by_key[k][0]
            if m['internal_id'] != s['internal_id'] or identity(m) != identity(s) or m['index'] != s['index']:
                reason = 'MEMBER_ID_CONFLICT'
            elif m['size'] != s['size']:
                reason = 'SIZE_CONFLICT'
            elif m['pad']:
                reason = 'PAD_MEMBER'
            elif m['completion'] != 'complete':
                reason = 'COMPLETION_NOT_ESTABLISHED'
            elif m['validation'] != 'verified':
                reason = 'UNTRUSTED_VALIDATION_CLAIM'
        output.append(result(reason or 'MATCHED_METADATA_ASSERTION_ONLY', reason is None))
    return output
