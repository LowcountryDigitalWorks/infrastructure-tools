"""Inert synthetic metadata classifier. No I/O, trust acquisition, or promotion.

All inputs are untrusted assertions. A matched binding is a shape-consistent
claim only, not independent provenance or proof of data integrity. v0 refuses
hybrids and non-ASCII/ambiguous Windows paths rather than pretending to resolve
filesystem aliases. Not approved for private or production data.
"""
import re
from collections import Counter, defaultdict
from datetime import datetime

TOKEN = re.compile(r'[A-Za-z0-9_-]{1,80}', re.ASCII)
COMPONENT = re.compile(r'[A-Za-z0-9_(). -]{1,255}', re.ASCII)
RESERVED = re.compile(r'(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?', re.I | re.ASCII)
MAX_ROWS = 10000
MAX_SIZE = 2**63 - 1

def token(value):
    return type(value) is str and TOKEN.fullmatch(value) is not None

def digest(value, n):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{%d}' % n, value) is not None

def identity(record):
    kind = record.get('kind')
    if kind == 'v1' and digest(record.get('full_id'), 40):
        return kind, record['full_id']
    if kind == 'v2' and digest(record.get('full_id'), 64):
        return kind, record['full_id']
    return None

def size(value):
    return type(value) is int and 0 <= value <= MAX_SIZE

def stamp(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value, re.ASCII):
        return False
    try:
        datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
        return True
    except ValueError:
        return False

def key(record):
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
    proof promotion. Strictly bounded fixture input. Globally reject malformed
    bindings/member records so incomplete input never produces a positive claim.
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
        if type(b) is not dict or set(b) != {'internal_id', 'kind', 'full_id'} or not token(b.get('internal_id')) or not identity(b):
            return all_hold('INVALID_BINDING')
        i, full = b['internal_id'], identity(b)
        if i in by_internal or full in by_full:
            return all_hold('DUPLICATE_OR_CONFLICTING_BINDING')
        by_internal[i], by_full[full] = full, i
    by_key = defaultdict(list)
    member_indexes = set()
    root_volumes = defaultdict(set)
    fields = {'internal_id','kind','full_id','volume','root','path','index','size','pad','completion','validation','observed_at'}
    for m in members:
        if type(m) is not dict or set(m) != fields or not token(m.get('internal_id')) or not identity(m) or not key(m) or not size(m.get('index')) or not size(m.get('size')) or type(m.get('pad')) is not bool or not stamp(m.get('observed_at')):
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
    staged_keys = [key(s) if type(s) is dict else None for s in staged]
    for k in staged_keys:
        if k is not None:
            root_volumes[k[1]].add(k[0])
    counts = Counter(staged_keys)
    staged_indexes = Counter((s['internal_id'], s['index']) for s in staged
                             if type(s) is dict and token(s.get('internal_id')) and size(s.get('index')))
    output = []
    allowed = {'volume','root','path','size','tier','internal_id','kind','full_id','index'}
    for s, k in zip(staged, staged_keys):
        reason = None
        if type(s) is not dict or set(s) != allowed or not k or not size(s.get('size')) or not size(s.get('index')) or not token(s.get('internal_id')):
            reason = 'INVALID_STAGED'
        elif not identity(s):
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
