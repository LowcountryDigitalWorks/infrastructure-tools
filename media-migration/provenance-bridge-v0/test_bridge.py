import unittest
from bridge import classify

def fixture(n=0, kind='v1'):
    full = format(n+1, '0%dx' % (40 if kind=='v1' else 64))
    identity = dict(internal_id=f't{n}', kind=kind, full_id=full)
    common = dict(**identity, volume='vol1', root='root1', path=f'fixture/file{n}.bin', size=1024, index=0)
    return identity, dict(**common, pad=False, completion='complete', validation='verified', observed_at='2026-11-24T12:00:00Z'), dict(**common, tier='COPIED_PENDING_VERIFICATION')

class BridgeTests(unittest.TestCase):
    def check(self,b,m,s,reason):
        r=classify(b,m,s)
        self.assertEqual(len(r),len(s))
        self.assertTrue(all(x['status']=='HOLD' and x['content_proof']=='PENDING' and x['authority']=='UNVALIDATED_ASSERTIONS_ONLY' for x in r))
        self.assertTrue(all(x['reason']==reason for x in r),r)
    def test_v1_v2(self):
        for kind in ('v1','v2'):
            b,m,s=fixture(kind=kind); self.check([b],[m],[s],'MATCHED_METADATA_ASSERTION_ONLY')
    def test_unique_prefix(self):
        b,m,s=fixture(); s['full_id']=s['full_id'][:8]; self.check([b],[m],[s],'FULL_ID_REQUIRED')
    def test_shared_prefix_exact(self):
        b,m,s=fixture(); b2,m2,s2=fixture(1); self.assertEqual(b['full_id'][:8],b2['full_id'][:8]); self.check([b,b2],[m,m2],[s,s2],'MATCHED_METADATA_ASSERTION_ONLY')
    def test_truncated_v2(self):
        b,m,s=fixture(kind='v2'); s['full_id']=s['full_id'][:40]; self.check([b],[m],[s],'FULL_ID_REQUIRED')
    def test_hybrid(self):
        b,m,s=fixture(); b['kind']='hybrid'; self.check([b],[m],[s],'INVALID_BINDING')
    def test_duplicate_binding(self):
        b,m,s=fixture(); self.check([b,b],[m],[s],'DUPLICATE_OR_CONFLICTING_BINDING')
    def test_full_id_reuse(self):
        b,m,s=fixture(); self.check([b,dict(b,internal_id='other')],[m],[s],'DUPLICATE_OR_CONFLICTING_BINDING')
    def test_wrong_binding(self):
        b,m,s=fixture(); s['full_id']='f'*40; self.check([b],[m],[s],'NO_EXACT_BINDING')
    def test_no_binding(self):
        b,m,s=fixture(); self.check([],[],[s],'NO_EXACT_BINDING')
    def test_no_member(self):
        b,m,s=fixture(); self.check([b],[],[s],'NO_MEMBER')
    def test_index_conflict(self):
        b,m,s=fixture(); s['index']=1; self.check([b],[m],[s],'MEMBER_ID_CONFLICT')
    def test_duplicate_index(self):
        b,m,s=fixture(); self.check([b],[m,dict(m,path='other.bin')],[s],'DUPLICATE_MEMBER_INDEX')
    def test_member_binding_conflict(self):
        b,m,s=fixture(); self.check([b],[m,dict(m,index=1,path='other.bin',full_id='f'*40)],[s],'MEMBER_BINDING_CONFLICT')
    def test_duplicate_staged_index(self):
        b,m,s=fixture(); self.check([b],[m],[s,dict(s,path='other.bin')],'AMBIGUOUS_CANONICAL_KEY')
    def test_size_mismatch(self):
        b,m,s=fixture(); s['size']=1; self.check([b],[m],[s],'SIZE_CONFLICT')
    def test_pad(self):
        b,m,s=fixture(); m['pad']=True; self.check([b],[m],[s],'PAD_MEMBER')
    def test_bad_bool(self):
        b,m,s=fixture(); m['pad']='false'; self.check([b],[m],[s],'INVALID_MEMBER')
    def test_bad_size(self):
        b,m,s=fixture()
        for value in (True,-1,'1024',1.2,2**63):
            self.check([b],[m],[dict(s,size=value)],'INVALID_STAGED')
    def test_bad_paths(self):
        b,m,s=fixture()
        for path in ('a/../b','a/./b','/a','C:/a','a//b','a:stream','NUL.txt','COM1.txt','CON .txt','a.','a ','a~1.bin','é.bin','a\x00b'):
            self.check([b],[m],[dict(s,path=path)],'INVALID_STAGED')
    def test_duplicate_case_separator(self):
        b,m,s=fixture(); self.check([b],[m],[s,dict(s,path='FIXTURE\\FILE0.BIN')],'AMBIGUOUS_CANONICAL_KEY')
    def test_member_collision(self):
        b,m,s=fixture(); self.check([b],[m,dict(m,index=1,path='FIXTURE/FILE0.BIN')],[s],'AMBIGUOUS_CANONICAL_KEY')
    def test_root_conflict(self):
        b,m,s=fixture(); self.check([b],[dict(m,volume='vol2')],[s],'ROOT_VOLUME_CONFLICT')
    def test_untrusted_validation(self):
        b,m,s=fixture()
        for state in ('seed','no_verify','unknown'):
            self.check([b],[dict(m,validation=state)],[s],'UNTRUSTED_VALIDATION_CLAIM')
    def test_incomplete(self):
        b,m,s=fixture()
        for state in ('unknown','incomplete'):
            self.check([b],[dict(m,completion=state)],[s],'COMPLETION_NOT_ESTABLISHED')
    def test_bad_date(self):
        b,m,s=fixture(); self.check([b],[dict(m,observed_at='2026-02-30T12:00:00Z')],[s],'INVALID_MEMBER')
    def test_tier(self):
        b,m,s=fixture(); self.check([b],[m],[dict(s,tier='FULLY_VERIFIED')],'UNSUPPORTED_TIER')
    def test_multiple_files_per_torrent(self):
        b,m,s=fixture(); self.check([b],[m,dict(m,index=1,path='other.bin')],[s,dict(s,index=1,path='other.bin')],'MATCHED_METADATA_ASSERTION_ONLY')
    def test_497_scale(self):
        b,m,s=map(list,zip(*(fixture(n) for n in range(497)))); self.check(b,m,s,'MATCHED_METADATA_ASSERTION_ONLY')
    def test_output_privacy(self):
        b,m,s=fixture(); r=classify([b],[m],[s])[0]; self.assertNotIn(s['path'],str(r)); self.assertNotIn(s['full_id'],str(r))
    def test_bound(self):
        with self.assertRaises(ValueError): classify([None]*10001,[],[])

if __name__=='__main__': unittest.main()
