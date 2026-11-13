"""Fail-closed offline tests; synthetic-only inputs; never read physical device state."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

SRC = Path(__file__).resolve().parents[1] / "redrix_host_guest_evidence.py"
spec = importlib.util.spec_from_file_location("redrix_evidence", SRC)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

START = datetime(2026,11,13,18,0,0,tzinfo=timezone.utc)
def stamp(n):
    return (START+timedelta(seconds=n)).isoformat(timespec="milliseconds").replace("+00:00","Z")

def host(start=0):
    samples=[{"observed_at_utc":stamp(start+i), "host_total_mib":32768, "host_available_mib":17500-i} for i in range(5)]
    return {"schema":1,"marker":m.HOST_MARKER,"mode":"OBSERVE_ONLY", "source":"CHROME_SYSTEM_MEMORY_API",
        "memory_sample_scope":"CHROMEOS_BROWSER_HOST_PHYSICAL","capture_clock_source":"BROWSER_WALLCLOCK_UNATTESTED",
        "capture_started_utc":stamp(start),"capture_finished_utc":stamp(start+4),"capture_elapsed_ms":4000,
        "sample_count":5,"host_min_available_mib":17496,"samples":samples,"classification":"HOST_REPORTED_NOT_ATTESTED",
        "crostini_guest_corroboration":"NOT_COLLECTED_BY_THIS_EXTENSION", "nested_guest_peak":"UNMEASURED",
        "ci_dispatch_authorized":False,"jit_admission_authorized":False,"memory_policy_change_authorized":False}

def guest(start=1, min_ram=7932):
    passed=min_ram>=10240
    return {"schema":1,"marker":m.GUEST_MARKER,"mode":"OBSERVE_ONLY",
        "classification":"MEASURED_NOT_AUTHORIZED","capture_clock_source":"PENGUIN_UTC_WALLCLOCK_UNATTESTED",
        "memory_sample_scope":"CROSTINI_GUEST_VISIBLE_ONLY","chromeos_host_corroboration":"UNVERIFIED",
        "ci_dispatch_authorized":False,"jit_admission_authorized":False,"candidate_is_policy":False,
        "sample_count":3,"capture_started_utc":stamp(start),"capture_finished_utc":stamp(start+2),"capture_elapsed_ms":2000,
        "accepted_profile":{"guest_mib":2048,"reserve_mib":8192,"floor_mib":10240},
        "minimum_memavailable_mib":min_ram,"accepted_memory_floor_met_all_samples":passed,
        "guest_idle_memory_floor_disposition":("GUEST_FLOOR_OBSERVED_NOT_AUTHORIZED" if passed else "GUEST_FLOOR_BELOW_POLICY_NOT_HOST_EXHAUSTION")}

class Correlation(unittest.TestCase):
    def test_positive_overlap_still_never_authorized(self):
        out=m.correlate(host(),guest())
        self.assertEqual(out["classification"],"WALLCLOCK_OVERLAP_OBSERVED_NOT_ATTESTED")
        self.assertEqual(out["observed_wallclock_window_overlap_ms"],2000)
        self.assertFalse(out["accepted_guest_idle_floor_met"])
        self.assertEqual(out["host_reported_min_available_mib"],17496)
        self.assertEqual(out["guest_reported_min_available_mib"],7932)
        self.assertEqual(out["host_guest_causal_memory_attribution"],"NOT_ESTABLISHED")
        self.assertEqual(out["cross_device_clock_attestation"],"UNVERIFIED")
        for key in ("ci_dispatch_authorized","jit_admission_authorized","memory_policy_change_authorized"):
            self.assertIs(out[key],False)
    def test_no_overlap_is_hold(self):
        for shift in [-20,5,10]:
            out=m.correlate(host(),guest(start=shift))
            self.assertEqual(out["reason"],"NO_SUFFICIENT_WALLCLOCK_OVERLAP")
            self.assertEqual(out["classification"],"HOLD")
    def test_above_guest_floor_is_observation_only(self):
        out=m.correlate(host(),guest(min_ram=11000))
        self.assertTrue(out["accepted_guest_idle_floor_met"])
        self.assertFalse(out["jit_admission_authorized"])
    def test_host_schema_and_claim_tampering_rejected(self):
        for k,v in [("marker","FORGED"),("source","FORGED"),("classification","APPROVED"),
            ("memory_sample_scope","GUEST"),("capture_clock_source","ATTESTED"),
            ("ci_dispatch_authorized",True),("jit_admission_authorized",1),
            ("memory_policy_change_authorized",True),("nested_guest_peak",12345),
            ("host_min_available_mib",18000),("sample_count",4)]:
            with self.subTest(k=k):
                x=host();x[k]=v
                self.assertEqual(m.correlate(x,guest())["classification"],"HOLD")
    def test_guest_profile_and_claim_tampering_rejected(self):
        cases=[("marker","FORGED"),("classification","PASS"),("capture_clock_source","TRUSTED"),
           ("memory_sample_scope","CHROMEOS_BROWSER_HOST_PHYSICAL"),
           ("ci_dispatch_authorized",True),("jit_admission_authorized",1),
           ("candidate_is_policy",True),("sample_count",100),("accepted_memory_floor_met_all_samples",True)]
        for k,v in cases:
            with self.subTest(k=k):
                g=guest();g[k]=v
                self.assertEqual(m.correlate(host(),g)["classification"],"HOLD")
        for k in ("guest_mib","reserve_mib","floor_mib"):
            g=guest();g["accepted_profile"][k]=100
            self.assertEqual(m.correlate(host(),g)["reason"],"PRODUCTION_PROFILE_MISMATCH")
    def test_host_sample_clock_order_miB_bounds_and_gap(self):
        cases=[lambda h:h["samples"][3].update(observed_at_utc=stamp(0)),
               lambda h:h["samples"][1].update(host_total_mib=100),
               lambda h:h["samples"][1].update(host_available_mib=True),
               lambda h:h["samples"][1].update(host_available_mib=40000),
               lambda h:h["samples"][1].update(host_available_mib=-3),
               lambda h:h["samples"].pop(),
               lambda h:h.update(capture_elapsed_ms=0),
               lambda h:h.update(capture_finished_utc=stamp(999)),
               lambda h:h.update(capture_started_utc=stamp(9)),
               lambda h:h["samples"][1].update(observed_at_utc=stamp(20))]
        for mutation in cases:
            h=host();mutation(h)
            self.assertEqual(m.correlate(h,guest())["classification"],"HOLD")
    def test_host_clock_stall_is_not_correlated(self):
        h=host();h["capture_elapsed_ms"]=0
        h["capture_finished_utc"]=h["capture_started_utc"]
        for s in h["samples"]:s["observed_at_utc"]=h["capture_started_utc"]
        self.assertEqual(m.correlate(h,guest())["classification"],"HOLD")
    def test_guest_microsecond_timestamp_roundtrip_tolerates_at_most_one_ms(self):
        # Accepted guest producer truncates both ISO UTC endpoints to milliseconds,
        # then emits int(elapsed_total_microseconds / 1000). Quantization may cause
        # a one-millisecond difference even when both underlying clocks are valid.
        g=guest()
        g["capture_elapsed_ms"]=1999
        out=m.correlate(host(),g)
        self.assertEqual(out["classification"],"WALLCLOCK_OVERLAP_OBSERVED_NOT_ATTESTED")
        self.assertFalse(out["jit_admission_authorized"])
        g["capture_elapsed_ms"]=1998
        self.assertEqual(m.correlate(host(),g)["reason"],"CAPTURE_ELAPSED_MISMATCH")
        h=host()
        h["capture_elapsed_ms"]=3999
        self.assertEqual(m.correlate(h,guest())["reason"],"CAPTURE_ELAPSED_MISMATCH")

    def test_boolean_schema_and_summary_forgery_are_rejected(self):
        for who in ("host","guest"):
            a,b=host(),guest()
            if who=="host":a["schema"]=True
            else:b["schema"]=True
            self.assertEqual(m.correlate(a,b)["classification"],"HOLD")
        h=host()
        for row in h["samples"]:row["host_available_mib"]=1
        h["host_min_available_mib"]=True
        self.assertEqual(m.correlate(h,guest())["reason"],"HOST_SUMMARY_MISMATCH")

    def test_inputs_never_echo_arbitrary_payload_or_secrets(self):
        h=host();h["password"]="SHOULD_NOT_LEAK_FROM_HOST"
        g=guest();g["private_address"]="SHOULD_NOT_LEAK_FROM_GUEST"
        out=json.dumps(m.correlate(h,g))
        self.assertNotIn("SHOULD_NOT_LEAK",out)
        self.assertNotIn("password",out)
        self.assertNotIn("private_address",out)
    def test_bounded_json_reader_duplicate_fields_and_nonfinite_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"sample.json"
            for text in ['{"a":1,"a":2}', '{"value":NaN}', '{"value":Infinity}',
                         '{"value":1e4000}', '{"value":1e999999}', 'x'*40000, '{}']:
                path.write_text(text)
                if text == '{}': self.assertEqual(m._read_json(path),{})
                else:self.assertRaises(m.EvidenceError,m._read_json,path)
            for hostile_json in ('['*128 + '0' + ']'*128,
                                 '{"k":' + '9'*5000 + '}'):
                path.write_text(hostile_json)
                self.assertRaises(m.EvidenceError, m._read_json, path)
            path.write_text('{"brackets_inside_string":"' + '['*200 + '"}')
            self.assertEqual(m._read_json(path)["brackets_inside_string"], '['*200)
            path.write_text('{"value":0.125}')
            self.assertEqual(m._read_json(path)["value"],0.125)
            path.write_text(json.dumps(host()))
            self.assertEqual(m._read_json(path)["marker"],m.HOST_MARKER)
            link=Path(tmp)/"symlink.json"
            try:link.symlink_to(path)
            except OSError:pass
            else:self.assertRaises(m.EvidenceError,m._read_json,link)
    def test_cli_reports_only_sanitized_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Path(tmp)/"host.json";g=Path(tmp)/"guest.json"
            h.write_text(json.dumps(host()));g.write_text(json.dumps(guest()))
            from contextlib import redirect_stdout
            from io import StringIO
            buf=StringIO()
            with redirect_stdout(buf):
                self.assertEqual(m.main(["--host",str(h),"--guest",str(g)]),0)
            out=json.loads(buf.getvalue())
            self.assertEqual(out["classification"],"WALLCLOCK_OVERLAP_OBSERVED_NOT_ATTESTED")
            g.write_text('{"password":"SUPER_SECRET"}')
            buf=StringIO()
            with redirect_stdout(buf):
                self.assertEqual(m.main(["--host",str(h),"--guest",str(g)]),1)
            self.assertNotIn("SUPER_SECRET",buf.getvalue())

if __name__=="__main__":unittest.main()
