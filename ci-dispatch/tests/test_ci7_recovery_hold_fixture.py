"""Source-only CI7 incident decision negatives, no host/provider interactions."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

src = Path(__file__).resolve().parents[1] / "ci7_recovery_hold_fixture.py"
spec = importlib.util.spec_from_file_location("ci7_hold", src)
assert spec and spec.loader
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


def sample():
    return {
        "marker": f.MARKER, "schema": 1, "mode": "SYNTHETIC_SOURCE_ONLY",
        "local": {"unique_ci7_vm": True, "vm_off": True, "owned_tuple_exact": True,
                  "state_phase_running": True, "last_evidence_cleanup_failed": True},
        "provider": {"run_id": f.INCIDENT_RUN_ID, "job_id": f.INCIDENT_JOB_ID, "attempt": 1,
                     "original_head": f.ORIGINAL_PR_HEAD, "run_status": "completed",
                     "run_conclusion": "cancelled", "job_status": "completed", "job_conclusion": "cancelled"},
        "runner": {"recorded_positive_id": True, "matching_repository_runners": 0,
                   "inventory_scope": "REPOSITORY_EXACT_NAME_FILTER", "pagination_complete": True,
                   "original_registration_repository_scoped": True},
        "locks": {"global_lock_artifact_regular": True, "run_lock_artifact_regular": True,
                  "exclusive_current_lock_owner_proven": False},
        "release": {"accepted_manifest_hash_exact": True, "active_generation_attested": False,
                    "protected_root_acl_trusted": False},
        "approval": {"exact_local_operation_security_reviewed": False,
                     "owner_approved_this_exact_transaction": False},
    }


def full_hypothesis():
    v=sample()
    v["runner"].update(inventory_scope="REPOSITORY_EXACT_NAME_FILTER",pagination_complete=True,original_registration_repository_scoped=True)
    v["locks"]["exclusive_current_lock_owner_proven"]=True
    v["release"].update(active_generation_attested=True, protected_root_acl_trusted=True)
    v["approval"].update(exact_local_operation_security_reviewed=True,
                         owner_approved_this_exact_transaction=True)
    return v


class RefusalTests(unittest.TestCase):
    def check(self, obj, expected):
        out = f.assess(obj)
        self.assertEqual(out["reason"], expected)
        self.assertEqual(out["classification"], "HOLD_NO_ACTION")
        self.assertEqual(out["input_provenance"], "SYNTHETIC_NOT_ATTESTED")
        for key in ("owner_approved_cleanup_authorized", "controller_release_authorized",
                    "provider_cancel_authorized", "runner_deregister_authorized",
                    "local_guest_remove_authorized", "jit_dispatch_authorized", "mutations_performed"):
            self.assertIs(out[key], False)
        self.assertEqual(set(out), {"schema","marker","classification","reason","input_provenance",
                                    "owner_approved_cleanup_authorized","controller_release_authorized",
                                    "provider_cancel_authorized","runner_deregister_authorized",
                                    "local_guest_remove_authorized","jit_dispatch_authorized","mutations_performed"})
        return out

    def test_observed_incident_is_hold_for_unproven_exclusive_locks(self):
        # Live exact-name repository query returned total_count 0, but existence
        # of two normal lock files does not prove exclusive current handles.
        self.check(sample(),"HOLD_CONTROLLER_LOCK_AUTHORITY_UNVERIFIED")

    def test_historical_first_page_scan_not_full_registration_proof(self):
        s=sample()
        s["runner"].update(inventory_scope="PARTIAL_REPOSITORY",pagination_complete=False)
        self.check(s,"HOLD_RUNNER_REGISTRATION_NOT_EXHAUSTIVE")

    def test_exact_original_queued_job_preserved(self):
        for state in ("queued","in_progress","waiting","requested","pending"):
            s=sample()
            s["provider"].update(run_status=state,run_conclusion=None)
            self.check(s,"HOLD_PRESERVE_ACTIVE_PROVIDER_JOB")

    def test_current_job_queued_even_when_run_completed_is_hold(self):
        s=sample();s["provider"].update(job_status="queued",job_conclusion=None)
        self.check(s,"HOLD_PRESERVE_ACTIVE_PROVIDER_JOB")

    def test_job_success_or_failure_does_not_authorize_removal(self):
        for outcome in ("success","failure","timed_out", "action_required", None):
            s=sample();s["provider"]["job_conclusion"]=outcome
            self.check(s,"HOLD_PROVIDER_TERMINAL_NOT_PROVEN")

    def test_forged_provider_identity_holds(self):
        for key,bad in (("run_id",42),("job_id",0),("attempt",2),("original_head","0"*40)):
            s=sample();s["provider"][key]=bad
            self.check(s,"HOLD_PROVIDER_IDENTITY_MISMATCH")

    def test_invalid_schema_and_extra_private_fields_rejected(self):
        for changes in ({"schema":True},{"marker":"imposter"},{"mode":"LIVE_RECONCILIATION"},
                        {"private_token":"DO_NOT_OUTPUT"}):
            s=sample();s.update(changes)
            self.check(s,"HOLD_INPUT_UNTRUSTED")
        self.check(None,"HOLD_INPUT_UNTRUSTED")
        self.check([],"HOLD_INPUT_UNTRUSTED")

    def test_bool_smuggling_and_unknown_enums_holds(self):
        items=[("local","vm_off",1),("runner","matching_repository_runners",False),
               ("runner","matching_repository_runners",99),("runner","pagination_complete",1),
               ("runner","inventory_scope","ORGANIZATION"),("locks","exclusive_current_lock_owner_proven",1),
               ("release","accepted_manifest_hash_exact",None),("approval","owner_approved_this_exact_transaction",1),
               ("provider","run_id",True),("provider","job_conclusion",False)]
        for group,key,bad in items:
            with self.subTest(group=group,key=key):
                s=sample();s[group][key]=bad
                self.check(s,"HOLD_INPUT_UNTRUSTED")

    def test_local_path_media_notes_or_count_mismatch_holds(self):
        for key in sample()["local"]:
            s=sample();s["local"][key]=False
            self.check(s,"HOLD_LOCAL_TUPLE_NOT_PROVEN")

    def test_missing_or_nonexhaustive_runner_inventory_cannot_prove_absence(self):
        for key,bad in (("recorded_positive_id",False),("pagination_complete",False),
                        ("inventory_scope","PARTIAL_REPOSITORY"),("original_registration_repository_scoped",False)):
            s=full_hypothesis();s["runner"][key]=bad
            self.check(s,"HOLD_RUNNER_REGISTRATION_NOT_EXHAUSTIVE")

    def test_matching_registered_runner_does_not_authorize_deletion(self):
        s=full_hypothesis();s["runner"]["matching_repository_runners"]=1
        self.check(s,"HOLD_RUNNER_REGISTRATION_PRESENT")

    def test_lock_files_do_not_prove_exclusive_control(self):
        for key in sample()["locks"]:
            s=full_hypothesis();s["locks"][key]=False
            self.check(s,"HOLD_CONTROLLER_LOCK_AUTHORITY_UNVERIFIED")

    def test_manifest_hash_does_not_attest_active_generation_or_parent(self):
        for key,reason in (("accepted_manifest_hash_exact","HOLD_RELEASE_MANIFEST_NOT_PROVEN"),
                           ("active_generation_attested","HOLD_ACTIVE_GENERATION_UNATTESTED"),
                           ("protected_root_acl_trusted","HOLD_PARENT_ACL_NOT_TRUSTED")):
            s=full_hypothesis();s["release"][key]=False
            self.check(s,reason)

    def test_unreviewed_or_unapproved_operation_refused(self):
        for key in sample()["approval"]:
            s=full_hypothesis();s["approval"][key]=False
            self.check(s,"HOLD_OPERATION_AUTHORITY_NOT_ACCEPTED")

    def test_all_claims_positive_still_never_authorize_execution(self):
        self.check(full_hypothesis(),"HOLD_SEPARATE_PHYSICAL_TRANSACTION_REQUIRED")

    def test_replay_idempotency_and_no_secret_reflection(self):
        s=sample();first=f.assess(s);s2=copy.deepcopy(s)
        self.assertEqual(first,f.assess(s2))
        bad=copy.deepcopy(s);bad["runner"]["password"]="SHOULD_NOT_LEAK"
        self.assertNotIn("SHOULD_NOT_LEAK",str(f.assess(bad)))
        self.check(bad,"HOLD_INPUT_UNTRUSTED")


if __name__ == "__main__":
    unittest.main()
