"""Gate D offline proof: source-only, no actual ChatGPT conversation dispatch."""
import unittest
from artifact_gate_d_v0 import (
    ArtifactIdentityError, MAX_ARTIFACT_BYTES, SCHEMA, VERIFIED_STATE,
    create_claim, verify_claim,
)

DATA = b"synthetic candidate: immutable local bytes\n"


class GateDArtifactTests(unittest.TestCase):
    def setUp(self):
        self.claim = create_claim(artifact_id="candidate_a01", author_role="builder01", content=DATA)

    def check(self, *, claim=None, content=DATA, author="builder01", reviewer="ir02"):
        return verify_claim(
            claim=self.claim if claim is None else claim,
            content=content,
            authenticated_author_role=author,
            authenticated_reviewer_role=reviewer,
        )

    def deny(self, code, **kwargs):
        with self.assertRaises(ArtifactIdentityError) as caught:
            self.check(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_snapshot_identity_only(self):
        out = self.check()
        self.assertEqual(out["state"], VERIFIED_STATE)
        self.assertEqual(out["chat_wake"], "NOT_PROVEN")
        self.assertEqual(out["review_verdict"], "PENDING_INDEPENDENT_REVIEW")
        self.assertEqual(out["schema"], SCHEMA)
        self.assertNotIn("IR_PASS", out.values())
        self.assertNotIn("content", out)

    def test_digest_tamper(self):
        self.deny("DIGEST_MISMATCH", content=DATA[:-1] + b"x")

    def test_size_tamper(self):
        self.deny("SIZE_MISMATCH", content=DATA + b"x")

    def test_self_review(self):
        self.deny("SELF_REVIEW_REFUSED", reviewer="builder01")

    def test_forged_author_role(self):
        self.deny("AUTHOR_MISMATCH", author="other01")

    def test_claim_added_verdict(self):
        self.deny("INVALID_CLAIM_SCHEMA", claim={**self.claim, "ir_pass": True})

    def test_claim_missing_field(self):
        bad = dict(self.claim)
        bad.pop("author_role")
        self.deny("INVALID_CLAIM_SCHEMA", claim=bad)

    def test_claim_wrong_schema(self):
        self.deny("INVALID_CLAIM_SCHEMA", claim={**self.claim, "schema": "v9"})

    def test_fake_hash_uppercase(self):
        self.deny("INVALID_CLAIM_DIGEST", claim={**self.claim, "sha256": self.claim["sha256"].upper()})

    def test_fake_hash_format(self):
        self.deny("INVALID_CLAIM_DIGEST", claim={**self.claim, "sha256": "not-a-digest"})

    def test_bool_size_rejected(self):
        self.deny("INVALID_CLAIM_SIZE", claim={**self.claim, "size_bytes": True})

    def test_negative_size_rejected(self):
        self.deny("INVALID_CLAIM_SIZE", claim={**self.claim, "size_bytes": -1})

    def test_bad_artifact_id_rejected(self):
        with self.assertRaises(ArtifactIdentityError) as ctx:
            create_claim(artifact_id="../private/secret", author_role="builder01", content=DATA)
        self.assertEqual(ctx.exception.code, "INVALID_ARTIFACT_ID")

    def test_invalid_claim_artifact_id_rejected(self):
        self.deny("INVALID_ARTIFACT_ID", claim={**self.claim, "artifact_id": "https://example.com/private"})

    def test_invalid_role_rejected(self):
        self.deny("INVALID_ROLE", reviewer="Unknown Role")

    def test_invalid_content_type(self):
        self.deny("INVALID_ARTIFACT_BYTES", content=bytearray(DATA))

    def test_empty_content_refused(self):
        self.deny("INVALID_ARTIFACT_BYTES", content=b"")

    def test_oversize_content_refused(self):
        self.deny("INVALID_ARTIFACT_BYTES", content=b"x" * (MAX_ARTIFACT_BYTES + 1))

    def test_untrusted_manifest_string_refused(self):
        self.deny("INVALID_CLAIM_SCHEMA", claim="pass")


if __name__ == "__main__":
    unittest.main()
