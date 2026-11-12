"""Source-only non-GitHub artifact identity guard for LDW Chat Relay Gate D.

This offline deterministic proof checks a bounded byte snapshot and role separation.
It DOES NOT authenticate ChatGPT identities, run a review, mint a credential,
start a receiving chat, certify independence, or authorize an IR PASS.
"""
from __future__ import annotations

import hashlib
import hmac
import re

SCHEMA = "ldw.chat-relay.artifact-identity.v0"
VERIFIED_STATE = "CANDIDATE_BYTES_VERIFIED_IR_PENDING"
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024  # synthetic/public only
ARTIFACT_ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
ROLE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
FIELDS = frozenset({"schema", "artifact_id", "author_role", "size_bytes", "sha256"})


class ArtifactIdentityError(ValueError):
    """Fixed public error code, never include untrusted artifact bytes."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _role(value: object) -> str:
    if not isinstance(value, str) or ROLE.fullmatch(value) is None:
        raise ArtifactIdentityError("INVALID_ROLE")
    return value


def _artifact_id(value: object) -> str:
    if not isinstance(value, str) or ARTIFACT_ID.fullmatch(value) is None:
        raise ArtifactIdentityError("INVALID_ARTIFACT_ID")
    return value


def _bytes(value: object) -> bytes:
    # Immutable snapshot: no streams, path/URL reads, iterators or bytearray aliases.
    if type(value) is not bytes or not 1 <= len(value) <= MAX_ARTIFACT_BYTES:
        raise ArtifactIdentityError("INVALID_ARTIFACT_BYTES")
    return value


def create_claim(*, artifact_id: str, author_role: str, content: bytes) -> dict:
    """Fingerprint synthetic/public bytes locally; the claim is NOT signed."""
    _artifact_id(artifact_id)
    _role(author_role)
    snapshot = _bytes(content)
    return {
        "schema": SCHEMA,
        "artifact_id": artifact_id,
        "author_role": author_role,
        "size_bytes": len(snapshot),
        "sha256": hashlib.sha256(snapshot).hexdigest(),
    }


def verify_claim(
    *,
    claim: object,
    content: bytes,
    authenticated_author_role: str,
    authenticated_reviewer_role: str,
) -> dict:
    """Verify bytes and distinct *caller-supplied trusted* role identities.

    Caller MUST bind both roles from an independently authenticated transport,
    not model/chat text or this unsigned manifest. Even on success, IR is pending.
    """
    author = _role(authenticated_author_role)
    reviewer = _role(authenticated_reviewer_role)
    if author == reviewer:
        raise ArtifactIdentityError("SELF_REVIEW_REFUSED")
    if type(claim) is not dict or set(claim) != FIELDS:
        raise ArtifactIdentityError("INVALID_CLAIM_SCHEMA")
    if claim["schema"] != SCHEMA:
        raise ArtifactIdentityError("INVALID_CLAIM_SCHEMA")
    artifact_id = _artifact_id(claim["artifact_id"])
    claimed_author = _role(claim["author_role"])
    if claimed_author != author:
        raise ArtifactIdentityError("AUTHOR_MISMATCH")
    count = claim["size_bytes"]
    if type(count) is not int or not 1 <= count <= MAX_ARTIFACT_BYTES:
        raise ArtifactIdentityError("INVALID_CLAIM_SIZE")
    digest = claim["sha256"]
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise ArtifactIdentityError("INVALID_CLAIM_DIGEST")
    snapshot = _bytes(content)
    if len(snapshot) != count:
        raise ArtifactIdentityError("SIZE_MISMATCH")
    actual = hashlib.sha256(snapshot).hexdigest()
    if not hmac.compare_digest(actual, digest):
        raise ArtifactIdentityError("DIGEST_MISMATCH")
    return {
        "schema": SCHEMA,
        "artifact_id": artifact_id,
        "sha256": actual,
        "size_bytes": count,
        "author_role": author,
        "reviewer_role": reviewer,
        "state": VERIFIED_STATE,
        "chat_wake": "NOT_PROVEN",
        "review_verdict": "PENDING_INDEPENDENT_REVIEW",
    }
