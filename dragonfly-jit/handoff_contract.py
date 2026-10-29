#!/usr/bin/env python3
"""Strict transport-neutral handoff capsule contract for Dragonfly JIT.

This module validates one bounded dispatch capsule delivered through an already
authenticated byte stream. It creates no network listener, performs no provider
calls, starts no guest, and never prints the opaque bootstrap value.

Two closed profiles are accepted:
- the already-proven credential-free transport synthetic profile;
- one manually triggered, secretless GitHub canary profile.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
import uuid

MARKER = "CI-RUNNER-DRAGONFLY-JIT-001"
SCHEMA = 1
TARGET_HOST = "dragonfly-redrix-01"
REPOSITORY = "LowcountryDigitalWorks/infrastructure-tools"

SYNTHETIC_PROFILE_ID = "dragonfly-contract-synthetic-v1"
SYNTHETIC_WORKFLOW = "dragonfly-jit-contract-synthetic.yml"
SYNTHETIC_JOB_NAME = "dragonfly-jit-contract"
SYNTHETIC_LABELS = (
    "self-hosted",
    "Linux",
    "X64",
    "dragonfly",
    "jit",
    "synthetic-only",
)

CANARY_PROFILE_ID = "dragonfly-github-canary-v1"
CANARY_WORKFLOW = ".github/workflows/dragonfly-jit-canary.yml"
CANARY_JOB_NAME = "dragonfly-canary"
CANARY_STATIC_LABELS = (
    "self-hosted",
    "Linux",
    "X64",
    "dragonfly",
    "jit",
    "ldw-ephemeral",
    "synthetic-only",
)

PROFILE_ID = SYNTHETIC_PROFILE_ID
WORKFLOW = SYNTHETIC_WORKFLOW
JOB_NAME = SYNTHETIC_JOB_NAME
LABELS = SYNTHETIC_LABELS

MAX_CAPSULE_BYTES = 65536
MAX_BOOTSTRAP_CHARS = 32768
MAX_TTL_SECONDS = 300
CLOCK_SKEW_SECONDS = 30
CLAIM_SUBDIR = Path("handoff-claims")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_REQUIRED_FIELDS = {
    "marker", "schema", "dispatch_id", "target_host", "issued_at", "expires_at",
    "profile_id", "repository", "workflow", "run_id", "run_attempt", "job_id",
    "head_sha", "job_name", "labels", "opaque_bootstrap",
}
_SUMMARY_FIELDS = (_REQUIRED_FIELDS - {"opaque_bootstrap"}) | {"bootstrap_present"}


class HandoffError(RuntimeError):
    pass


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _parse_utc(value: object, field: str) -> dt.datetime:
    if not isinstance(value, str) or not _TIME_RE.fullmatch(value):
        raise HandoffError(f"{field.upper()}_INVALID")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise HandoffError(f"{field.upper()}_INVALID") from exc
    return parsed.replace(tzinfo=dt.timezone.utc)


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise HandoffError(f"{field.upper()}_INVALID")
    return value


def _canonical_uuid4(value: object) -> str:
    if not isinstance(value, str):
        raise HandoffError("DISPATCH_ID_INVALID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise HandoffError("DISPATCH_ID_INVALID") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise HandoffError("DISPATCH_ID_INVALID")
    return value


def _opaque_bootstrap(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_BOOTSTRAP_CHARS:
        raise HandoffError("OPAQUE_BOOTSTRAP_INVALID")
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
        raise HandoffError("OPAQUE_BOOTSTRAP_INVALID")
    return value


def expected_labels(profile_id: str, run_id: int, run_attempt: int) -> tuple[str, ...]:
    if profile_id == SYNTHETIC_PROFILE_ID:
        return SYNTHETIC_LABELS
    if profile_id == CANARY_PROFILE_ID:
        return CANARY_STATIC_LABELS + (
            f"dragonfly-run-{run_id}",
            f"dragonfly-attempt-{run_attempt}",
        )
    raise HandoffError("PROFILE_INVALID")


def _expected_workflow(profile_id: str) -> str:
    if profile_id == SYNTHETIC_PROFILE_ID:
        return SYNTHETIC_WORKFLOW
    if profile_id == CANARY_PROFILE_ID:
        return CANARY_WORKFLOW
    raise HandoffError("PROFILE_INVALID")


def _expected_job_name(profile_id: str) -> str:
    if profile_id == SYNTHETIC_PROFILE_ID:
        return SYNTHETIC_JOB_NAME
    if profile_id == CANARY_PROFILE_ID:
        return CANARY_JOB_NAME
    raise HandoffError("PROFILE_INVALID")


def _validate_identity_fields(payload: dict) -> tuple[str, str, int, int, int, str, dt.datetime, dt.datetime]:
    if payload["marker"] != MARKER or type(payload["schema"]) is not int or payload["schema"] != SCHEMA:
        raise HandoffError("CAPSULE_IDENTITY_INVALID")
    dispatch_id = _canonical_uuid4(payload["dispatch_id"])
    if payload["target_host"] != TARGET_HOST:
        raise HandoffError("TARGET_HOST_INVALID")
    profile_id = payload["profile_id"]
    if not isinstance(profile_id, str) or profile_id not in {SYNTHETIC_PROFILE_ID, CANARY_PROFILE_ID}:
        raise HandoffError("PROFILE_INVALID")
    if payload["repository"] != REPOSITORY:
        raise HandoffError("REPOSITORY_INVALID")
    if payload["workflow"] != _expected_workflow(profile_id):
        raise HandoffError("WORKFLOW_INVALID")
    if payload["job_name"] != _expected_job_name(profile_id):
        raise HandoffError("JOB_NAME_INVALID")

    run_id = _positive_int(payload["run_id"], "run_id")
    run_attempt = _positive_int(payload["run_attempt"], "run_attempt")
    if payload["labels"] != list(expected_labels(profile_id, run_id, run_attempt)):
        raise HandoffError("LABELS_INVALID")
    job_id = _positive_int(payload["job_id"], "job_id")
    head_sha = payload["head_sha"]
    if not isinstance(head_sha, str) or not _SHA_RE.fullmatch(head_sha):
        raise HandoffError("HEAD_SHA_INVALID")
    issued_at = _parse_utc(payload["issued_at"], "issued_at")
    expires_at = _parse_utc(payload["expires_at"], "expires_at")
    if expires_at <= issued_at:
        raise HandoffError("EXPIRY_INVALID")
    ttl = int((expires_at - issued_at).total_seconds())
    if ttl > MAX_TTL_SECONDS:
        raise HandoffError("TTL_INVALID")
    return dispatch_id, profile_id, run_id, run_attempt, job_id, head_sha, issued_at, expires_at


def _validate_time_window(issued_at: dt.datetime, expires_at: dt.datetime, *, now: dt.datetime | None) -> None:
    current = (now or _utc_now()).astimezone(dt.timezone.utc).replace(microsecond=0)
    if issued_at > current + dt.timedelta(seconds=CLOCK_SKEW_SECONDS):
        raise HandoffError("NOT_YET_VALID")
    if current >= expires_at:
        raise HandoffError("EXPIRED")


def _summary(*, dispatch_id: str, profile_id: str, run_id: int, run_attempt: int, job_id: int,
             head_sha: str, issued_at: str, expires_at: str) -> dict:
    return {
        "marker": MARKER,
        "schema": SCHEMA,
        "dispatch_id": dispatch_id,
        "target_host": TARGET_HOST,
        "profile_id": profile_id,
        "repository": REPOSITORY,
        "workflow": _expected_workflow(profile_id),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "job_id": job_id,
        "head_sha": head_sha,
        "job_name": _expected_job_name(profile_id),
        "labels": list(expected_labels(profile_id, run_id, run_attempt)),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "bootstrap_present": True,
    }


def validate_capsule(payload: object, *, now: dt.datetime | None = None) -> dict:
    if not isinstance(payload, dict):
        raise HandoffError("CAPSULE_INVALID")
    if set(payload) != _REQUIRED_FIELDS:
        raise HandoffError("CAPSULE_FIELDS_INVALID")
    dispatch_id, profile_id, run_id, run_attempt, job_id, head_sha, issued_at, expires_at = _validate_identity_fields(payload)
    _validate_time_window(issued_at, expires_at, now=now)
    _opaque_bootstrap(payload["opaque_bootstrap"])
    return _summary(
        dispatch_id=dispatch_id, profile_id=profile_id, run_id=run_id, run_attempt=run_attempt,
        job_id=job_id, head_sha=head_sha, issued_at=payload["issued_at"], expires_at=payload["expires_at"],
    )


def _validate_claim_summary(summary: object, *, now: dt.datetime | None = None) -> dict:
    if not isinstance(summary, dict) or set(summary) != _SUMMARY_FIELDS:
        raise HandoffError("SUMMARY_FIELDS_INVALID")
    dispatch_id, profile_id, run_id, run_attempt, job_id, head_sha, issued_at, expires_at = _validate_identity_fields(summary)
    _validate_time_window(issued_at, expires_at, now=now)
    if summary["bootstrap_present"] is not True:
        raise HandoffError("BOOTSTRAP_FLAG_INVALID")
    return _summary(
        dispatch_id=dispatch_id, profile_id=profile_id, run_id=run_id, run_attempt=run_attempt,
        job_id=job_id, head_sha=head_sha, issued_at=summary["issued_at"], expires_at=summary["expires_at"],
    )


def read_capsule(stream) -> dict:
    raw = stream.read(MAX_CAPSULE_BYTES + 1)
    if len(raw) > MAX_CAPSULE_BYTES:
        raise HandoffError("CAPSULE_TOO_LARGE")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HandoffError("CAPSULE_UTF8_INVALID") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise HandoffError("CAPSULE_JSON_INVALID") from exc


def _assert_no_symlink(path: Path, *, allow_missing_leaf: bool = False) -> None:
    path = path.expanduser().absolute()
    cursor = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        is_leaf = index == len(parts) - 1
        if not cursor.exists() and not cursor.is_symlink():
            if is_leaf and allow_missing_leaf:
                return
            continue
        if cursor.is_symlink():
            raise HandoffError("CLAIM_PATH_SYMLINK")


def _fsync_directory(path: Path) -> None:
    path = path.expanduser().absolute()
    _assert_no_symlink(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise HandoffError("CLAIM_DURABILITY_FAILED") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise HandoffError("CLAIM_DURABILITY_FAILED") from exc
    finally:
        os.close(fd)


def claim_dispatch(summary: dict, *, state_root: Path, now: dt.datetime | None = None) -> Path:
    summary = _validate_claim_summary(summary, now=now)
    state_root = state_root.expanduser().absolute()
    _assert_no_symlink(state_root, allow_missing_leaf=True)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_no_symlink(state_root)
    _fsync_directory(state_root.parent)

    claims = state_root / CLAIM_SUBDIR
    _assert_no_symlink(claims, allow_missing_leaf=True)
    claims.mkdir(mode=0o700, exist_ok=True)
    _assert_no_symlink(claims)
    os.chmod(claims, 0o700)
    _fsync_directory(state_root)

    claim_path = claims / f"{summary['dispatch_id']}.json"
    _assert_no_symlink(claim_path, allow_missing_leaf=True)
    record = {
        "marker": MARKER,
        "schema": SCHEMA,
        "dispatch_id": summary["dispatch_id"],
        "target_host": summary["target_host"],
        "profile_id": summary["profile_id"],
        "run_id": summary["run_id"],
        "run_attempt": summary["run_attempt"],
        "job_id": summary["job_id"],
        "head_sha": summary["head_sha"],
        "expires_at": summary["expires_at"],
        "claimed_at": (now or _utc_now()).astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(claim_path, flags, 0o600)
    except FileExistsError as exc:
        raise HandoffError("HANDOFF_REPLAY") from exc
    except OSError as exc:
        raise HandoffError("CLAIM_CREATE_FAILED") from exc
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as exc:
        try:
            claim_path.unlink()
            _fsync_directory(claims)
        except (OSError, HandoffError):
            pass
        raise HandoffError("CLAIM_WRITE_FAILED") from exc
    _fsync_directory(claims)
    return claim_path


def default_state_root() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base).expanduser() / "ldw-dragonfly-jit"
    return Path.home() / ".local/state/ldw-dragonfly-jit"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate/claim one Dragonfly handoff capsule from stdin")
    parser.add_argument("command", choices=("validate", "claim"))
    parser.add_argument("--state-root", type=Path, default=default_state_root())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = read_capsule(sys.stdin.buffer)
        summary = validate_capsule(payload)
        if args.command == "claim":
            claim_dispatch(summary, state_root=args.state_root)
            summary = dict(summary)
            summary["claimed"] = True
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    except HandoffError as exc:
        print(f"ERROR:{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
