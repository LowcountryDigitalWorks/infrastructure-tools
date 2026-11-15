"""REDRIX workflow-source GitHub evidence collector (source-only, NO authority).

Consumes eight narrow GET-shaped snapshots from an injected reader; this module
contains no credentials, network client, provider write or protected issuer.
All input, including the caller's candidate 'release', is UNTRUSTED. A matching
tuple is DATA_ONLY and never authorizes a GitHub JIT POST or a guest launch.
"""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable, Mapping
from typing import Any

from tools.dragonfly_workflow_source_admission import inspect_workflow_source_tuple

_REPO = "LowcountryDigitalWorks/infrastructure-tools"
_PATH = ".github/workflows/dragonfly-jit-canary.yml"
_PREFIX = f"repos/{_REPO}"
_HEAD_REF_PATH = f"{_PREFIX}/git/ref/heads/main"
_CONTENT_PATH = f"{_PREFIX}/contents/{_PATH}"
_MAX_WORKFLOW_BYTES = 16_384
_SHA = re.compile(r"^[a-f0-9]{40}$")


class _Refuse(Exception):
    pass


def _assert(ok: bool) -> None:
    if not ok:
        raise _Refuse()


def _mapping(value: Any) -> Mapping[str, Any]:
    _assert(isinstance(value, Mapping))
    return value


def _get(value: Any, field: str) -> Any:
    obj = _mapping(value)
    _assert(field in obj)
    return obj[field]


def _int(value: Any) -> int:
    _assert(type(value) is int and value > 0)
    return value


def _sha(value: Any) -> str:
    _assert(type(value) is str and bool(_SHA.fullmatch(value)))
    return value


def _read(reader: Callable[[str], Any], path: str) -> Mapping[str, Any]:
    # Caller can connect this to an approved read-only adapter in the future.
    # Never expose raw responses or exceptions to the result.
    return _mapping(reader(path))


def _workflow_blob(reader: Callable[[str], Any], commit: str) -> dict[str, Any]:
    contents = _read(reader, f"{_CONTENT_PATH}?ref={commit}")
    _assert(_get(contents, "path") == _PATH)
    _assert(_get(contents, "type") == "file")
    provider_sha = _sha(_get(contents, "sha"))
    size = _get(contents, "size")
    _assert(type(size) is int and 0 < size <= _MAX_WORKFLOW_BYTES)
    _assert(_get(contents, "encoding") == "base64")
    b64 = _get(contents, "content")
    _assert(type(b64) is str and len(b64) <= 4 * _MAX_WORKFLOW_BYTES)
    try:
        raw = base64.b64decode(b64.replace("\n", "").replace("\r", ""), validate=True)
    except (ValueError, base64.binascii.Error):
        raise _Refuse() from None
    _assert(len(raw) == size)
    # Git's historical SHA-1 blob framing; this repository uses 40-hex IDs.
    computed = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    _assert(computed == provider_sha)
    # Return only sanitized identity, never workflow bytes.
    return {"path": _PATH, "type": "file",
            "commit_sha": commit, "git_blob_sha": computed}


def _ref(reader: Callable[[str], Any]) -> dict[str, Any]:
    ref = _read(reader, _HEAD_REF_PATH)
    obj = _get(ref, "object")
    return {"ref": _get(ref, "ref"),
            "object_type": _get(obj, "type"),
            "object_sha": _get(obj, "sha")}


def _run(reader: Callable[[str], Any], run_id: int) -> dict[str, Any]:
    v = _read(reader, f"{_PREFIX}/actions/runs/{run_id}")
    repo = _get(_get(v, "repository"), "full_name")
    head_repo = _get(_get(v, "head_repository"), "full_name")
    return {"id": _get(v, "id"), "run_attempt": _get(v, "run_attempt"),
            "repository": repo, "head_repository": head_repo,
            "head_sha": _get(v, "head_sha"), "head_branch": _get(v, "head_branch"),
            "path": _get(v, "path"), "event": _get(v, "event"),
            "status": _get(v, "status"), "conclusion": _get(v, "conclusion")}


def _job(reader: Callable[[str], Any], run_id: int, attempt: int,
         job_id: int) -> dict[str, Any]:
    response = _read(reader, f"{_PREFIX}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    count = _get(response, "total_count")
    jobs = _get(response, "jobs")
    _assert(type(count) is int and 0 < count <= 100)
    _assert(type(jobs) is list and len(jobs) == count)
    matches = [v for v in jobs if _get(v, "id") == job_id]
    _assert(len(matches) == 1)
    v = _mapping(matches[0])
    return {"id": _get(v, "id"), "run_id": _get(v, "run_id"),
            "run_attempt": _get(v, "run_attempt"), "head_sha": _get(v, "head_sha"),
            "name": _get(v, "name"), "status": _get(v, "status"),
            "conclusion": _get(v, "conclusion"), "runner_id": _get(v, "runner_id"),
            "runner_name": _get(v, "runner_name"), "labels": _get(v, "labels")}


def _frame(reader: Callable[[str], Any], commit: str,
           run_id: int, attempt: int, job_id: int) -> tuple[dict[str, Any], ...]:
    # No GET to an unbounded caller-provided URL or arbitrary repository.
    return (_ref(reader), _workflow_blob(reader, commit),
            _run(reader, run_id), _job(reader, run_id, attempt, job_id))


def collect_workflow_source_evidence(
    provider_get: Callable[[str], Any],
    candidate: Any,
    run_id: int,
    run_attempt: int,
    job_id: int,
    *,
    caller_expected_sha: str | None = None,
) -> dict[str, Any]:
    """Collect and correlate, but NEVER admit.

    The snapshot API contract is modeled on GitHub REST GET objects. The
    collector cannot attest that its injected reader is authenticated or that
    a candidate came from a protected issuer. It therefore cannot authorize a
    provider write even if every source field matches. Provider errors are
    collapsed to one safe constant and never echoed.
    """
    hold = {"classification": "HOLD_PROVIDER_EVIDENCE_UNVERIFIED",
            "tuple_consistent": False, "jit_authorized": False,
            "provider_write_authorized": False, "provider_reads_complete": False}
    try:
        _int(run_id); _int(run_attempt); _int(job_id)
        _assert(callable(provider_get))
        c = _mapping(candidate)
        # The commit is the only variable component allowed into an API path.
        commit = _sha(_get(c, "commit_sha"))
        _assert(_get(c, "approved_ref") == "refs/heads/main")
        _assert(_get(c, "repository") == _REPO and
                _get(c, "workflow_path") == _PATH)
        before = _frame(provider_get, commit, run_id, run_attempt, job_id)
        fresh = _frame(provider_get, commit, run_id, run_attempt, job_id)
        correlated = inspect_workflow_source_tuple(
            candidate, *before, *fresh, caller_expected_sha=caller_expected_sha
        )
        # Unlike a negative fetched read, a consistent tuple may be emitted as
        # DATA_ONLY; never grant an operational permission.
        return {"classification": correlated["classification"],
                "tuple_consistent": correlated["tuple_consistent"],
                "jit_authorized": False, "provider_write_authorized": False,
                "provider_reads_complete": True}
    except Exception:
        # Includes provider exceptions: never expose arbitrary messages, paths,
        # decoded content, headers, credentials, or raw objects.
        return hold
