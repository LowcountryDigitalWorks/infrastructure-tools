"""Synthetic, non-authorizing REDRIX workflow-source provenance correlation.

This module has no GitHub transport, protected issuer, credentials, side effects,
or production import. A matching input tuple is DATA_ONLY and never permits a
workflow dispatch, JIT configuration POST, runner registration or guest launch.
Live admission requires a distinct protected, independently approved issuer.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_REPOSITORY = "LowcountryDigitalWorks/infrastructure-tools"
_WORKFLOW = ".github/workflows/dragonfly-jit-canary.yml"
_PROFILE = "dragonfly-github-canary-v1"
_STATIC_LABELS = (
    "self-hosted", "Linux", "X64", "dragonfly", "jit", "ldw-ephemeral",
    "synthetic-only",
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_BRANCH = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,100}$")
_GENERATION = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class _Hold(Exception):
    """Closed refusal: never include arbitrary provider exception details."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise _Hold(reason)


def _field(obj: Any, name: str) -> Any:
    _require(isinstance(obj, Mapping) and name in obj, "MISSING_EVIDENCE")
    return obj[name]


def _sha(value: Any) -> bool:
    return type(value) is str and bool(_SHA.fullmatch(value))


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _ref_name(ref: str) -> str:
    return ref.removeprefix("refs/heads/")


def _check_candidate(candidate: Any) -> None:
    _require(isinstance(candidate, Mapping), "MISSING_PROTECTED_GENERATION")
    _require(_field(candidate, "schema") == 1, "GENERATION_SCHEMA_INVALID")
    generation = _field(candidate, "generation")
    _require(type(generation) is str and bool(_GENERATION.fullmatch(generation)),
             "GENERATION_INVALID")
    _require(_field(candidate, "profile") == _PROFILE, "PROFILE_MISMATCH")
    _require(_field(candidate, "repository") == _REPOSITORY,
             "REPOSITORY_MISMATCH")
    _require(_field(candidate, "workflow_path") == _WORKFLOW,
             "WORKFLOW_PATH_MISMATCH")
    _require(_sha(_field(candidate, "commit_sha")), "PINNED_COMMIT_INVALID")
    _require(_sha(_field(candidate, "workflow_blob_sha")), "PINNED_BLOB_INVALID")
    ref = _field(candidate, "approved_ref")
    _require(type(ref) is str and bool(_BRANCH.fullmatch(ref)) and
             ".." not in ref and "//" not in ref and not ref.endswith((".","/")),
             "REF_INVALID")


def _check_ref(candidate: Mapping[str, Any], observed: Any) -> None:
    _require(_field(observed, "ref") == candidate["approved_ref"],
             "REF_MISMATCH")
    _require(_field(observed, "object_type") == "commit",
             "REF_TARGET_TYPE_INVALID")
    _require(_field(observed, "object_sha") == candidate["commit_sha"],
             "REF_TARGET_MOVED")


def _check_blob(candidate: Mapping[str, Any], observed: Any) -> None:
    _require(_field(observed, "path") == _WORKFLOW, "WORKFLOW_PATH_MISMATCH")
    _require(_field(observed, "type") == "file", "WORKFLOW_TYPE_INVALID")
    _require(_field(observed, "commit_sha") == candidate["commit_sha"],
             "WORKFLOW_COMMIT_MISMATCH")
    _require(_field(observed, "git_blob_sha") == candidate["workflow_blob_sha"],
             "WORKFLOW_BLOB_MISMATCH")


def _check_run(candidate: Mapping[str, Any], observed: Any) -> None:
    _require(_positive_int(_field(observed, "id")) and
             _positive_int(_field(observed, "run_attempt")), "RUN_ID_INVALID")
    _require(_field(observed, "repository") == _REPOSITORY and
             _field(observed, "head_repository") == _REPOSITORY,
             "RUN_REPOSITORY_MISMATCH")
    _require(_field(observed, "head_sha") == candidate["commit_sha"],
             "RUN_COMMIT_MISMATCH")
    _require(_field(observed, "head_branch") == _ref_name(candidate["approved_ref"]),
             "RUN_REF_MISMATCH")
    _require(_field(observed, "path") == _WORKFLOW and
             _field(observed, "event") == "workflow_dispatch",
             "RUN_WORKFLOW_MISMATCH")
    _require(_field(observed, "status") == "queued" and
             _field(observed, "conclusion") is None, "RUN_NOT_QUEUED")


def _check_job(run: Mapping[str, Any], observed: Any) -> None:
    _require(_positive_int(_field(observed, "id")) and
             _field(observed, "run_id") == run["id"] and
             _field(observed, "run_attempt") == run["run_attempt"],
             "JOB_IDENTITY_MISMATCH")
    _require(_field(observed, "head_sha") == run["head_sha"] and
             _field(observed, "name") == "dragonfly-canary", "JOB_SOURCE_MISMATCH")
    _require(_field(observed, "status") == "queued" and
             _field(observed, "conclusion") is None, "JOB_NOT_QUEUED")
    _require(_field(observed, "runner_id") in (None, 0) and
             _field(observed, "runner_name") in ("", None),
             "JOB_ALREADY_ASSIGNED")
    expected = set(_STATIC_LABELS) | {
        f"dragonfly-run-{run['id']}",
        f"dragonfly-attempt-{run['run_attempt']}",
    }
    labels = _field(observed, "labels")
    _require(type(labels) is list and len(labels) == len(expected) and
             all(type(label) is str for label in labels) and
             set(labels) == expected, "JOB_LABELS_MISMATCH")


def inspect_workflow_source_tuple(
    candidate: Any,
    ref_before: Any,
    blob_before: Any,
    run_before: Any,
    job_before: Any,
    ref_fresh: Any,
    blob_fresh: Any,
    run_fresh: Any,
    job_fresh: Any,
    *,
    caller_expected_sha: str | None = None,
) -> dict[str, Any]:
    """Correlate synthetic normalized snapshots; never grant runtime authority.

    The caller_expected_sha argument is deliberately ignored for trust:
    matching an arbitrary caller-supplied SHA cannot create an issuer pin.
    Provider authentication, atomicity, immutable release binding and live
    JIT mint-path integration are OUT OF SCOPE for this source-only fixture.
    """
    refusal = "HOLD_WORKFLOW_SOURCE_UNBOUND"
    try:
        _check_candidate(candidate)
        # Both an initial and a genuinely fresh provider read are required.
        for ref in (ref_before, ref_fresh):
            _check_ref(candidate, ref)
        for blob in (blob_before, blob_fresh):
            _check_blob(candidate, blob)
        for run in (run_before, run_fresh):
            _check_run(candidate, run)
        for run, job in ((run_before, job_before), (run_fresh, job_fresh)):
            _check_job(run, job)
        _require(run_before == run_fresh, "RUN_CHANGED_BETWEEN_READS")
        _require(job_before == job_fresh, "JOB_CHANGED_BETWEEN_READS")
        _require(ref_before == ref_fresh, "REF_CHANGED_BETWEEN_READS")
        _require(blob_before == blob_fresh, "BLOB_CHANGED_BETWEEN_READS")
        # Never use caller_expected_sha as the pin or substitute for a release.
        _ = caller_expected_sha
    except _Hold as error:
        return {
            "classification": refusal,
            "reason": str(error),
            "tuple_consistent": False,
            "jit_authorized": False,
            "provider_write_authorized": False,
        }
    return {
        "classification": "SOURCE_TUPLE_CONSISTENT_DATA_ONLY",
        "reason": "PROTECTED_ISSUER_AND_PROVIDER_AUTH_NOT_ATTESTED",
        "tuple_consistent": True,
        "jit_authorized": False,
        "provider_write_authorized": False,
    }
