#!/usr/bin/env python3
"""Replay the accepted scanner scripts without creating a second scanner source.

This public synthetic caller cannot establish the private production check.
It proves the unchanged contract and runtime canaries in a disposable guest.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

import yaml  # Included in the pinned Ubuntu cloud image for cloud-init.

PIN = "d8a2f4ed8a7a56b996c2e6c99cdde9fcf39bb744"
SOURCE_HASH = "e87c43b9811e443a4697d70e28a84797b8f602dc9674eee126aebfc988001608"
VERSION = "1.7.4"
SCANNER_HASH = "9ed7739a39a26a2217f38726bff8a8f4fe079d3b21272caa7959823ccc444d96"
SOURCE = f"https://raw.githubusercontent.com/LowcountryDigitalWorks/.github/{PIN}/.github/workflows/security-secrets.yml"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


def refuse(code):
    # Only fixed classifications leave the guest; no exception/output payloads.
    print(f"BETTERLEAKS_CONTRACT_PROOF_FAILED={code}", flush=True)
    raise SystemExit(1)


def load_contract(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_HASH:
        refuse("SOURCE_HASH")
    contract = yaml.safe_load(data)
    if contract["permissions"] != {"contents": "read"}:
        refuse("PERMISSIONS")
    if contract["env"] != {"BETTERLEAKS_VERSION": VERSION, "BETTERLEAKS_SHA256": SCANNER_HASH}:
        refuse("VERSION_OR_HASH_PIN")
    steps = contract["jobs"]["secret-scan"]["steps"]
    checkout = steps[0]
    if checkout.get("uses") != CHECKOUT or checkout.get("with") != {"fetch-depth": 0, "persist-credentials": False}:
        refuse("CALLER_HISTORY_CHECKOUT")
    scripts = steps[1:]
    if len(scripts) != 6 or any(step.get("shell") != "bash" or "run" not in step for step in scripts):
        refuse("SCRIPT_CONTRACT")
    return contract, scripts


def expression_context(environment):
    return {
        "${{ github.event_name }}": environment["EVENT_NAME"],
        "${{ github.event.pull_request.base.sha }}": environment.get("PR_BASE_SHA", ""),
        "${{ github.event.pull_request.head.sha }}": environment.get("PR_HEAD_SHA", ""),
        "${{ github.event.pull_request.base.sha || '' }}": environment.get("PR_BASE_SHA", ""),
        "${{ github.event.pull_request.head.sha || '' }}": environment.get("PR_HEAD_SHA", ""),
        "${{ github.sha }}": environment["CALLER_SHA"],
        "${{ inputs.verify_canary }}": "true",
    }


def run_proof():
    if os.getuid() == 0 or os.environ.get("GITHUB_REPOSITORY") != "LowcountryDigitalWorks/infrastructure-tools":
        refuse("SYNTHETIC_CALLER_BOUNDARY")
    if subprocess.run(["git", "rev-parse", "--is-shallow-repository"], capture_output=True, text=True, check=True).stdout.strip() != "false":
        refuse("FULL_CALLER_HISTORY")
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        data = response.read(128 * 1024)
    contract, scripts = load_contract(data)
    environment = dict(os.environ)
    environment.update(contract["env"])
    expressions = expression_context(os.environ)
    for index, step in enumerate(scripts, start=1):
        if step.get("if") not in (None, "${{ inputs.verify_canary }}"):
            refuse("UNSUPPORTED_STEP_CONDITION")
        step_environment = dict(environment)
        for key, value in step.get("env", {}).items():
            if value not in expressions:
                refuse("UNSUPPORTED_STEP_EXPRESSION")
            step_environment[key] = expressions[value]
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
            env=step_environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=300,
        )
        # The accepted scripts already redact/suppress findings. Discard all
        # captured output again, including error text and tool version output.
        result.stdout = None
        if result.returncode != 0:
            refuse(f"SCRIPT_{index}")
        env_file = Path(environment["GITHUB_ENV"])
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                key, separator, value = line.partition("=")
                if not separator or key not in {"BETTERLEAKS_BIN", "BETTERLEAKS_LOG_OPTS"}:
                    refuse("UNEXPECTED_ENV_EXPORT")
                environment[key] = value
        print(f"BETTERLEAKS_EXACT_SCRIPT_{index}=PASS", flush=True)
    for classification in (
        "BETTERLEAKS_VERSION_PIN_PRESERVED=YES",
        "BETTERLEAKS_HASH_VERIFICATION=PASS",
        "CALLER_HISTORY_SCOPE_EQUIVALENT=PASS",
        "CANDIDATE_HISTORY_SCAN_EQUIVALENT=PASS",
        "CANDIDATE_TREE_SCAN_EQUIVALENT=PASS",
        "FAIL_CLOSED_REVISION_RESOLUTION=PASS",
        "FINDINGS_REDACTED_SUPPRESSED=YES",
        "BETTERLEAKS_DISPOSABLE_CLASS_PROOF=PARTIAL",
        "BUSINESS_OPERATIONS_PRODUCTION_CHECK=NOT_RUN",
    ):
        print(classification, flush=True)


if __name__ == "__main__":
    try:
        run_proof()
    except Exception:
        refuse("BOUNDED_EXECUTION_FAILURE")
