#!/usr/bin/env python3
"""Render the bounded in-memory REDRIX Gate A0 invocation.

This is a source-only control-plane helper. It does not fetch, execute, connect to
REDRIX, mutate provider state, or perform Gate A. It renders a shell-safe command
whose embedded Python bootstrap fetches one immutable public helper blob into
memory, verifies its exact SHA-256 and size bound, then compile/executes it only
after verification.
"""
from __future__ import annotations

import argparse
import re
import shlex

ACCEPTED_A0_COMMIT = "5815e4e4e5ea4719c9d694b1ccefa1808c927ac7"
ACCEPTED_A0_BLOB = "fc9784a52d5f0d20b02c5d95ad4adc2e86ae04e9"
ACCEPTED_A0_SHA256 = "eed2ab4ef830a119b6c73915c20a07c354be43844806b692277004bc6d0461b7"
ACCEPTED_A0_BYTES = 25719
ACCEPTED_A0_PATH = "tools/dragonfly_gate_a0.py"
ACCEPTED_A0_URL = (
    "https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/"
    + ACCEPTED_A0_COMMIT
    + "/"
    + ACCEPTED_A0_PATH
)
MAX_SOURCE_BYTES = 65536
PYTHON = "/usr/bin/python3"
ACCEPTED_ALIASES = {"redrix", "penguin"}


class BootstrapInputError(ValueError):
    pass


def build_bootstrap_code(*, url: str, sha256: str, max_bytes: int) -> str:
    if not re.fullmatch(r"https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[A-Za-z0-9_./-]+", url):
        raise BootstrapInputError("A0_BOOTSTRAP_URL_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise BootstrapInputError("A0_BOOTSTRAP_SHA256_INVALID")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0 or max_bytes > 1024 * 1024:
        raise BootstrapInputError("A0_BOOTSTRAP_SIZE_LIMIT_INVALID")

    return f'''import hashlib,sys,urllib.request
URL={url!r}
EXPECTED_SHA256={sha256!r}
MAX_BYTES={max_bytes}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise RuntimeError("A0_SOURCE_REDIRECT_REFUSED")
def hold(code):
    print("DRAGONFLY_GATE_A0_BOOTSTRAP=HOLD")
    print("CLASSIFICATION="+code)
    raise SystemExit(1)
try:
    request=urllib.request.Request(URL,headers={{"User-Agent":"LDW-Dragonfly-A0/1","Accept":"text/plain"}},method="GET")
    opener=urllib.request.build_opener(NoRedirect)
    response=opener.open(request,timeout=10)
    try:
        if getattr(response,"status",None)!=200:
            hold("A0_SOURCE_HTTP_STATUS_INVALID")
        if response.geturl()!=URL:
            hold("A0_SOURCE_FINAL_URL_INVALID")
        data=response.read(MAX_BYTES+1)
    finally:
        response.close()
    if len(data)>MAX_BYTES:
        hold("A0_SOURCE_TOO_LARGE")
    if hashlib.sha256(data).hexdigest()!=EXPECTED_SHA256:
        hold("A0_SOURCE_SHA256_MISMATCH")
except SystemExit:
    raise
except Exception:
    hold("A0_SOURCE_FETCH_FAILED")
sys.argv=["dragonfly_gate_a0.py"]+sys.argv[1:]
try:
    exec(compile(data,"<dragonfly_gate_a0.py>","exec"),{{"__name__":"__main__","__file__":"<memory>"}})
except SystemExit:
    raise
except Exception:
    hold("A0_HELPER_EXECUTION_FAILED")
'''


def render_command(*, alias: str, host_fingerprint: str, transport_key_sha256: str) -> str:
    if alias not in ACCEPTED_ALIASES:
        raise BootstrapInputError("A0_EXPECTED_LOCAL_HOST_IDENTITY_INVALID")
    if re.fullmatch(r"SHA256:[A-Za-z0-9+/]+={0,2}", host_fingerprint) is None:
        raise BootstrapInputError("A0_EXPECTED_HOST_FINGERPRINT_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", transport_key_sha256) is None:
        raise BootstrapInputError("A0_EXPECTED_TRANSPORT_KEY_SHA256_INVALID")

    code = build_bootstrap_code(
        url=ACCEPTED_A0_URL,
        sha256=ACCEPTED_A0_SHA256,
        max_bytes=MAX_SOURCE_BYTES,
    )
    argv = [
        PYTHON,
        "-c",
        code,
        "--expected-local-alias",
        alias,
        "--expected-host-fingerprint",
        host_fingerprint,
        "--expected-transport-key-sha256",
        transport_key_sha256,
    ]
    return shlex.join(argv)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render immutable in-memory REDRIX Gate A0 command")
    parser.add_argument("--expected-local-alias", required=True, choices=sorted(ACCEPTED_ALIASES))
    parser.add_argument("--expected-host-fingerprint", required=True)
    parser.add_argument("--expected-transport-key-sha256", required=True)
    args = parser.parse_args()
    try:
        command = render_command(
            alias=args.expected_local_alias,
            host_fingerprint=args.expected_host_fingerprint,
            transport_key_sha256=args.expected_transport_key_sha256,
        )
    except BootstrapInputError as exc:
        print("DRAGONFLY_GATE_A0_BOOTSTRAP_RENDER=HOLD")
        print("CLASSIFICATION=" + str(exc))
        return 1
    print("DRAGONFLY_GATE_A0_BOOTSTRAP_RENDER=PASS")
    print(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
