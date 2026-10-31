#!/usr/bin/env python3
"""Render the bounded in-memory REDRIX Gate A3 preflight invocation.

Source-only control-plane helper. It does not connect to REDRIX or mutate host
state. It renders a shell-safe command whose embedded Python bootstrap fetches one
immutable public preflight helper into memory, verifies exact byte length and
SHA-256, compile/executes it only after verification, and passes the expected
transport-key identity digest bound at render time.

The transport-key SHA-256 must be the Gate A1 operator-verified dedicated transport
public identity (LDW01 ``TRANSPORT_PRIVATE_KEY_UNCHANGED`` contract output). The
orchestrator supplies that digest to this renderer; REDRIX must not accept an
ad-hoc operator-typed CLI value without passing through this pinned fetch path.
"""
from __future__ import annotations

import argparse
import re
import shlex

# Updated with each accepted Gate A3 preflight packet (same discipline as Gate A0).
ACCEPTED_A3_COMMIT = "b73acb51aee0887dd987fe8926855cc623e21c21"
ACCEPTED_A3_SHA256 = "336d3dcfb445301394093f287935ee034f37db0073695ff4adba4c715b26e086"
ACCEPTED_A3_BYTES = 4646
ACCEPTED_A3_PATH = "tools/dragonfly_canary_redrix_preflight.py"
ACCEPTED_A3_URL = (
    "https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/"
    + ACCEPTED_A3_COMMIT
    + "/"
    + ACCEPTED_A3_PATH
)
MAX_SOURCE_BYTES = 65536
PYTHON = "/usr/bin/python3"
PYTHON_FLAGS = ("-I", "-B")
TRANSPORT_KEY_PROVENANCE = "gate-a1-ldw01-transport-private-key-unchanged-contract"


class BootstrapInputError(ValueError):
    pass


def build_bootstrap_code(
    *,
    url: str,
    sha256: str,
    exact_bytes: int,
    max_bytes: int,
    transport_key_sha256: str,
) -> str:
    if not re.fullmatch(
        r"https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[A-Za-z0-9_./-]+",
        url,
    ):
        raise BootstrapInputError("A3_BOOTSTRAP_URL_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise BootstrapInputError("A3_BOOTSTRAP_SHA256_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", transport_key_sha256) is None:
        raise BootstrapInputError("A3_EXPECTED_TRANSPORT_KEY_SHA256_INVALID")
    if not isinstance(exact_bytes, int) or isinstance(exact_bytes, bool) or exact_bytes <= 0:
        raise BootstrapInputError("A3_BOOTSTRAP_EXACT_SIZE_INVALID")
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes <= 0
        or max_bytes > 1024 * 1024
        or exact_bytes > max_bytes
    ):
        raise BootstrapInputError("A3_BOOTSTRAP_SIZE_LIMIT_INVALID")

    return f'''import hashlib,sys,urllib.request
URL={url!r}
EXPECTED_SHA256={sha256!r}
EXPECTED_BYTES={exact_bytes}
MAX_BYTES={max_bytes}
TRANSPORT_SHA256={transport_key_sha256!r}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise RuntimeError("A3_SOURCE_REDIRECT_REFUSED")
def hold(code):
    print("DRAGONFLY_GATE_A3_BOOTSTRAP=HOLD")
    print("CLASSIFICATION="+code)
    raise SystemExit(1)
try:
    request=urllib.request.Request(URL,headers={{"User-Agent":"LDW-Dragonfly-A3/1","Accept":"text/plain"}},method="GET")
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({{}}),NoRedirect)
    response=opener.open(request,timeout=10)
    try:
        if getattr(response,"status",None)!=200:
            hold("A3_SOURCE_HTTP_STATUS_INVALID")
        if response.geturl()!=URL:
            hold("A3_SOURCE_FINAL_URL_INVALID")
        data=response.read(MAX_BYTES+1)
    finally:
        response.close()
    if len(data)>MAX_BYTES:
        hold("A3_SOURCE_TOO_LARGE")
    if len(data)!=EXPECTED_BYTES:
        hold("A3_SOURCE_LENGTH_MISMATCH")
    if hashlib.sha256(data).hexdigest()!=EXPECTED_SHA256:
        hold("A3_SOURCE_SHA256_MISMATCH")
except SystemExit:
    raise
except Exception:
    hold("A3_SOURCE_FETCH_FAILED")
sys.argv=["dragonfly_canary_redrix_preflight.py","--expected-transport-key-sha256",TRANSPORT_SHA256]
try:
    exec(compile(data,"<dragonfly_canary_redrix_preflight.py>","exec"),{{"__name__":"__main__","__file__":"<memory>"}})
except SystemExit:
    raise
except Exception:
    hold("A3_HELPER_EXECUTION_FAILED")
'''


def render_command(*, transport_key_sha256: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", transport_key_sha256) is None:
        raise BootstrapInputError("A3_EXPECTED_TRANSPORT_KEY_SHA256_INVALID")

    code = build_bootstrap_code(
        url=ACCEPTED_A3_URL,
        sha256=ACCEPTED_A3_SHA256,
        exact_bytes=ACCEPTED_A3_BYTES,
        max_bytes=MAX_SOURCE_BYTES,
        transport_key_sha256=transport_key_sha256,
    )
    argv = [PYTHON, *PYTHON_FLAGS, "-c", code]
    return shlex.join(argv)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render immutable in-memory REDRIX Gate A3 preflight command")
    parser.add_argument("--expected-transport-key-sha256", required=True)
    parser.add_argument("--provenance", default=TRANSPORT_KEY_PROVENANCE, choices=[TRANSPORT_KEY_PROVENANCE])
    args = parser.parse_args()
    try:
        command = render_command(transport_key_sha256=args.expected_transport_key_sha256)
    except BootstrapInputError as exc:
        print("DRAGONFLY_GATE_A3_BOOTSTRAP_RENDER=HOLD")
        print("CLASSIFICATION=" + str(exc))
        return 1
    print("DRAGONFLY_GATE_A3_BOOTSTRAP_RENDER=PASS")
    print("TRANSPORT_KEY_PROVENANCE=" + args.provenance)
    print(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
