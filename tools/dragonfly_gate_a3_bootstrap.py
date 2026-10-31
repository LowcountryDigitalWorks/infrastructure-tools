#!/usr/bin/env python3
"""Render the bounded in-memory REDRIX Gate A3 preflight invocation.

Source-only control-plane helper. It does not connect to REDRIX or mutate host
state. It renders a shell-safe command whose embedded Python bootstrap fetches two
immutable public helpers (preflight + pinned installer) into memory, verifies exact
byte length and SHA-256 for each, injects verified installer bytes into the preflight
exec namespace, compile/executes preflight only after verification, and passes the
expected transport-key identity digest derived from the Gate A1 protected private key against
an independently trusted Gate A1 baseline and audit record (both required).
"""
from __future__ import annotations

import argparse
import re
import shlex
import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from dragonfly_gate_a1_transport_identity import (  # noqa: E402
    PROVENANCE as TRANSPORT_KEY_PROVENANCE,
    TransportIdentityError,
    derive_bound_transport_public_identity,
    parse_record as parse_gate_a1_transport_identity_record,
)

# Updated with each accepted Gate A3 preflight packet (same discipline as Gate A0).
ACCEPTED_A3_COMMIT = "5c402c74272aac1ad9f529f58f28f50640545df1"
ACCEPTED_A3_SHA256 = "a81958cada36dd9a1f8dc199369096e9df7a10ed78e6e9c002948b111c3ad2f1"
ACCEPTED_A3_BYTES = 5019
ACCEPTED_A3_PATH = "tools/dragonfly_canary_redrix_preflight.py"
ACCEPTED_A3_URL = (
    "https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/"
    + ACCEPTED_A3_COMMIT
    + "/"
    + ACCEPTED_A3_PATH
)
ACCEPTED_INSTALLER_COMMIT = "98613ad38d36c16b71ed19f270ebec397d8c8f8e"
ACCEPTED_INSTALLER_SHA256 = "2ddb5e290270f2536f896b1c1dcaf902c66a64640ac4c4265e7705193fbdd288"
ACCEPTED_INSTALLER_BYTES = 37106
ACCEPTED_INSTALLER_PATH = "tools/dragonfly_canary_redrix_install.py"
ACCEPTED_INSTALLER_URL = (
    "https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/"
    + ACCEPTED_INSTALLER_COMMIT
    + "/"
    + ACCEPTED_INSTALLER_PATH
)
MAX_SOURCE_BYTES = 65536
PYTHON = "/usr/bin/python3"
PYTHON_FLAGS = ("-I", "-B")


class BootstrapInputError(ValueError):
    pass


def build_bootstrap_code(
    *,
    url: str,
    sha256: str,
    exact_bytes: int,
    max_bytes: int,
    installer_url: str,
    installer_sha256: str,
    installer_exact_bytes: int,
    transport_key_sha256: str,
) -> str:
    if not re.fullmatch(
        r"https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[A-Za-z0-9_./-]+",
        url,
    ):
        raise BootstrapInputError("A3_BOOTSTRAP_URL_INVALID")
    if not re.fullmatch(
        r"https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[A-Za-z0-9_./-]+",
        installer_url,
    ):
        raise BootstrapInputError("A3_BOOTSTRAP_INSTALLER_URL_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise BootstrapInputError("A3_BOOTSTRAP_SHA256_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", installer_sha256) is None:
        raise BootstrapInputError("A3_BOOTSTRAP_INSTALLER_SHA256_INVALID")
    if re.fullmatch(r"[0-9a-f]{64}", transport_key_sha256) is None:
        raise BootstrapInputError("A3_EXPECTED_TRANSPORT_KEY_SHA256_INVALID")
    if not isinstance(exact_bytes, int) or isinstance(exact_bytes, bool) or exact_bytes <= 0:
        raise BootstrapInputError("A3_BOOTSTRAP_EXACT_SIZE_INVALID")
    if (
        not isinstance(installer_exact_bytes, int)
        or isinstance(installer_exact_bytes, bool)
        or installer_exact_bytes <= 0
    ):
        raise BootstrapInputError("A3_BOOTSTRAP_INSTALLER_EXACT_SIZE_INVALID")
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes <= 0
        or max_bytes > 1024 * 1024
        or exact_bytes > max_bytes
        or installer_exact_bytes > max_bytes
    ):
        raise BootstrapInputError("A3_BOOTSTRAP_SIZE_LIMIT_INVALID")

    fetch_fn = '''def fetch_pinned(url,expected_sha256,expected_bytes,max_bytes,prefix):
    request=urllib.request.Request(url,headers={"User-Agent":"LDW-Dragonfly-A3/1","Accept":"text/plain"},method="GET")
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
    response=opener.open(request,timeout=10)
    try:
        if getattr(response,"status",None)!=200:
            hold(prefix+"_SOURCE_HTTP_STATUS_INVALID")
        if response.geturl()!=url:
            hold(prefix+"_SOURCE_FINAL_URL_INVALID")
        data=response.read(max_bytes+1)
    finally:
        response.close()
    if len(data)>max_bytes:
        hold(prefix+"_SOURCE_TOO_LARGE")
    if len(data)!=expected_bytes:
        hold(prefix+"_SOURCE_LENGTH_MISMATCH")
    if hashlib.sha256(data).hexdigest()!=expected_sha256:
        hold(prefix+"_SOURCE_SHA256_MISMATCH")
    return data
'''

    return f'''import hashlib,sys,urllib.request
URL={url!r}
EXPECTED_SHA256={sha256!r}
EXPECTED_BYTES={exact_bytes}
INSTALLER_URL={installer_url!r}
INSTALLER_EXPECTED_SHA256={installer_sha256!r}
INSTALLER_EXPECTED_BYTES={installer_exact_bytes}
MAX_BYTES={max_bytes}
TRANSPORT_SHA256={transport_key_sha256!r}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise RuntimeError("A3_SOURCE_REDIRECT_REFUSED")
def hold(code):
    print("DRAGONFLY_GATE_A3_BOOTSTRAP=HOLD")
    print("CLASSIFICATION="+code)
    raise SystemExit(1)
{fetch_fn}
try:
    data=fetch_pinned(URL,EXPECTED_SHA256,EXPECTED_BYTES,MAX_BYTES,"A3")
    installer_data=fetch_pinned(INSTALLER_URL,INSTALLER_EXPECTED_SHA256,INSTALLER_EXPECTED_BYTES,MAX_BYTES,"A3_INSTALLER")
except SystemExit:
    raise
except Exception:
    hold("A3_SOURCE_FETCH_FAILED")
sys.argv=["dragonfly_canary_redrix_preflight.py","--expected-transport-key-sha256",TRANSPORT_SHA256]
namespace={{"__name__":"__main__","__file__":"<memory>","__LDW_VERIFIED_INSTALLER_BYTES__":installer_data}}
try:
    exec(compile(data,"<dragonfly_canary_redrix_preflight.py>","exec"),namespace)
except SystemExit:
    raise
except Exception:
    hold("A3_HELPER_EXECUTION_FAILED")
'''


def render_command(
    *,
    gate_a1_transport_private_key: Path,
    gate_a1_transport_identity_record: Path,
    gate_a1_transport_private_key_baseline_sha256: str,
) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", gate_a1_transport_private_key_baseline_sha256) is None:
        raise BootstrapInputError("GATE_A1_TRANSPORT_PRIVATE_KEY_BASELINE_INVALID")
    try:
        transport_key_sha256 = derive_bound_transport_public_identity(
            gate_a1_transport_private_key,
            baseline_sha256=gate_a1_transport_private_key_baseline_sha256,
        )
        record_text = gate_a1_transport_identity_record.read_text(encoding="utf-8")
        record_digest = parse_gate_a1_transport_identity_record(record_text)
        if record_digest != transport_key_sha256:
            raise BootstrapInputError("GATE_A1_TRANSPORT_IDENTITY_RECORD_MISMATCH")
    except TransportIdentityError as exc:
        raise BootstrapInputError(str(exc)) from exc
    except ValueError as exc:
        raise BootstrapInputError(str(exc)) from exc

    code = build_bootstrap_code(
        url=ACCEPTED_A3_URL,
        sha256=ACCEPTED_A3_SHA256,
        exact_bytes=ACCEPTED_A3_BYTES,
        max_bytes=MAX_SOURCE_BYTES,
        installer_url=ACCEPTED_INSTALLER_URL,
        installer_sha256=ACCEPTED_INSTALLER_SHA256,
        installer_exact_bytes=ACCEPTED_INSTALLER_BYTES,
        transport_key_sha256=transport_key_sha256,
    )
    argv = [PYTHON, *PYTHON_FLAGS, "-c", code]
    return shlex.join(argv)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render immutable in-memory REDRIX Gate A3 preflight command")
    parser.add_argument(
        "--gate-a1-transport-private-key",
        type=Path,
        required=True,
        help="Gate A1 protected LDW01 transport private key (bound derivation source)",
    )
    parser.add_argument(
        "--gate-a1-transport-identity-record",
        type=Path,
        required=True,
        help="Gate A1 audit record; must match bound derivation against the accepted baseline",
    )
    parser.add_argument(
        "--gate-a1-transport-private-key-baseline-sha256",
        required=True,
        help="SHA-256 of accepted Gate A1 transport private key bytes (independent trust anchor)",
    )
    args = parser.parse_args()
    try:
        command = render_command(
            gate_a1_transport_private_key=args.gate_a1_transport_private_key,
            gate_a1_transport_identity_record=args.gate_a1_transport_identity_record,
            gate_a1_transport_private_key_baseline_sha256=args.gate_a1_transport_private_key_baseline_sha256,
        )
    except BootstrapInputError as exc:
        print("DRAGONFLY_GATE_A3_BOOTSTRAP_RENDER=HOLD")
        print("CLASSIFICATION=" + str(exc))
        return 1
    print("DRAGONFLY_GATE_A3_BOOTSTRAP_RENDER=PASS")
    print("TRANSPORT_KEY_PROVENANCE=" + TRANSPORT_KEY_PROVENANCE)
    print(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
