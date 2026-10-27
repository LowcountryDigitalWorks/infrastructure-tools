from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
READBACK = ROOT / 'dragonfly-jit' / 'redrix-accepted-main-readback.sh'
PROOF = ROOT / 'operations-bridge' / 'scripts' / 'redrix-credential-free-proof.sh'

EXPECTED = {
    'zip': 'e0091c03c7a0e0c3bdf01c51e8c29fcf70e51788c1a9d3d84a91226cea6b01d4',
    'tar': '27835aad28f13723c831ad4c8d0c5b8a2110cb22eb55e1387199eb8fff960f71',
    'source': 'bcbdfb181f18eacfbceef2bf990c07a0b612915a',
    'adapter': '9ffbfd1dd2ea63fd7eece24e1f3eb791c92da0bf',
}


def text(path: Path) -> str:
    value = path.read_text(encoding='utf-8')
    assert value.startswith('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n')
    return value


def compile_embedded_python(label: str, value: str) -> None:
    blocks = re.findall(r"python3\s+-\s+<<'PY'\n(.*?)\nPY(?:\n|$)", value, flags=re.S)
    assert blocks, f'{label}: no embedded Python blocks found'
    for index, block in enumerate(blocks, 1):
        compile(block, f'<{label}-python-{index}>', 'exec')


def assert_no_mutating_capability_commands(value: str) -> None:
    forbidden = [
        r'\bsudo\b',
        r'\bapt(?:-get)?\b',
        r'\bdpkg\b',
        r'\bsystemctl\s+(?:start|enable|restart|mask|unmask|stop|disable)\b',
        r'\btailscale\s+(?:up|set|serve|funnel|ssh)\b',
        r'\bsecret-tool\s+(?:store|clear)\b',
        r'\bssh-keygen\s+-A\b',
        r'authorized_keys\s*(?:>|>>)',
        r'\biptables\b',
        r'\bnft\b',
        r'\bufw\b',
    ]
    for pattern in forbidden:
        assert re.search(pattern, value) is None, pattern


def test_readback_contract() -> None:
    value = text(READBACK)
    subprocess.run(['bash', '-n', str(READBACK)], check=True)
    compile_embedded_python('readback', value)
    assert_no_mutating_capability_commands(value)
    for expected in EXPECTED.values():
        assert expected in value
    assert "command -v realpath >/dev/null" in value
    assert 'for cmd in sha256sum sha512sum unzip tar python3 mktemp stat awk id head grep basename rm; do' in value
    assert "AUTHORIZED_KEYS_RESTRICT_DOC=probe_tool_missing" in value
    assert 'tailscale status --json' in value
    assert '/usr/sbin/sshd -V' in value
    assert 'ssh-keygen -lf "$HOST_PUB" -E sha256' in value
    assert 'READBACK_COMPLETE=PASS' in value
    assert 'TailscaleIPs' not in value
    assert 'MagicDNSSuffix' not in value
    assert "d.get('Self')" in value
    assert 'JIT_STATE_ROOT=' in value
    assert "print('JIT_QEMU_PID='+('null' if qemu is None else 'present'))" in value
    assert "print('JIT_RESIDUE_COUNT='+str(residue))" in value
    assert '"$CONTROLLER" status' not in value
    assert 'ensure_roots' in value  # explanatory comment only: why command execution is forbidden


def test_credential_free_proof_contract() -> None:
    value = text(PROOF)
    subprocess.run(['bash', '-n', str(PROOF)], check=True)
    compile_embedded_python('proof', value)
    assert_no_mutating_capability_commands(value)
    for expected in EXPECTED.values():
        assert expected in value
    assert "EXPECTED_BRIDGE_ID='dragonfly-redrix-01'" in value
    assert 'ERROR:BRIDGE_CREDENTIAL_PRESENT_OR_AMBIGUOUS' in value
    assert '/usr/bin/secret-tool lookup service ldw-operations-bridge bridge-id "$EXPECTED_BRIDGE_ID"' in value
    assert '[[ $runtime_rc -eq 6 ]]' in value
    assert "BRIDGE_STATUS_AFTER=blocked" in value
    assert "JIT_FINAL_STATE=PASS" in value
    assert "EXISTING_DRAGONFLY_ASSETS_UNCHANGED=PASS" in value
    rollback = value.index("echo 'ROLLBACK=PASS'")
    terminal = value.index("echo 'CREDENTIAL_FREE_REDRIX_PROOF=PASS'")
    cleanup = value.index('if ! cleanup 0; then')
    assert cleanup < rollback < terminal
    for needle in ('curl ', 'wget ', 'ssh ', 'tailscale ', 'nc ', 'socat '):
        assert needle not in value


if __name__ == '__main__':
    test_readback_contract()
    test_credential_free_proof_contract()
    print('REDRIX_PROOF_HELPER_CONTRACT=PASS')
