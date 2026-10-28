from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'operations-bridge' / 'scripts' / 'redrix-systemd-credential-feasibility.sh'


def text() -> str:
    value = HELPER.read_text(encoding='utf-8')
    assert value.startswith('#!/usr/bin/env bash\nset -euo pipefail\nset +x\numask 077\n')
    return value


def compile_embedded_python(value: str) -> None:
    blocks = re.findall(r"(?:\"\$PYTHON3\"|\$PYTHON3)\s+-\s+<<'PY'\n(.*?)\nPY(?:\n|\))", value, flags=re.S)
    assert blocks, 'no embedded Python blocks found'
    for index, block in enumerate(blocks, 1):
        compile(block, f'<systemd-credential-python-{index}>', 'exec')


def test_contract() -> None:
    value = text()
    subprocess.run(['bash', '-n', str(HELPER)], check=True)
    compile_embedded_python(value)

    # This candidate is synthetic-only and must not create/configure the real
    # host/security/runtime boundary by itself.
    forbidden = [
        r'\bsudo\b',
        r'\bapt(?:-get)?\b',
        r'\bdpkg\b',
        r'\bsystemd-creds\s+setup\b',
        r'\bsystemctl\s+(?:enable|disable|start|stop|restart|mask|unmask)\b',
        r'\btailscale\s+(?:up|set|serve|funnel|ssh)\b',
        r'\bssh\b',
        r'\bscp\b',
        r'\bsecret-tool\s+(?:store|clear|lookup)\b',
        r'authorized_keys\s*(?:>|>>)',
        r'known_hosts\s*(?:>|>>)',
        r'\biptables\b',
        r'\bnft\b',
        r'\bufw\b',
        r'--with-key=(?:null|auto-initrd)',
    ]
    for pattern in forbidden:
        assert re.search(pattern, value) is None, pattern

    assert "HOST_KEY='/var/lib/systemd/credential.secret'" in value
    assert "CREDENTIAL_ID='dragonfly-bridge-token'" in value
    assert "[[ -f \"$HOST_KEY\" && ! -L \"$HOST_KEY\" ]]" in value
    assert "st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077" in value

    # Host-key-backed, user-scoped encryption only. The helper must consume an
    # already-authorized host key, never create one.
    assert '--user' in value
    assert '--with-key=host' in value
    assert 'encrypt - "$CIPHER"' in value
    assert 'decrypt "$CIPHER" -' in value
    assert 'systemd-creds setup' not in value
    assert "HOST_CREDENTIAL_KEY_CREATED=no" in value

    # Synthetic secret only; no production Bridge identity/lookup path appears.
    assert 'secrets.token_hex(32)' in value
    assert 'dragonfly-redrix-01' not in value
    assert 'ldw-operations-bridge' not in value
    assert 'secret-tool' not in value
    assert 'REAL_BRIDGE_BEARER_TOUCHED=no' in value

    # The service-manager proof must consume LoadCredentialEncrypted and expose
    # only a SHA-256 digest of credential bytes.
    assert '"$SYSTEMD_RUN"' in value
    assert '--user' in value
    assert '--property="LoadCredentialEncrypted=$CREDENTIAL_ID:$CIPHER"' in value
    assert 'CREDENTIALS_DIRECTORY' in value
    assert 'hashlib.sha256(data).hexdigest()' in value
    assert 'SYSTEMD_USER_SERVICE_CREDENTIAL=PASS' in value

    # Preserve runtime cleanliness and deterministic cleanup.
    assert "JIT_BASELINE=PASS" in value
    assert "JIT_FINAL_STATE=PASS" in value
    assert "SYNTHETIC_SECRET_RESIDUE=NONE" in value
    assert 'SYNTHETIC=\'\'' in value
    assert 'unset SYNTHETIC' in value
    assert 'rm -rf -- "$WORK"' in value
    assert 'SYSTEMD_CREDENTIAL_FEASIBILITY=PASS' in value

    # No network activity is part of this proof.
    for needle in ('curl ', 'wget ', 'ssh ', 'tailscale ', 'nc ', 'socat '):
        assert needle not in value


if __name__ == '__main__':
    test_contract()
    print('REDRIX_SYSTEMD_CREDENTIAL_HELPER_CONTRACT=PASS')
