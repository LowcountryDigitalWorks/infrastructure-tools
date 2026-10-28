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

    # Synthetic-only proof. It may create only one transient systemd-run unit;
    # it must not configure any persistent host/runtime boundary.
    forbidden = [
        r'\bsudo\b',
        r'\bapt(?:-get)?\b',
        r'\bdpkg\b',
        r'\bsystemd-creds\s+setup\b',
        r'\bsystemctl\s+(?:enable|disable|start|stop|restart|mask|unmask|daemon-reload)\b',
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
        r'\bsystemd-run\s+--user\b',
        r'\bsystemctl\s+--user\b',
        r'\bsystemd-creds\s+--user\b',
    ]
    for pattern in forbidden:
        assert re.search(pattern, value) is None, pattern

    # REDRIX/system-manager target identity is fixed and must remain normal-user
    # at payload execution time even though the system manager owns decryption.
    assert "OWNER_USER='eddie'" in value
    assert "OWNER_UID='1000'" in value
    assert "OWNER_HOME='/home/eddie'" in value
    assert '[[ "$(id -u)" == \'0\' ]]' in value
    assert '[[ "$(id -u "$OWNER_USER")" == "$OWNER_UID" ]]' in value
    assert 'pwd.getpwnam' in value
    assert '--property="User=$OWNER_USER"' in value
    assert 'SYSTEMD_SYSTEM_SERVICE_USER=PASS' in value

    # Host key must pre-exist, be root-only, and remain byte/inode-identical.
    assert "HOST_KEY='/var/lib/systemd/credential.secret'" in value
    assert "[[ -f \"$HOST_KEY\" && ! -L \"$HOST_KEY\" ]]" in value
    assert "st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077" in value
    assert "host_inode_before=" in value
    assert "host_digest_before=" in value
    assert "host_inode_after=" in value
    assert "host_digest_after=" in value
    assert 'HOST_CREDENTIAL_KEY_UNCHANGED=PASS' in value
    assert 'systemd-creds setup' not in value
    assert "HOST_CREDENTIAL_KEY_CREATED=no" in value

    # Use system-manager, host-key-backed credentials. The known-broken v257
    # per-user manager path must not reappear.
    assert '--with-key=host' in value
    assert 'encrypt - "$CIPHER"' in value
    assert 'decrypt "$CIPHER" -' in value
    assert '--user' not in value
    assert "(( systemd_version >= 257 ))" in value
    assert 'SYSTEM_MANAGER=PASS' in value
    assert 'SYSTEMD_SYSTEM_ENCRYPT=PASS' in value
    assert 'SYSTEMD_SYSTEM_CLI_DECRYPT_DIGEST=PASS' in value

    # Synthetic secret only; no production Bridge identity/lookup path appears.
    assert "CREDENTIAL_ID='dragonfly-bridge-token'" in value
    assert 'secrets.token_hex(32)' in value
    assert 'dragonfly-redrix-01' not in value
    assert 'ldw-operations-bridge' not in value
    assert 'secret-tool' not in value
    assert 'REAL_BRIDGE_BEARER_TOUCHED=no' in value

    # Transient service consumes LoadCredentialEncrypted and emits only UID +
    # SHA-256 digest. Harden the synthetic payload and forbid network families
    # except local AF_UNIX.
    assert '"$SYSTEMD_RUN"' in value
    assert '--wait' in value and '--collect' in value and '--pipe' in value
    assert '--property="LoadCredentialEncrypted=$CREDENTIAL_ID:$CIPHER"' in value
    assert "--property='NoNewPrivileges=yes'" in value
    assert "--property='PrivateTmp=yes'" in value
    assert "--property='PrivateDevices=yes'" in value
    assert "--property='ProtectSystem=strict'" in value
    assert "--property='ProtectHome=yes'" in value
    assert "--property='RestrictAddressFamilies=AF_UNIX'" in value
    assert 'CREDENTIALS_DIRECTORY' in value
    assert 'hashlib.sha256(data).hexdigest()' in value
    assert 'os.geteuid()' in value
    assert 'SYSTEMD_SYSTEM_SERVICE_CREDENTIAL=PASS' in value
    assert "PERSISTENT_SERVICE_CREATED=no" in value

    # Preserve runtime cleanliness and deterministic cleanup.
    assert "JIT_STATE_ROOT=\"$OWNER_HOME/.local/state/ldw-dragonfly-jit\"" in value
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
