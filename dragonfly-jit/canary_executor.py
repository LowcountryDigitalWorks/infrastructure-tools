#!/usr/bin/env python3
"""Execute one claimed Dragonfly GitHub canary without provider authority on REDRIX."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

PROFILE_ID = "dragonfly-github-canary-v1"
CONTROLLER_FILENAME = "dragonfly_jit.py"
EXPECTED_CONTROLLER_GIT_BLOB = "dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a"
MAX_SOURCE_BYTES = 256 * 1024
MAX_BOOTSTRAP_CHARS = 32768
BOOTSTRAP_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
DEFAULT_TIMEOUT_SECONDS = 720

ASSET_SPECS = {
    "bootstrap.sh": (Path("canary-guest/bootstrap.sh"), "0fa167cba3f30652caac3bf822a616f31183d62a"),
    "run-one.sh": (Path("../ci-runner/guest/run-one.sh"), "a17ee1fa2ae307ce142572eb7dff9b2bbcfb56ee"),
    "ci7-runner.service": (Path("../ci-runner/guest/ci7-runner.service"), "b5a7cdad0d7ec457b3aacee59167454a5078022e"),
}


class CanaryExecutorError(RuntimeError):
    pass


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _assert_owned_regular(path: Path, *, expected_blob: str, max_bytes: int = MAX_SOURCE_BYTES) -> bytes:
    path = path.absolute()
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise CanaryExecutorError("CANARY_SOURCE_UNTRUSTED")
    try:
        st = path.stat()
    except OSError as exc:
        raise CanaryExecutorError("CANARY_SOURCE_UNTRUSTED") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > max_bytes:
        raise CanaryExecutorError("CANARY_SOURCE_UNTRUSTED")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise CanaryExecutorError("CANARY_SOURCE_UNTRUSTED")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise CanaryExecutorError("CANARY_SOURCE_UNTRUSTED")
    data = path.read_bytes()
    if _git_blob_sha1(data) != expected_blob:
        raise CanaryExecutorError("CANARY_SOURCE_UNTRUSTED")
    return data


def _load_controller():
    source = Path(__file__).absolute().parent / CONTROLLER_FILENAME
    _assert_owned_regular(source, expected_blob=EXPECTED_CONTROLLER_GIT_BLOB)
    spec = importlib.util.spec_from_file_location("ldw_dragonfly_canary_controller", source)
    if spec is None or spec.loader is None:
        raise CanaryExecutorError("CANARY_CONTROLLER_UNTRUSTED")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise CanaryExecutorError("CANARY_CONTROLLER_UNTRUSTED") from exc
    return module


def _load_guest_assets(source_root: Path | None = None) -> dict[str, str]:
    root = (source_root or Path(__file__).absolute().parent).absolute()
    values: dict[str, str] = {}
    for name, (relative, expected_blob) in ASSET_SPECS.items():
        data = _assert_owned_regular(root / relative, expected_blob=expected_blob)
        try:
            values[name] = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanaryExecutorError("CANARY_SOURCE_UNTRUSTED") from exc
    return values


def _validate_execution_inputs(payload: dict, summary: dict) -> str:
    if not isinstance(payload, dict) or not isinstance(summary, dict):
        raise CanaryExecutorError("CANARY_INPUT_INVALID")
    if payload.get("profile_id") != PROFILE_ID or summary.get("profile_id") != PROFILE_ID:
        raise CanaryExecutorError("CANARY_PROFILE_INVALID")
    fields = (
        "dispatch_id", "target_host", "profile_id", "repository", "workflow", "run_id",
        "run_attempt", "job_id", "head_sha", "job_name", "labels", "issued_at", "expires_at",
    )
    for field in fields:
        if payload.get(field) != summary.get(field):
            raise CanaryExecutorError("CANARY_IDENTITY_MISMATCH")
    if summary.get("bootstrap_present") is not True:
        raise CanaryExecutorError("CANARY_BOOTSTRAP_FLAG_INVALID")
    bootstrap = payload.get("opaque_bootstrap")
    if (
        not isinstance(bootstrap, str)
        or not bootstrap
        or len(bootstrap) > MAX_BOOTSTRAP_CHARS
        or BOOTSTRAP_RE.fullmatch(bootstrap) is None
    ):
        raise CanaryExecutorError("CANARY_BOOTSTRAP_INVALID")
    return bootstrap


def _b64(value: str) -> str:
    return base64.b64encode(value.replace("\r\n", "\n").encode("utf-8")).decode("ascii")


def build_user_data(*, bootstrap: str, run_id: str, assets: dict[str, str]) -> str:
    if not bootstrap or len(bootstrap) > MAX_BOOTSTRAP_CHARS or BOOTSTRAP_RE.fullmatch(bootstrap) is None:
        raise CanaryExecutorError("CANARY_BOOTSTRAP_INVALID")
    if not run_id or set(assets) != set(ASSET_SPECS):
        raise CanaryExecutorError("CANARY_ASSET_SET_INVALID")
    files = (
        ("/run/ci7/jit", "0600", bootstrap),
        ("/run/ci7/run-id", "0444", run_id),
        ("/usr/local/lib/ci7/bootstrap.sh", "0700", assets["bootstrap.sh"]),
        ("/usr/local/lib/ci7/run-one.sh", "0755", assets["run-one.sh"]),
        ("/etc/systemd/system/ci7-runner.service", "0644", assets["ci7-runner.service"]),
    )
    lines = [
        "#cloud-config", "users:", "  - name: ldw-runner", "    lock_passwd: true",
        "    shell: /bin/bash", "    sudo: false", "    groups: []", "ssh_pwauth: false",
        "disable_root: true", "write_files:",
    ]
    for path, mode, data in files:
        lines.extend((
            f"  - path: {path}", f"    permissions: '{mode}'", "    encoding: b64",
            f"    content: {_b64(data)}",
        ))
    lines.extend(("runcmd:", "  - [bash, /usr/local/lib/ci7/bootstrap.sh]", ""))
    return "\n".join(lines)


def _terminate_process(process) -> bool:
    """Return True only when guest death is positively observed."""
    if process is None:
        return True
    try:
        if process.poll() is not None:
            return True
    except Exception:
        return False
    with contextlib.suppress(Exception):
        process.terminate()
    try:
        process.wait(timeout=10)
        return True
    except Exception:
        pass
    with contextlib.suppress(Exception):
        process.kill()
    try:
        process.wait(timeout=5)
        return True
    except Exception:
        try:
            return process.poll() is not None
        except Exception:
            return False


def _remove_owned_bootstrap_material(controller, run_id: str, run_dir: Path) -> None:
    """Unlink only proven owned transient inputs; never remove guest ownership evidence.

    Linux permits unlinking the readonly seed while QEMU holds its FD. This does
    not stop the guest, revoke its open FD, or authorize deleting its overlay.
    The pinned controller validates manifest paths even when the seed is absent.
    """
    manifest = controller._validate_manifest(run_dir)
    if run_dir.name != run_id or manifest.get("run_id") != run_id:
        raise CanaryExecutorError("CANARY_SENSITIVE_ARTIFACT_OWNERSHIP_INVALID")
    if run_dir.parent.resolve(strict=True) != controller.runs_root.resolve(strict=True):
        raise CanaryExecutorError("CANARY_SENSITIVE_ARTIFACT_OWNERSHIP_INVALID")
    if Path(manifest["seed"]).absolute() != (run_dir / "seed.img").absolute():
        raise CanaryExecutorError("CANARY_SENSITIVE_ARTIFACT_OWNERSHIP_INVALID")
    cursor = Path(run_dir.absolute().anchor)
    for part in run_dir.absolute().parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise CanaryExecutorError("CANARY_SENSITIVE_ARTIFACT_OWNERSHIP_INVALID")
    for name in ("user-data", "seed.img"):
        candidate = run_dir / name
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or (hasattr(os, "geteuid") and info.st_uid != os.geteuid()):
            raise CanaryExecutorError("CANARY_SENSITIVE_ARTIFACT_OWNERSHIP_INVALID")
        candidate.unlink()


def execute_canary(
    payload: dict,
    summary: dict,
    *,
    state_root: Path | None = None,
    data_root: Path | None = None,
    controller_module=None,
    source_root: Path | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    bootstrap = _validate_execution_inputs(payload, summary)
    controller_module = controller_module or _load_controller()
    assets = _load_guest_assets(source_root)
    controller = controller_module.Controller(data_root=data_root, state_root=state_root)
    controller.ensure_roots()
    controller.verify_base()
    controller_module.assert_admission(controller_module.resource_snapshot(controller.state_root))
    for tool in ("qemu-img", "cloud-localds", "qemu-system-x86_64"):
        if shutil.which(tool) is None:
            raise CanaryExecutorError("CANARY_TOOL_REQUIRED")

    process = None
    run_id = None
    run_dir = None
    try:
        with controller_module._file_lock(controller.guest_lock_path):
            with controller_module._file_lock(controller.state_lock_path):
                current = controller.read_state()
                if current["state"] != "AVAILABLE":
                    raise CanaryExecutorError("CANARY_HOST_NOT_AVAILABLE")
                if controller._run_dirs():
                    raise CanaryExecutorError("CANARY_STALE_RUN_STATE")

            run_id, run_dir, overlay, seed, user_data, pidfile, _ = controller._new_run()
            # Establish durable ownership before any bootstrap-bearing plaintext is written.
            controller._write_manifest(run_id, run_dir, overlay, seed, pidfile)
            user_data.write_text(build_user_data(bootstrap=bootstrap, run_id=run_id, assets=assets), encoding="utf-8")
            os.chmod(user_data, 0o600)
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(controller.base_path), str(overlay), "8G"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["cloud-localds", str(seed), str(user_data)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            user_data.unlink()

            with controller_module._file_lock(controller.state_lock_path):
                if controller.read_state()["state"] != "AVAILABLE":
                    raise CanaryExecutorError("CANARY_HOST_STATE_CHANGED")
                process = subprocess.Popen(
                    [
                        "qemu-system-x86_64", "-accel", "kvm", "-machine", "q35", "-cpu", "host",
                        "-smp", str(controller_module.GUEST_CPUS), "-m", f"{controller_module.GUEST_MEMORY_MIB}M",
                        "-drive", f"if=virtio,format=qcow2,file={overlay}",
                        "-drive", f"if=virtio,format=raw,readonly=on,file={seed}",
                        "-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0",
                        "-display", "none", "-serial", "none", "-monitor", "none",
                        "-pidfile", str(pidfile), "-no-reboot",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=controller_module._set_parent_death_signal,
                )
                controller._write_manifest(run_id, run_dir, overlay, seed, pidfile, qemu_pid=process.pid)
                controller.write_state("RUNNING", run_id=run_id, qemu_pid=process.pid)

            try:
                rc = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                if not _terminate_process(process):
                    raise CanaryExecutorError("CANARY_GUEST_TERMINATION_UNCERTAIN") from exc
                raise CanaryExecutorError("CANARY_GUEST_TIMEOUT") from exc
            if rc != 0:
                raise CanaryExecutorError("CANARY_QEMU_NONZERO_EXIT")
            # QEMU death is known here. Preserve the original PID evidence until the
            # accepted cleanup guard independently verifies it is no longer live.
            controller._cleanup_owned_run(run_dir)
            with controller_module._file_lock(controller.state_lock_path):
                controller.write_state("STOPPED")
            return {
                "guest_qemu_exit": "PASS",
                "guest_cleanup": "PASS",
                "state": "STOPPED",
                "job_id": summary["job_id"],
                "dispatch_id": summary["dispatch_id"],
            }
    except Exception as original:
        termination_confirmed = _terminate_process(process)
        if run_id is not None and not termination_confirmed:
            qemu_pid = getattr(process, "pid", None)
            sensitive_removed = False
            try:
                # Serialize against other guest/recovery operations, without requiring
                # death and without invoking the destructive owned-run cleanup path.
                with controller_module._file_lock(controller.guest_lock_path, blocking=True):
                    _remove_owned_bootstrap_material(controller, run_id, run_dir)
                sensitive_removed = True
            except Exception:
                pass
            with controller_module._file_lock(controller.state_lock_path):
                controller.write_state(
                    "HOLD",
                    run_id=run_id,
                    qemu_pid=qemu_pid if isinstance(qemu_pid, int) and qemu_pid > 0 else None,
                    reason="CANARY_TERMINATION_UNCERTAIN" if sensitive_removed else "CANARY_SENSITIVE_CLEANUP_UNCERTAIN",
                )
            raise CanaryExecutorError("CANARY_GUEST_TERMINATION_UNCERTAIN") from original

        cleanup_confirmed = False
        if run_dir is not None and run_dir.exists():
            try:
                # Reacquire the guest lock for all destructive failure cleanup. The
                # run manifest/PID evidence remains intact so the controller's live-PID
                # guard remains authoritative.
                with controller_module._file_lock(controller.guest_lock_path, blocking=True):
                    controller._cleanup_owned_run(run_dir)
                cleanup_confirmed = True
            except Exception:
                cleanup_confirmed = False
        elif run_id is None:
            cleanup_confirmed = True

        if run_id is not None:
            with controller_module._file_lock(controller.state_lock_path):
                if cleanup_confirmed:
                    controller.write_state("STOPPED", reason="CANARY_FAILED")
                else:
                    qemu_pid = getattr(process, "pid", None)
                    controller.write_state(
                        "HOLD",
                        run_id=run_id,
                        qemu_pid=qemu_pid if isinstance(qemu_pid, int) and qemu_pid > 0 and not termination_confirmed else None,
                        reason="CANARY_CLEANUP_UNCERTAIN",
                    )
        raise
    finally:
        bootstrap = None
