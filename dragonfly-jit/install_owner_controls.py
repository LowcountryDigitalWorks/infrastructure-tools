#!/usr/bin/env python3
"""Install exactly three user-level Dragonfly owner controls.

The installer copies the local controller/presentation scripts into a user-owned
application directory and creates exactly three ChromeOS-visible Linux launchers.
It creates no daemon, schedule, provider integration, credential, or network listener.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import tempfile

MARKER = "CI-RUNNER-DRAGONFLY-JIT-001"
INSTALL_SUBDIR = Path(".local/lib/ldw-dragonfly-jit")
DESKTOP_SUBDIR = Path(".local/share/applications")
OWNED_DESKTOP_GLOB = "ldw-runner-*.desktop"
_SAFE_EXEC_PATH = re.compile(r"^[A-Za-z0-9_./+-]+$")

DESKTOP_SPECS = (
    ("ldw-runner-start.desktop", "Start LDW Runner", "start", 6,
     "Make Dragonfly execution capacity locally AVAILABLE after admission checks."),
    ("ldw-runner-drain-stop.desktop", "Drain & Stop LDW Runner", "drain", 8,
     "Stop new Dragonfly work; let accepted current work finish before STOPPED."),
    ("ldw-runner-status.desktop", "LDW Runner Status", "status", 12,
     "Show bounded Dragonfly runner state and local resource/admission summary."),
)


class InstallError(RuntimeError):
    pass


def _assert_no_symlink(path: Path, *, allow_missing_leaf: bool = False) -> None:
    path = path.expanduser().absolute()
    cursor = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        is_leaf = index == len(parts) - 1
        if not cursor.exists() and not cursor.is_symlink():
            if is_leaf and allow_missing_leaf:
                return
            continue
        if cursor.is_symlink():
            raise InstallError(f"SYMLINK_PATH_REFUSED:{cursor}")


def _safe_exec_path(path: Path) -> str:
    value = str(path.expanduser().absolute())
    if not _SAFE_EXEC_PATH.fullmatch(value):
        raise InstallError("UNSAFE_EXEC_PATH")
    return value


def _atomic_write(path: Path, content: str, mode: int) -> None:
    _assert_no_symlink(path.parent, allow_missing_leaf=True)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_no_symlink(path.parent)
    _assert_no_symlink(path, allow_missing_leaf=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, mode)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _atomic_copy(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise InstallError("SOURCE_FILE_INVALID")
    _atomic_write(destination, source.read_text(encoding="utf-8"), 0o700)


def desktop_text(*, filename: str, name: str, control: str, linger: int,
                 comment: str, python_path: Path, control_path: Path) -> str:
    if control not in {"start", "drain", "status"}:
        raise InstallError("CONTROL_INVALID")
    python_exec = _safe_exec_path(python_path)
    control_exec = _safe_exec_path(control_path)
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={name}\n"
        f"Comment={comment}\n"
        f"Exec={python_exec} {control_exec} {control} --linger-seconds {linger}\n"
        "Terminal=true\n"
        "Icon=utilities-terminal\n"
        "Categories=Utility;\n"
        "StartupNotify=true\n"
        f"X-LDW-Marker={MARKER}\n"
        f"X-LDW-Control={control}\n"
    )


def _owned_desktop_names(desktop_dir: Path) -> set[str]:
    if not desktop_dir.exists():
        return set()
    return {path.name for path in desktop_dir.glob(OWNED_DESKTOP_GLOB)}


def install(*, source_dir: Path, home: Path, python_path: Path) -> dict:
    source_dir = source_dir.expanduser().absolute()
    home = home.expanduser().absolute()
    _assert_no_symlink(source_dir)
    _assert_no_symlink(home)

    install_root = home / INSTALL_SUBDIR
    desktop_dir = home / DESKTOP_SUBDIR
    _assert_no_symlink(install_root, allow_missing_leaf=True)
    _assert_no_symlink(desktop_dir, allow_missing_leaf=True)
    install_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    desktop_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_no_symlink(install_root)
    _assert_no_symlink(desktop_dir)

    expected_names = {spec[0] for spec in DESKTOP_SPECS}
    unknown = _owned_desktop_names(desktop_dir) - expected_names
    if unknown:
        raise InstallError("UNKNOWN_LDW_LAUNCHER_REFUSED")

    _atomic_copy(source_dir / "dragonfly_jit.py", install_root / "dragonfly_jit.py")
    _atomic_copy(source_dir / "owner_controls.py", install_root / "owner_controls.py")

    control_path = install_root / "owner_controls.py"
    for filename, name, control, linger, comment in DESKTOP_SPECS:
        content = desktop_text(
            filename=filename,
            name=name,
            control=control,
            linger=linger,
            comment=comment,
            python_path=python_path,
            control_path=control_path,
        )
        _atomic_write(desktop_dir / filename, content, 0o644)

    return {
        "marker": MARKER,
        "result": "INSTALLED",
        "launchers": [spec[1] for spec in DESKTOP_SPECS],
        "desktop_files": [spec[0] for spec in DESKTOP_SPECS],
        "install_root": str(install_root),
    }


def check(*, home: Path) -> dict:
    home = home.expanduser().absolute()
    desktop_dir = home / DESKTOP_SUBDIR
    expected_names = {spec[0] for spec in DESKTOP_SPECS}
    actual_names = _owned_desktop_names(desktop_dir)
    install_root = home / INSTALL_SUBDIR
    installed_scripts = all(
        (install_root / name).is_file() and not (install_root / name).is_symlink()
        for name in ("dragonfly_jit.py", "owner_controls.py")
    )
    return {
        "marker": MARKER,
        "result": "PASS" if actual_names == expected_names and installed_scripts else "FAIL",
        "desktop_files": sorted(actual_names),
        "scripts_present": installed_scripts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install/check LDW Dragonfly owner controls")
    parser.add_argument("command", choices=("install", "check"))
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--source-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--python", type=Path, default=Path(os.environ.get("PYTHON", "/usr/bin/python3")))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install":
            payload = install(source_dir=args.source_dir, home=args.home, python_path=args.python)
        else:
            payload = check(home=args.home)
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0 if payload.get("result") in {"INSTALLED", "PASS"} else 2
    except InstallError as exc:
        print(f"ERROR:{exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
