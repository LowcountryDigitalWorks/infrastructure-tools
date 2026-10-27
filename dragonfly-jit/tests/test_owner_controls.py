import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


controls = load("owner_controls", ROOT / "owner_controls.py")
installer = load("install_owner_controls", ROOT / "install_owner_controls.py")


class OwnerControlTests(unittest.TestCase):
    def test_desktop_contract_is_exactly_three_owner_controls(self):
        self.assertEqual(
            [
                "Start LDW Runner",
                "Drain & Stop LDW Runner",
                "LDW Runner Status",
            ],
            [spec[1] for spec in installer.DESKTOP_SPECS],
        )
        self.assertEqual(
            {"start", "drain", "status"},
            {spec[2] for spec in installer.DESKTOP_SPECS},
        )

    def test_install_creates_exactly_three_desktop_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            result = installer.install(
                source_dir=ROOT,
                home=home,
                python_path=Path("/usr/bin/python3"),
            )
            desktop_dir = home / installer.DESKTOP_SUBDIR
            files = sorted(path.name for path in desktop_dir.glob("ldw-runner-*.desktop"))
            self.assertEqual(sorted(spec[0] for spec in installer.DESKTOP_SPECS), files)
            self.assertEqual("INSTALLED", result["result"])
            for filename, name, control, linger, _comment in installer.DESKTOP_SPECS:
                text = (desktop_dir / filename).read_text()
                self.assertIn(f"Name={name}\n", text)
                self.assertIn(f"X-LDW-Control={control}\n", text)
                self.assertIn(f" {control} --linger-seconds {linger}\n", text)
                self.assertIn("Terminal=true\n", text)
                self.assertNotIn(" smoke ", text)
                self.assertNotIn(" recover ", text)

            check = installer.check(home=home)
            self.assertEqual("PASS", check["result"])

    def test_installer_refuses_unknown_ldw_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            desktop_dir = home / installer.DESKTOP_SUBDIR
            desktop_dir.mkdir(parents=True)
            (desktop_dir / "ldw-runner-emergency.desktop").write_text("[Desktop Entry]\n")
            with self.assertRaisesRegex(installer.InstallError, "UNKNOWN_LDW_LAUNCHER_REFUSED"):
                installer.install(
                    source_dir=ROOT,
                    home=home,
                    python_path=Path("/usr/bin/python3"),
                )

    def test_status_format_is_bounded_and_ignores_unrecognized_fields(self):
        text = controls.format_result(
            "status",
            {
                "marker": controls.MARKER,
                "state": "AVAILABLE",
                "reason": None,
                "visible_cpus": 12,
                "mem_available_mib": 12000,
                "free_disk_gib": 80,
                "load_fraction": 0.1,
                "residue_count": 0,
                "base_present": True,
                "secret": "must-not-render",
            },
        )
        self.assertIn("LDW Runner: AVAILABLE", text)
        self.assertIn("Visible CPUs: 12", text)
        self.assertNotIn("must-not-render", text)
        self.assertNotIn("secret", text)

    def test_controller_error_is_reduced_to_bounded_reason(self):
        completed = subprocess.CompletedProcess(
            ["python3"], 2, stdout="", stderr="sensitive path\nERROR:CAPACITY_MEMORY\n"
        )
        with mock.patch.object(controls.subprocess, "run", return_value=completed), \
             mock.patch.object(Path, "is_file", return_value=True), \
             mock.patch.object(Path, "is_symlink", return_value=False):
            rc, payload, error = controls.run_controller("start", controller=Path("/tmp/controller.py"))
        self.assertEqual(2, rc)
        self.assertIsNone(payload)
        self.assertEqual("ERROR:CAPACITY_MEMORY", error)

    def test_linger_is_bounded(self):
        self.assertEqual(2, controls.main(["status", "--linger-seconds", "31"]))


if __name__ == "__main__":
    unittest.main()
