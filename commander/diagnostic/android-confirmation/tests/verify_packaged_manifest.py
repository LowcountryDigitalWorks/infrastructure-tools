"""Check aapt xmltree output. Does not contact a device."""
import sys


def assert_packaged_manifest(xml: str) -> None:
    if "uses-permission" in xml:
        raise SystemExit("packaged manifest declared a permission")
    for attr_id, label in (
        ("0x01010280", "allowBackup"),
        ("0x010104ec", "usesCleartextTraffic"),
    ):
        hits = [line for line in xml.splitlines() if attr_id in line]
        if len(hits) != 1:
            raise SystemExit(f"missing {label}")
        line = hits[0]
        if "0xffffffff" in line or "=true" in line:
            raise SystemExit(f"{label} is not false")
        if not (line.rstrip().endswith("0x0") or "=false" in line):
            raise SystemExit(f"{label} was not a false flag: {line}")


if __name__ == "__main__":
    assert_packaged_manifest(sys.stdin.read())
