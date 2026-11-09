"""Emit a release-neutral provenance manifest for CI or local verification."""
from __future__ import annotations

import argparse
import pathlib
import sys

from provenance_contract import (
    build_release_neutral_manifest,
    dumps_manifest,
    loads_manifest,
    validate_manifest_document,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_MANIFEST = ROOT / "app" / "src" / "main" / "AndroidManifest.xml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--git-tree", required=True)
    parser.add_argument("--pr-source-head")
    parser.add_argument("--apk", type=pathlib.Path, required=True)
    parser.add_argument("--validate-only", type=pathlib.Path)
    args = parser.parse_args(argv)
    if args.validate_only is not None:
        text = args.validate_only.read_text(encoding="utf-8")
        manifest = loads_manifest(text)
        validate_manifest_document(
            manifest,
            expected_commit=args.git_commit,
            expected_tree=args.git_tree,
            expected_pr_head=args.pr_source_head,
            expected_apk_sha256=manifest["artifacts"][0]["sha256"],
            diagnostic_root=ROOT,
        )
        return 0
    manifest = build_release_neutral_manifest(
        git_commit=args.git_commit,
        git_tree=args.git_tree,
        pr_source_head=args.pr_source_head,
        apk_path=args.apk,
        diagnostic_root=ROOT,
        source_manifest_path=SOURCE_MANIFEST,
    )
    validate_manifest_document(
        manifest,
        expected_commit=args.git_commit,
        expected_tree=args.git_tree,
        expected_pr_head=args.pr_source_head,
        expected_apk_sha256=manifest["artifacts"][0]["sha256"],
        diagnostic_root=ROOT,
    )
    sys.stdout.write(dumps_manifest(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
