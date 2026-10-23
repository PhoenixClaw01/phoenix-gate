#!/usr/bin/env python3
"""Read-only comparison of a directory to a path manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def parse_manifest(path: Path) -> list[str]:
    rows: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("/") or ".." in Path(line).parts:
            raise ValueError(f"manifest path must stay inside the root: {line}")
        rows.append(Path(line).as_posix())
    return rows


def scan(root: Path, expected: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for rel in expected:
        target = root / rel
        if not target.is_file():
            findings.append(
                {
                    "severity": "high",
                    "check": "repo-drift",
                    "path": rel,
                    "detail": "missing from the tree",
                }
            )
    findings.sort(key=lambda row: (SEVERITY_ORDER.index(row["severity"]), row["path"]))
    return findings


def render(findings: list[dict[str, str]]) -> str:
    lines = ["# Findings", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines.append("| severity | check | path | detail |")
    lines.append("| --- | --- | --- | --- |")
    for row in findings:
        lines.append(f"| {row['severity']} | {row['check']} | {row['path']} | {row['detail']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare a directory to a manifest. Read-only.")
    parser.add_argument("--root", required=True, help="Directory under audit. Nothing is written.")
    parser.add_argument("--manifest", required=True, help="Text file of relative paths.")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    manifest = Path(args.manifest)
    if not root.is_dir():
        print(f"repo-drift: {root} is not a directory", file=sys.stderr)
        return 2
    try:
        expected = parse_manifest(manifest)
    except ValueError as exc:
        print(f"repo-drift: {exc}", file=sys.stderr)
        return 2
    findings = scan(root, expected)
    sys.stdout.write(render(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
