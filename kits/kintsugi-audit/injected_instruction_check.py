#!/usr/bin/env python3
"""Read-only scan for injected instructions. Prints severity-ranked findings."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Needles are joined at runtime so this file does not contain the phrase it detects.
RULES = (
    ("critical", ("ignore previous ", "instructions")),
    ("critical", ("ignore all ", "previous")),
    ("critical", ("ignore prior ", "instructions")),
    ("high", ("disregard the ", "above")),
    ("high", ("you are ", "now")),
    ("high", ("new ", "instructions:")),
    ("high", ("do not tell ", "the user")),
    ("medium", ("act as if you have ", "no restrictions")),
)

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".html",
    ".xml",
    ".csv",
}


def needle(parts: tuple[str, ...]) -> str:
    return "".join(parts).lower()


def iter_text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        yield path


def scan(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    compiled = [(severity, needle(parts)) for severity, parts in RULES]
    for path in iter_text_files(root):
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        rel = path.relative_to(root).as_posix()
        for severity, phrase in compiled:
            if phrase in text:
                findings.append(
                    {
                        "severity": severity,
                        "check": "injected-instruction",
                        "path": rel,
                        "detail": phrase,
                    }
                )
    findings.sort(key=lambda row: (SEVERITY_ORDER.index(row["severity"]), row["path"], row["detail"]))
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
    parser = argparse.ArgumentParser(description="Scan text files for injected instructions. Read-only.")
    parser.add_argument("--root", required=True, help="Directory to scan. Nothing is written.")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"injected-instruction: {root} is not a directory", file=sys.stderr)
        return 2
    findings = scan(root)
    sys.stdout.write(render(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
