#!/usr/bin/env python3
"""Scan a directory for caller-supplied phrases. Read only.

The phrase file decides what counts as a leak. This script does not ship a
phrase list, does not open the network, and does not write files.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SEVERITY = "high"
CHECK = "public-copy-leak"
SKIP_DIRS = {".git", "__pycache__"}
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".zip",
    ".gz",
    ".woff",
    ".woff2",
    ".ico",
    ".pyc",
}


def parse_phrases(text: str) -> list[str]:
    phrases: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        phrases.append(stripped)
    return phrases


def scan(root: Path, phrases: list[str], skip: Path | None = None) -> list[dict[str, str]]:
    skip_resolved = skip.resolve() if skip is not None else None
    findings: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if skip_resolved is not None and path.resolve() == skip_resolved:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lowered = text.lower()
        rel = path.relative_to(root).as_posix()
        for phrase in phrases:
            if phrase.lower() in lowered:
                findings.append(
                    {
                        "severity": SEVERITY,
                        "check": CHECK,
                        "path": rel,
                        "phrase": phrase,
                    }
                )
    return findings


def format_finding(row: dict[str, str]) -> str:
    return f"{row['severity']}\t{row['check']}\t{row['path']}\t{row['phrase']}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan text files for caller-supplied phrases.")
    parser.add_argument("--root", required=True, help="Directory to scan")
    parser.add_argument("--phrases", required=True, help="Phrase file, one phrase per line")
    args = parser.parse_args(argv)
    root = Path(args.root)
    phrase_path = Path(args.phrases)
    if not root.is_dir():
        print(f"root is not a directory: {root}", file=sys.stderr)
        return 2
    if not phrase_path.is_file():
        print(f"phrase file is missing: {phrase_path}", file=sys.stderr)
        return 2
    phrases = parse_phrases(phrase_path.read_text(encoding="utf-8"))
    if not phrases:
        print("phrase file has no phrases", file=sys.stderr)
        return 2
    findings = scan(root, phrases, skip=phrase_path)
    for row in findings:
        print(format_finding(row))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
