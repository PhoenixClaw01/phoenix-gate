#!/usr/bin/env python3
"""Redact generic patterns from text, plus an optional phrase file.

Missing phrase file: scrub the generic patterns and continue.
This script does not open the network and does not write files.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REDACTION = "[redacted]"
DEFAULT_PHRASES = Path("phrases.local.txt")

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    (
        "phone",
        re.compile(r"(?<!\d)(?:\+\d{1,3}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    ),
    (
        "uuid",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
    ),
    (
        "private-key",
        re.compile(
            r"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?-----END \1PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "labeled-secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*\S+"
        ),
    ),
    ("project-id", re.compile(r"\bprj_[A-Za-z0-9]{8,}\b")),
    ("team-id", re.compile(r"\bteam_[A-Za-z0-9]{8,}\b")),
    ("hex-wallet", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("opaque-wallet", re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")),
)


def parse_phrases(text: str) -> list[str]:
    phrases: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        phrases.append(stripped)
    return phrases


def load_phrases(path: Path | None) -> list[str]:
    if path is None or not path.is_file():
        return []
    return parse_phrases(path.read_text(encoding="utf-8"))


def hits(text: str, phrases: list[str] | None = None) -> list[str]:
    found = [name for name, pattern in PATTERNS if pattern.search(text)]
    for phrase in phrases or []:
        if phrase and re.search(re.escape(phrase), text, re.IGNORECASE):
            found.append(f"phrase:{phrase}")
    return found


def _spans(text: str, phrases: list[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for _name, pattern in PATTERNS:
        spans.extend(match.span() for match in pattern.finditer(text))
    for phrase in phrases:
        if not phrase:
            continue
        spans.extend(match.span() for match in re.finditer(re.escape(phrase), text, re.IGNORECASE))
    spans.sort(key=lambda span: (span[0], span[0] - span[1]))
    chosen: list[tuple[int, int]] = []
    last_end = -1
    for start, end in spans:
        if start < last_end:
            continue
        chosen.append((start, end))
        last_end = end
    return chosen


def scrub(text: str, phrases: list[str] | None = None) -> str:
    extra = list(phrases or [])
    pieces: list[str] = []
    cursor = 0
    for start, end in _spans(text, extra):
        pieces.append(text[cursor:start])
        pieces.append(REDACTION)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Redact generic patterns from a text file.")
    parser.add_argument("--input", required=True, help="Text file to scrub")
    parser.add_argument(
        "--phrases",
        default=None,
        help="Optional phrase file. When omitted, phrases.local.txt is used if it exists.",
    )
    args = parser.parse_args(argv)
    source = Path(args.input)
    if not source.is_file():
        print(f"input is not a file: {source}", file=sys.stderr)
        return 2
    phrase_path = Path(args.phrases) if args.phrases else DEFAULT_PHRASES
    if args.phrases and not phrase_path.is_file():
        print(f"phrase file is missing: {phrase_path}", file=sys.stderr)
        return 2
    phrases = load_phrases(phrase_path)
    print(scrub(source.read_text(encoding="utf-8"), phrases), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
