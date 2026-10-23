#!/usr/bin/env python3
"""Read-only freshness check for a watcher status file."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    stamp = datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def assess(payload: dict, max_age: timedelta, now: datetime) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    name = str(payload.get("name") or "").strip()
    if not name:
        findings.append(
            {
                "severity": "high",
                "check": "watcher-health",
                "path": "name",
                "detail": "status name is empty",
            }
        )
    if payload.get("read_only") is not True:
        findings.append(
            {
                "severity": "critical",
                "check": "watcher-health",
                "path": "read_only",
                "detail": "watcher is not marked read-only",
            }
        )
    raw = payload.get("last_ok")
    if not isinstance(raw, str) or not raw.strip():
        findings.append(
            {
                "severity": "critical",
                "check": "watcher-health",
                "path": "last_ok",
                "detail": "last success timestamp is missing",
            }
        )
        return findings
    try:
        last_ok = parse_timestamp(raw)
    except ValueError:
        findings.append(
            {
                "severity": "critical",
                "check": "watcher-health",
                "path": "last_ok",
                "detail": "last success timestamp is not a UTC time",
            }
        )
        return findings
    age = now - last_ok
    if age > max_age:
        findings.append(
            {
                "severity": "high",
                "check": "watcher-health",
                "path": name or "last_ok",
                "detail": f"last success is older than {int(max_age.total_seconds() // 3600)} hours",
            }
        )
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
    parser = argparse.ArgumentParser(description="Check a watcher status file. Read-only.")
    parser.add_argument("--status", required=True, help="JSON status file. Nothing is written.")
    parser.add_argument("--max-age-hours", type=int, default=168)
    args = parser.parse_args(argv)
    if args.max_age_hours < 1:
        print("watcher-health: --max-age-hours must be >= 1", file=sys.stderr)
        return 2
    path = Path(args.status)
    if not path.is_file():
        sys.stdout.write(
            render(
                [
                    {
                        "severity": "critical",
                        "check": "watcher-health",
                        "path": path.as_posix(),
                        "detail": "status file is missing",
                    }
                ]
            )
        )
        return 1
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("watcher-health: status file is not JSON", file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print("watcher-health: status file must be an object", file=sys.stderr)
        return 2
    findings = assess(payload, timedelta(hours=args.max_age_hours), datetime.now(timezone.utc))
    sys.stdout.write(render(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
