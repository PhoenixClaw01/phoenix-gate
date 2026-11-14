#!/usr/bin/env python3
"""Allow a merge only when a verdict says PASS for the exact current head.

A PASS with a non-empty blocking list is refused. A PASS whose author_id
and reviewer_id are both present and equal is refused. The verdict file
is caller-supplied JSON or text. This script does not open the network,
does not read credentials, and does not merge.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SHA_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")
VERDICT_RE = re.compile(r"PASS|FAIL", re.IGNORECASE)


class GateError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def normalize_sha(value: object) -> str:
    if not isinstance(value, str):
        raise GateError("bad-verdict")
    token = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", token) is None:
        raise GateError("bad-verdict")
    return token


def whole_verdict(token: str) -> str | None:
    if VERDICT_RE.fullmatch(token) is None:
        return None
    return token.upper()


def find_sha(text: str) -> str | None:
    match = SHA_RE.search(text)
    if match is None:
        return None
    return match.group(1).lower()


class VerdictRecord:
    def __init__(
        self,
        verdict: str,
        sha: str | None,
        *,
        blocking_open: bool = False,
        author_id: str | None = None,
        reviewer_id: str | None = None,
    ) -> None:
        self.verdict = verdict
        self.sha = sha
        self.blocking_open = blocking_open
        self.author_id = author_id
        self.reviewer_id = reviewer_id


def _optional_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise GateError("bad-verdict")
    token = value.strip()
    return token or None


def _blocking_open(value: object) -> bool:
    if value is None:
        return False
    if not isinstance(value, list):
        raise GateError("bad-verdict")
    return len(value) > 0


def _text_blocking(value: str) -> bool:
    return value.strip().lower() not in ("", "[]", "0", "none")


def _same_party(author_id: str | None, reviewer_id: str | None) -> bool:
    return author_id is not None and reviewer_id is not None and author_id == reviewer_id


def parse_verdict(text: str) -> list[VerdictRecord]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise GateError("bad-verdict") from exc
        if not isinstance(data, dict):
            raise GateError("bad-verdict")
        record = _record_from_json(data)
        if record is None:
            return []
        return [record]
    return _parse_text(stripped)


def _record_from_json(data: dict) -> VerdictRecord | None:
    sha = None
    if "sha" in data and data.get("sha") not in (None, ""):
        sha = normalize_sha(data["sha"])
    tokens = str(data.get("verdict", "")).split()
    verdict = whole_verdict(tokens[0]) if tokens else None
    if verdict is None:
        return None
    author_id = _optional_id(data["author_id"]) if "author_id" in data else None
    reviewer_id = _optional_id(data["reviewer_id"]) if "reviewer_id" in data else None
    blocking_open = _blocking_open(data["blocking"]) if "blocking" in data else False
    return VerdictRecord(
        verdict,
        sha,
        blocking_open=blocking_open,
        author_id=author_id,
        reviewer_id=reviewer_id,
    )


def _parse_text(text: str) -> list[VerdictRecord]:
    records: list[VerdictRecord] = []
    pending_verdict: str | None = None
    pending_sha: str | None = None
    saw_sha = False
    pending_author: str | None = None
    pending_reviewer: str | None = None
    pending_blocking = False

    def take_side() -> tuple[bool, str | None, str | None]:
        nonlocal pending_author, pending_reviewer, pending_blocking
        side = (pending_blocking, pending_author, pending_reviewer)
        pending_author = None
        pending_reviewer = None
        pending_blocking = False
        return side

    def emit(verdict: str, sha: str | None) -> None:
        blocking_open, author_id, reviewer_id = take_side()
        records.append(
            VerdictRecord(
                verdict,
                sha,
                blocking_open=blocking_open,
                author_id=author_id,
                reviewer_id=reviewer_id,
            )
        )

    def flush() -> None:
        nonlocal pending_verdict, pending_sha, saw_sha
        if pending_verdict is None:
            pending_sha = None
            saw_sha = False
            return
        if saw_sha and pending_sha is None:
            raise GateError("bad-verdict")
        emit(pending_verdict, pending_sha)
        pending_verdict = None
        pending_sha = None
        saw_sha = False

    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        lower = raw.lower()
        if lower.startswith("author_id:"):
            pending_author = _optional_id(raw.split(":", 1)[1])
            continue
        if lower.startswith("reviewer_id:"):
            pending_reviewer = _optional_id(raw.split(":", 1)[1])
            continue
        if lower.startswith("blocking:"):
            pending_blocking = _text_blocking(raw.split(":", 1)[1])
            continue
        if lower.startswith("verdict:"):
            if pending_verdict is not None:
                flush()
            value = raw.split(":", 1)[1].strip().split()
            pending_verdict = whole_verdict(value[0]) if value else None
            continue
        if lower.startswith("sha:"):
            token = raw.split(":", 1)[1].strip()
            found = find_sha(token)
            if token and found is None:
                raise GateError("bad-verdict")
            if saw_sha and pending_verdict is not None:
                flush()
            pending_sha = found
            saw_sha = True
            continue
        verdict = None
        for token in raw.split():
            verdict = whole_verdict(token)
            if verdict is not None:
                break
        if verdict is None:
            continue
        flush()
        emit(verdict, find_sha(raw))
    flush()
    if records and (pending_blocking or pending_author is not None or pending_reviewer is not None):
        last = records[-1]
        records[-1] = VerdictRecord(
            last.verdict,
            last.sha,
            blocking_open=last.blocking_open or pending_blocking,
            author_id=last.author_id if last.author_id is not None else pending_author,
            reviewer_id=last.reviewer_id if last.reviewer_id is not None else pending_reviewer,
        )
    return records


def evaluate(records: list[VerdictRecord], head: str) -> dict[str, object]:
    current = head.lower()
    # Last PASS or FAIL for this sha wins. A FAIL with no sha counts too,
    # so a later FAIL overrides an earlier PASS.
    last_for_head: VerdictRecord | None = None
    for record in records:
        if record.verdict == "PASS" and record.sha == current:
            last_for_head = record
        elif record.verdict == "FAIL" and record.sha in (current, None):
            last_for_head = record
    if last_for_head is not None and last_for_head.verdict == "PASS":
        if last_for_head.blocking_open:
            decision, reason, approved = "refuse", "blocking", False
        elif _same_party(last_for_head.author_id, last_for_head.reviewer_id):
            decision, reason, approved = "refuse", "author-is-reviewer", False
        else:
            decision, reason, approved = "allow", "pass", True
    elif last_for_head is not None and last_for_head.verdict == "FAIL":
        decision, reason, approved = "refuse", "no-pass", False
    elif any(record.verdict == "PASS" and record.sha not in (None, current) for record in records):
        decision, reason, approved = "refuse", "stale", False
    elif any(record.verdict == "PASS" and record.sha is None for record in records):
        decision, reason, approved = "refuse", "missing-sha", False
    else:
        decision, reason, approved = "refuse", "no-pass", False
    return {"decision": decision, "reason": reason, "head": current, "approved": approved}


def format_result(result: dict[str, object], *, dry_run: bool) -> str:
    approved = False if dry_run else bool(result["approved"])
    lines = []
    if dry_run:
        lines.append("dry-run")
    lines.extend(
        [
            f"decision: {result['decision']}",
            f"reason: {result['reason']}",
            f"head: {result['head']}",
            f"approved: {str(approved).lower()}",
            "",
        ]
    )
    return "\n".join(lines)


def read_local_head(cwd: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(cwd), "rev-parse", "--verify", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CEILING_DIRECTORIES": str(cwd)},
    )
    if completed.returncode != 0:
        raise GateError("bad-head")
    try:
        return normalize_sha(completed.stdout.strip())
    except GateError:
        raise GateError("bad-head") from None


def main(argv: list[str] | None = None, *, cwd: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a reviewer verdict against the current head.")
    parser.add_argument("--verdict", required=True, help="JSON or text verdict file")
    parser.add_argument("--head", default=None, help="Current head sha. Defaults to local git HEAD.")
    parser.add_argument("--dry-run", action="store_true", help="Print the decision without approving.")
    args = parser.parse_args(argv)
    work = cwd or Path.cwd()
    try:
        if args.head is not None:
            try:
                head = normalize_sha(args.head)
            except GateError:
                raise GateError("bad-head") from None
        else:
            head = read_local_head(work)
    except GateError as exc:
        print(f"head is not usable ({exc.reason})", file=sys.stderr)
        return 2
    verdict_path = Path(args.verdict)
    if not verdict_path.is_file():
        print(f"verdict file is missing: {verdict_path}", file=sys.stderr)
        return 2
    try:
        records = parse_verdict(verdict_path.read_text(encoding="utf-8"))
    except (GateError, UnicodeDecodeError):
        print("verdict is not readable", file=sys.stderr)
        return 2
    result = evaluate(records, head)
    print(format_result(result, dry_run=args.dry_run), end="")
    return 0 if result["decision"] == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main())
