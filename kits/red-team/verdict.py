#!/usr/bin/env python3
"""Validate a red-team verdict against the current head.

The verdict file is caller-supplied JSON. This script does not open the
network, does not read credentials, and does not merge.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")
LANE_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")
PR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,63}")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

REQUIRED_FIELDS = (
    "repo",
    "pr",
    "head_sha",
    "sha",
    "verdict",
    "blocking",
    "kintsugi",
    "reviewer_id",
    "author_id",
    "timestamp",
)
BLOCKING_KINDS = ("attacker-reachable", "leak")
KINTSUGI_SIZES = ("small", "medium", "large")
VERDICTS = ("PASS", "FAIL")


class RedTeamError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def normalize_sha(value: object, *, reason: str = "bad-verdict") -> str:
    if not isinstance(value, str):
        raise RedTeamError(reason)
    token = value.strip().lower()
    if SHA_RE.fullmatch(token) is None:
        raise RedTeamError(reason)
    return token


def check_repo(value: object, *, reason: str = "bad-verdict") -> str:
    if not isinstance(value, str):
        raise RedTeamError(reason)
    token = value.strip()
    if REPO_RE.fullmatch(token) is None:
        raise RedTeamError(reason)
    return token


def same_pr(left: object, right: object) -> bool:
    left_number = isinstance(left, int) and not isinstance(left, bool)
    right_number = isinstance(right, int) and not isinstance(right, bool)
    if left_number and isinstance(right, str) and right.isdigit():
        return left == int(right)
    if right_number and isinstance(left, str) and left.isdigit():
        return right == int(left)
    return left == right


def check_pr(value: object, *, reason: str = "bad-verdict") -> int | str:
    if isinstance(value, bool) or isinstance(value, float):
        raise RedTeamError(reason)
    if isinstance(value, int):
        if value < 1:
            raise RedTeamError(reason)
        return value
    if isinstance(value, str):
        token = value.strip()
        if PR_RE.fullmatch(token) is None:
            raise RedTeamError(reason)
        return token
    raise RedTeamError(reason)


def check_id(value: object, *, reason: str = "bad-verdict") -> str:
    if not isinstance(value, str):
        raise RedTeamError(reason)
    token = value.strip()
    if ID_RE.fullmatch(token) is None:
        raise RedTeamError(reason)
    return token


def check_lane(value: object, *, allow_wildcard: bool, reason: str) -> str:
    if not isinstance(value, str):
        raise RedTeamError(reason)
    token = value.strip()
    if allow_wildcard and token == "*":
        return token
    if LANE_RE.fullmatch(token) is None:
        raise RedTeamError(reason)
    return token


def check_timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise RedTeamError("bad-verdict")
    token = value.strip()
    if TIMESTAMP_RE.fullmatch(token) is None:
        raise RedTeamError("bad-verdict")
    try:
        datetime.strptime(token, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RedTeamError("bad-verdict") from exc
    return token


def _text_line(value: object) -> str:
    if not isinstance(value, str):
        raise RedTeamError("bad-verdict")
    token = value.strip()
    if not token or "\n" in token or "\r" in token or len(token) > 240:
        raise RedTeamError("bad-verdict")
    return token


def _object_fields(value: object, fields: tuple[str, ...]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise RedTeamError("bad-verdict")
    return value


def _blocking_item(value: object) -> dict[str, str]:
    row = _object_fields(value, ("kind", "summary"))
    kind = row["kind"]
    if not isinstance(kind, str) or kind.strip() not in BLOCKING_KINDS:
        raise RedTeamError("bad-verdict")
    return {"kind": kind.strip(), "summary": _text_line(row["summary"])}


def _kintsugi_item(value: object) -> dict[str, str]:
    row = _object_fields(value, ("repair", "size"))
    size = row["size"]
    if not isinstance(size, str) or size.strip() not in KINTSUGI_SIZES:
        raise RedTeamError("bad-verdict")
    return {"repair": _text_line(row["repair"]), "size": size.strip()}


def _item_list(value: object, parse) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise RedTeamError("bad-verdict")
    return [parse(item) for item in value]


def validate_verdict(data: object, *, head: str, repo: str, pr: object) -> dict[str, object]:
    """Return a normalized verdict, or raise RedTeamError.

    `stale` means head_sha is not the current head. `repo-mismatch` and
    `pr-mismatch` mean the document is not for this repo or PR. `sha`
    must equal `head_sha`.
    """
    current = normalize_sha(head, reason="bad-head")
    expected_repo = check_repo(repo, reason="bad-repo")
    expected_pr = check_pr(pr, reason="bad-pr")
    if not isinstance(data, dict) or set(data) != set(REQUIRED_FIELDS):
        raise RedTeamError("bad-verdict")
    verdict = data.get("verdict")
    if not isinstance(verdict, str) or verdict.strip() not in VERDICTS:
        raise RedTeamError("bad-verdict")
    verdict = verdict.strip()
    document: dict[str, object] = {
        "repo": check_repo(data.get("repo")),
        "pr": check_pr(data.get("pr")),
        "head_sha": normalize_sha(data.get("head_sha")),
        "sha": normalize_sha(data.get("sha")),
        "verdict": verdict,
        "blocking": _item_list(data.get("blocking"), _blocking_item),
        "kintsugi": _item_list(data.get("kintsugi"), _kintsugi_item),
        "reviewer_id": check_id(data.get("reviewer_id")),
        "author_id": check_id(data.get("author_id")),
        "timestamp": check_timestamp(data.get("timestamp")),
    }
    if document["sha"] != document["head_sha"]:
        raise RedTeamError("sha-mismatch")
    if document["reviewer_id"] == document["author_id"]:
        raise RedTeamError("author-is-reviewer")
    blocking = document["blocking"]
    if verdict == "PASS" and blocking:
        raise RedTeamError("blocking-on-pass")
    if verdict == "FAIL" and not blocking:
        raise RedTeamError("fail-without-blocking")
    if document["repo"] != expected_repo:
        raise RedTeamError("repo-mismatch")
    if not same_pr(document["pr"], expected_pr):
        raise RedTeamError("pr-mismatch")
    if document["head_sha"] != current:
        raise RedTeamError("stale")
    return document


def format_result(document: dict[str, object], *, decision: str, reason: str, head: str) -> str:
    lines = [
        f"decision: {decision}",
        f"reason: {reason}",
        f"head: {head}",
        f"verdict: {document['verdict']}",
        f"reviewer: {document['reviewer_id']}",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a red-team verdict against one head.")
    parser.add_argument("--verdict", required=True, help="JSON verdict file")
    parser.add_argument("--head", required=True, help="Current head sha")
    parser.add_argument("--repo", required=True, help="Target repository, owner/name")
    parser.add_argument("--pr", required=True, help="Target pull request id")
    args = parser.parse_args(argv)
    try:
        head = normalize_sha(args.head, reason="bad-head")
    except RedTeamError as exc:
        print(f"head is not usable ({exc.reason})", file=sys.stderr)
        return 2
    try:
        repo = check_repo(args.repo, reason="bad-repo")
        pr_token: object = int(args.pr) if str(args.pr).isdigit() else args.pr
        pr = check_pr(pr_token, reason="bad-pr")
    except RedTeamError as exc:
        print(f"target is not usable ({exc.reason})", file=sys.stderr)
        return 2
    verdict_path = Path(args.verdict)
    if not verdict_path.is_file():
        print(f"verdict file is missing: {verdict_path}", file=sys.stderr)
        return 2
    try:
        payload = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print("verdict is not readable", file=sys.stderr)
        return 2
    try:
        document = validate_verdict(payload, head=head, repo=repo, pr=pr)
    except RedTeamError as exc:
        if exc.reason == "bad-verdict" or not isinstance(payload, dict):
            print("verdict is not readable", file=sys.stderr)
            return 2
        raw_verdict = payload.get("verdict", "")
        raw_reviewer = payload.get("reviewer_id", "")
        print(
            format_result(
                {"verdict": raw_verdict, "reviewer_id": raw_reviewer},
                decision="reject",
                reason=exc.reason,
                head=head,
            ),
            end="",
        )
        return 1
    decision = "valid" if document["verdict"] == "FAIL" else "accept"
    print(format_result(document, decision=decision, reason="current", head=head), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
