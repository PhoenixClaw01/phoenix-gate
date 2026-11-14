#!/usr/bin/env python3
"""Choose a reviewer backend for one job.

The author of a change is never selected to review it. Backends are
adapters named by the config. This module ships a local stand-in and
does not open the network.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Protocol

# A path loader may exec this file before registering it. Dataclasses look
# up string annotations on sys.modules, so a missing entry has to exist.
if sys.modules.get(__name__) is None:
    sys.modules[__name__] = ModuleType(__name__)


def _load_verdict():
    path = Path(__file__).resolve().parent / "verdict.py"
    spec = importlib.util.spec_from_file_location("red_team_verdict", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("verdict module is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_verdict = _load_verdict()
RedTeamError = _verdict.RedTeamError
normalize_sha = _verdict.normalize_sha
validate_verdict = _verdict.validate_verdict
check_repo = _verdict.check_repo
check_pr = _verdict.check_pr
check_id = _verdict.check_id
check_lane = _verdict.check_lane


@dataclass(frozen=True)
class ReviewJob:
    repo: str
    pr: int | str
    head_sha: str
    author_id: str
    lane: str = "default"

    def __post_init__(self) -> None:
        object.__setattr__(self, "repo", check_repo(self.repo, reason="bad-job"))
        object.__setattr__(self, "pr", check_pr(self.pr, reason="bad-job"))
        object.__setattr__(self, "head_sha", normalize_sha(self.head_sha, reason="bad-job"))
        object.__setattr__(self, "author_id", check_id(self.author_id, reason="bad-job"))
        object.__setattr__(
            self,
            "lane",
            check_lane(self.lane, allow_wildcard=False, reason="bad-job"),
        )


@dataclass(frozen=True)
class ReviewDraft:
    """Findings a backend returns. The router stamps reviewer, sha, and time."""

    verdict: str
    blocking: tuple[Mapping[str, str], ...] = ()
    kintsugi: tuple[Mapping[str, str], ...] = ()


class ReviewBackend(Protocol):
    """Adapter interface. A backend reviews a job it did not author."""

    def review(self, job: ReviewJob) -> ReviewDraft:
        """Return a draft for this job."""


@dataclass(frozen=True)
class ReviewerRoute:
    reviewer_id: str
    backend: str
    lanes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "reviewer_id", check_id(self.reviewer_id, reason="bad-config"))
        object.__setattr__(self, "backend", check_id(self.backend, reason="bad-config"))
        if isinstance(self.lanes, str) or not self.lanes:
            raise RedTeamError("bad-config")
        lanes = tuple(
            check_lane(lane, allow_wildcard=True, reason="bad-config") for lane in self.lanes
        )
        if len(set(lanes)) != len(lanes):
            raise RedTeamError("bad-config")
        object.__setattr__(self, "lanes", lanes)


@dataclass(frozen=True)
class ReviewerConfig:
    routes: tuple[ReviewerRoute, ...]

    def __post_init__(self) -> None:
        if not self.routes:
            raise RedTeamError("bad-config")
        for route in self.routes:
            if not isinstance(route, ReviewerRoute):
                raise RedTeamError("bad-config")


class LocalMockAdapter:
    """In-process stand-in. It returns a draft the caller supplied.

    With no draft, review refuses. This adapter does not inspect a change
    and does not open the network.
    """

    name = "local"

    def __init__(self, draft: ReviewDraft | None = None) -> None:
        self._draft = draft

    def review(self, job: ReviewJob) -> ReviewDraft:
        if not isinstance(job, ReviewJob):
            raise RedTeamError("bad-job")
        if self._draft is None:
            raise RedTeamError("local-adapter-does-not-review")
        return self._draft


def builtin_backends() -> dict[str, LocalMockAdapter]:
    """The only backend shipped with this kit."""
    return {"local": LocalMockAdapter()}


def load_config(data: object) -> ReviewerConfig:
    if not isinstance(data, dict) or set(data) != {"routes"}:
        raise RedTeamError("bad-config")
    rows = data.get("routes")
    if not isinstance(rows, list) or not rows:
        raise RedTeamError("bad-config")
    routes: list[ReviewerRoute] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"reviewer_id", "backend", "lanes"}:
            raise RedTeamError("bad-config")
        lanes = row.get("lanes")
        if not isinstance(lanes, list):
            raise RedTeamError("bad-config")
        routes.append(
            ReviewerRoute(
                reviewer_id=row["reviewer_id"],
                backend=row["backend"],
                lanes=tuple(lanes),
            )
        )
    return ReviewerConfig(tuple(routes))


def select_reviewer(config: ReviewerConfig, job: ReviewJob) -> ReviewerRoute:
    """Pick the route for this job.

    A route whose reviewer id equals the author is skipped. An exact lane
    match wins over a `*` lane. Config order breaks remaining ties.
    """
    if not isinstance(config, ReviewerConfig) or not isinstance(job, ReviewJob):
        raise RedTeamError("bad-job")
    exact: list[ReviewerRoute] = []
    wildcard: list[ReviewerRoute] = []
    blocked_author = False
    for route in config.routes:
        matched_exact = job.lane in route.lanes
        matched_wild = "*" in route.lanes
        if not matched_exact and not matched_wild:
            continue
        if route.reviewer_id == job.author_id:
            blocked_author = True
            continue
        if matched_exact:
            exact.append(route)
        else:
            wildcard.append(route)
    if exact:
        return exact[0]
    if wildcard:
        return wildcard[0]
    if blocked_author:
        raise RedTeamError("author-is-reviewer")
    raise RedTeamError("no-reviewer")


def stamp(moment: datetime | None = None) -> str:
    current = moment if moment is not None else datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise RedTeamError("bad-verdict")
    return current.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_verdict(
    job: ReviewJob,
    reviewer_id: str,
    draft: ReviewDraft,
    *,
    timestamp: str,
) -> dict[str, object]:
    if not isinstance(draft, ReviewDraft):
        raise RedTeamError("bad-verdict")
    document = {
        "repo": job.repo,
        "pr": job.pr,
        "head_sha": job.head_sha,
        "sha": job.head_sha,
        "verdict": draft.verdict,
        "blocking": [dict(item) for item in draft.blocking],
        "kintsugi": [dict(item) for item in draft.kintsugi],
        "reviewer_id": reviewer_id,
        "author_id": job.author_id,
        "timestamp": timestamp,
    }
    return validate_verdict(document, head=job.head_sha, repo=job.repo, pr=job.pr)


def require_backend(name: str, backends: Mapping[str, ReviewBackend]) -> ReviewBackend:
    """Return the adapter registered under this name."""
    try:
        return backends[name]
    except KeyError:
        raise RedTeamError("unknown-backend") from None


def dispatch(
    config: ReviewerConfig,
    job: ReviewJob,
    backends: Mapping[str, ReviewBackend],
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Run the selected backend and return a verdict for this head.

    The author route is never used. A missing backend name refuses.
    """
    route = select_reviewer(config, job)
    if route.reviewer_id == job.author_id:
        raise RedTeamError("author-is-reviewer")
    backend = require_backend(route.backend, backends)
    draft = backend.review(job)
    return build_verdict(job, route.reviewer_id, draft, timestamp=stamp(now))


def format_route(route: ReviewerRoute, job: ReviewJob) -> str:
    lines = [
        "decision: route",
        f"reviewer: {route.reviewer_id}",
        f"backend: {route.backend}",
        f"author: {job.author_id}",
        f"lane: {job.lane}",
        f"head: {job.head_sha}",
        "",
    ]
    return "\n".join(lines)


def format_reject(reason: str, job: ReviewJob) -> str:
    lines = [
        "decision: reject",
        f"reason: {reason}",
        f"author: {job.author_id}",
        f"lane: {job.lane}",
        f"head: {job.head_sha}",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Choose a reviewer backend for one job.")
    parser.add_argument("--config", required=True, help="Reviewer config JSON")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True)
    parser.add_argument("--head", required=True, help="Current head sha")
    parser.add_argument(
        "--author",
        required=True,
        help="Author id. This id is not selected to review.",
    )
    parser.add_argument("--lane", default="default")
    args = parser.parse_args(argv)
    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"config file is missing: {config_path}", file=sys.stderr)
        return 2
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        config = load_config(payload)
        pr: int | str = int(args.pr) if str(args.pr).isdigit() else args.pr
        job = ReviewJob(
            repo=args.repo,
            pr=pr,
            head_sha=args.head,
            author_id=args.author,
            lane=args.lane,
        )
    except (RedTeamError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        print("config or job is not usable", file=sys.stderr)
        return 2
    try:
        route = select_reviewer(config, job)
        require_backend(route.backend, builtin_backends())
    except RedTeamError as exc:
        print(format_reject(exc.reason, job), end="")
        return 1
    print(format_route(route, job), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
