#!/usr/bin/env python3
"""A token bucket. The clock is injected so a caller can replay a timeline."""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable


class TokenBucket:
    def __init__(
        self,
        capacity: float,
        refill_per_second: float,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_second < 0:
            raise ValueError("refill_per_second must be zero or positive")
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_second)
        self._clock = clock or time.monotonic
        self._tokens = float(capacity)
        self._updated = self._clock()

    def take(self, cost: float = 1.0) -> bool:
        if cost <= 0:
            raise ValueError("cost must be positive")
        self._refill(self._clock())
        if cost > self.capacity or self._tokens < cost:
            return False
        self._tokens -= cost
        return True

    def _refill(self, now: float) -> None:
        elapsed = now - self._updated
        if elapsed <= 0:
            return
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_second)
        self._updated = now


def parse_event(text: str) -> tuple[float, float]:
    stamp, _, cost = text.partition(":")
    if not _:
        raise ValueError(f"event must look like time:cost, got {text!r}")
    return float(stamp), float(cost)


def run(capacity: float, refill_per_second: float, events: list[tuple[float, float]]) -> list[bool]:
    clock = {"now": events[0][0] if events else 0.0}
    bucket = TokenBucket(capacity, refill_per_second, clock=lambda: clock["now"])
    results: list[bool] = []
    for at, cost in events:
        clock["now"] = at
        results.append(bucket.take(cost))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a token bucket over timed events.")
    parser.add_argument("--capacity", type=float, required=True)
    parser.add_argument("--refill-per-second", type=float, required=True)
    parser.add_argument("--event", action="append", default=[], help="time:cost, repeatable, in time order")
    args = parser.parse_args(argv)
    if not args.event:
        parser.error("at least one --event is required")
    results = run(args.capacity, args.refill_per_second, [parse_event(item) for item in args.event])
    for allowed in results:
        print("allow" if allowed else "deny")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
