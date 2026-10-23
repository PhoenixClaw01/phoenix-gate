#!/usr/bin/env python3
"""Print a message that would be sent. This module never sends it."""

from __future__ import annotations

import argparse
import sys
from typing import Mapping, TextIO


def render(message: Mapping[str, str]) -> str:
    if "to" not in message or "body" not in message:
        raise ValueError("message needs 'to' and 'body'")
    title = message.get("title", "")
    lines = [
        "dry-run",
        f"to: {message['to']}",
        f"title: {title}",
        "body:",
        str(message["body"]),
        "",
    ]
    return "\n".join(lines)


def deliver(message: Mapping[str, str], out: TextIO | None = None) -> dict[str, object]:
    preview = render(message)
    print(preview, end="", file=out or sys.stdout)
    return {"delivered": False, "dry_run": True, "preview": preview}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print a message instead of sending it.")
    parser.add_argument("--to", required=True)
    parser.add_argument("--title", default="")
    parser.add_argument("--body", required=True)
    args = parser.parse_args(argv)
    deliver({"to": args.to, "title": args.title, "body": args.body})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
