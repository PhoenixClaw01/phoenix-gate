#!/usr/bin/env python3
"""Run a script only when its sha256 is allowlisted and the git tree is clean.

The receipt is passed through the safe-helpers export scrubber.
This script does not open the network.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


class RunnerError(Exception):
    """The request cannot be checked. Exit 2."""


def load_scrubber():
    path = Path(__file__).resolve().parents[1] / "safe-helpers" / "export_scrub.py"
    if not path.is_file():
        raise RunnerError("scrubber is missing")
    spec = importlib.util.spec_from_file_location("export_scrub", path)
    if spec is None or spec.loader is None:
        raise RunnerError("scrubber is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_allowlist(text: str) -> list[str]:
    hashes: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        token = stripped.split()[0].lower()
        if len(token) != 64 or any(char not in "0123456789abcdef" for char in token):
            raise RunnerError("allowlist line is not a sha256")
        hashes.append(token)
    return hashes


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def tree_state(root: Path) -> str:
    """Return clean, dirty, or not-a-repo. Git stays on this machine."""
    try:
        probe = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=root,
            capture_output=True,
            text=True,
            env=_git_env(),
            check=False,
        )
    except FileNotFoundError as exc:
        raise RunnerError("git is missing") from exc
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return "not-a-repo"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        capture_output=True,
        text=True,
        env=_git_env(),
        check=False,
    )
    if status.returncode != 0:
        return "not-a-repo"
    if status.stdout.strip():
        return "dirty"
    return "clean"


def decide(root: Path, script: Path, allowlist: list[str]) -> dict[str, object]:
    digest = file_sha256(script)
    state = tree_state(root)
    if state != "clean":
        reason = "dirty-tree" if state == "dirty" else "not-a-repo"
        return _result("refuse", reason, digest, None, "", "")
    if digest not in allowlist:
        return _result("refuse", "not-allowlisted", digest, None, "", "")
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=root,
        capture_output=True,
        text=True,
        errors="replace",
        env=_git_env(),
        check=False,
        shell=False,
    )
    return _result("allow", "ran", digest, completed.returncode, completed.stdout, completed.stderr)


def _result(
    decision: str,
    reason: str,
    digest: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
) -> dict[str, object]:
    return {
        "decision": decision,
        "reason": reason,
        "sha256": digest,
        "exit": "none" if exit_code is None else str(exit_code),
        "stdout": stdout,
        "stderr": stderr,
    }


def render_receipt(result: dict[str, object]) -> str:
    lines = [
        f"decision: {result['decision']}",
        f"reason: {result['reason']}",
        f"sha256: {result['sha256']}",
        f"exit: {result['exit']}",
        "stdout:",
        str(result["stdout"]),
        "stderr:",
        str(result["stderr"]),
    ]
    text = "\n".join(lines)
    if not text.endswith("\n"):
        text += "\n"
    return text


def redact(text: str, phrases: list[str] | None = None) -> str:
    return load_scrubber().scrub(text, phrases)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a script only when its sha256 is allowlisted and the git tree is clean."
    )
    parser.add_argument("--allowlist", required=True, help="File of sha256 lines")
    parser.add_argument("--script", required=True, help="Script file to hash and maybe run")
    parser.add_argument("--receipt", required=True, help="Where to write the redacted receipt")
    parser.add_argument("--root", default=".", help="Git work tree to check. Defaults to the current directory.")
    parser.add_argument(
        "--phrases",
        default=None,
        help="Optional phrase file for the scrubber. When omitted, phrases.local.txt is used if it exists.",
    )
    args = parser.parse_args(argv)

    allowlist_path = Path(args.allowlist)
    script = Path(args.script).resolve()
    receipt_path = Path(args.receipt)
    root = Path(args.root).resolve()
    if not allowlist_path.is_file() or not script.is_file() or not root.is_dir():
        print("allowlist, script, or root is missing", file=sys.stderr)
        return 2
    if receipt_path.parent != Path(".") and not receipt_path.parent.is_dir():
        print("receipt directory is missing", file=sys.stderr)
        return 2

    try:
        allowlist = parse_allowlist(allowlist_path.read_text(encoding="utf-8"))
        result = decide(root, script, allowlist)
        scrubber = load_scrubber()
        phrase_path = Path(args.phrases) if args.phrases else scrubber.DEFAULT_PHRASES
        if args.phrases and not phrase_path.is_file():
            print("phrase file is missing", file=sys.stderr)
            return 2
        phrases = scrubber.load_phrases(phrase_path)
        body = scrubber.scrub(render_receipt(result), phrases)
    except RunnerError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    receipt_path.write_text(body, encoding="utf-8")
    sys.stdout.write(body)
    if result["decision"] != "allow":
        return 1
    return 0 if result["exit"] == "0" else 1


if __name__ == "__main__":
    raise SystemExit(main())
