"""Behavior checks for the hash allowlist runner. Fixtures are synthetic."""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kits" / "hash-allowlist-runner"
SYNTHETIC_PHRASES = ("crimson widget", "orbit lantern")


def load_script(name: str, directory: Path):
    path = directory / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> None:
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(key, None)
    env["GIT_AUTHOR_NAME"] = "Example Keeper"
    env["GIT_AUTHOR_EMAIL"] = "keeper@example.com"
    env["GIT_COMMITTER_NAME"] = "Example Keeper"
    env["GIT_COMMITTER_EMAIL"] = "keeper@example.com"
    subprocess.run(["git", *args], cwd=repo, check=True, env=env, capture_output=True, text=True)


def commit_script(repo: Path, source: str, name: str = "script.py") -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    script = repo / name
    script.write_text(source, encoding="utf-8")
    git(repo, "init")
    git(repo, "add", name)
    git(repo, "commit", "-m", "add script")
    return script


class HashAllowlistScrubTests(unittest.TestCase):
    def test_kit_text_has_no_generic_hits(self):
        scrubber = load_script("export_scrub.py", ROOT / "kits" / "safe-helpers")
        hits = []
        for path in sorted(KIT.rglob("*")):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            text = path.read_text(encoding="utf-8")
            found = scrubber.hits(text)
            lowered = text.lower()
            for phrase in SYNTHETIC_PHRASES:
                if phrase in lowered:
                    found.append(f"phrase:{phrase}")
            if found or scrubber.scrub(text) != text:
                hits.append(f"{path.relative_to(ROOT)} {found}")
        self.assertEqual(hits, [])

    def test_runner_reuses_the_export_scrubber(self):
        runner = load_script("runner.py", KIT)
        scrubber = runner.load_scrubber()
        self.assertTrue(str(scrubber.__file__).endswith("export_scrub.py"))
        self.assertIn("safe-helpers", str(scrubber.__file__).replace("\\", "/"))
        sample = "ada@example.com"
        self.assertEqual(runner.redact(sample), "[redacted]")
        self.assertNotIn(sample, runner.redact(sample))


class HashAllowlistBehaviorTests(unittest.TestCase):
    def test_example_allowlist_matches_the_example_script(self):
        runner = load_script("runner.py", KIT)
        script = KIT / "examples" / "hello.py"
        listed = runner.parse_allowlist((KIT / "examples" / "allowlist.txt").read_text(encoding="utf-8"))
        self.assertEqual(listed, [runner.file_sha256(script)])

    def test_clean_allowlisted_script_runs_and_the_receipt_is_redacted(self):
        runner = load_script("runner.py", KIT)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            script = commit_script(
                repo,
                "print('ada@example.com')\nprint('a crimson widget')\n",
            )
            phrases = root / "phrases.txt"
            phrases.write_text("# note\n\ncrimson widget\n", encoding="utf-8")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            receipt = root / "receipt.txt"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = runner.main(
                    [
                        "--allowlist",
                        str(allowlist),
                        "--script",
                        str(script),
                        "--root",
                        str(repo),
                        "--receipt",
                        str(receipt),
                        "--phrases",
                        str(phrases),
                    ]
                )
            body = receipt.read_text(encoding="utf-8")
            self.assertEqual(code, 0)
            self.assertEqual(stdout.getvalue(), body)
            self.assertIn("decision: allow", body)
            self.assertIn("reason: ran", body)
            self.assertIn("exit: 0", body)
            self.assertNotIn("ada@example.com", body)
            self.assertNotIn("crimson widget", body.lower())
            self.assertIn("[redacted]", body)

    def test_dirty_tree_and_a_missing_hash_do_not_run(self):
        runner = load_script("runner.py", KIT)
        source = "from pathlib import Path\nPath('ran.txt').write_text('yes\\n', encoding='utf-8')\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            script = commit_script(repo, source)
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + " note\n", encoding="utf-8")
            (repo / "extra.txt").write_text("untracked\n", encoding="utf-8")
            receipt = root / "dirty.txt"
            self.assertEqual(
                runner.main(
                    [
                        "--allowlist",
                        str(allowlist),
                        "--script",
                        str(script),
                        "--root",
                        str(repo),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                1,
            )
            self.assertFalse((repo / "ran.txt").exists())
            self.assertIn("reason: dirty-tree", receipt.read_text(encoding="utf-8"))

            git(repo, "add", "extra.txt")
            git(repo, "commit", "-m", "track the extra file")
            wrong = root / "wrong.txt"
            wrong.write_text("a" * 64 + "\n", encoding="utf-8")
            missed = root / "missed.txt"
            self.assertEqual(
                runner.main(
                    [
                        "--allowlist",
                        str(wrong),
                        "--script",
                        str(script),
                        "--root",
                        str(repo),
                        "--receipt",
                        str(missed),
                    ]
                ),
                1,
            )
            self.assertFalse((repo / "ran.txt").exists())
            self.assertIn("reason: not-allowlisted", missed.read_text(encoding="utf-8"))

    def test_a_directory_that_is_not_a_checkout_refuses(self):
        runner = load_script("runner.py", KIT)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "script.py"
            script.write_text("print('harbor desk')\n", encoding="utf-8")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            receipt = root / "receipt.txt"
            self.assertEqual(
                runner.main(
                    [
                        "--allowlist",
                        str(allowlist),
                        "--script",
                        str(script),
                        "--root",
                        str(root),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                1,
            )
            self.assertIn("reason: not-a-repo", receipt.read_text(encoding="utf-8"))

    def test_bad_input_exits_2_and_a_failing_script_exits_1(self):
        runner = load_script("runner.py", KIT)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(
                runner.main(
                    [
                        "--allowlist",
                        str(root / "missing.txt"),
                        "--script",
                        str(root / "missing.py"),
                        "--root",
                        str(root),
                        "--receipt",
                        str(root / "receipt.txt"),
                    ]
                ),
                2,
            )
            allowlist = root / "allowlist.txt"
            allowlist.write_text("not-a-hash\n", encoding="utf-8")
            script = root / "script.py"
            script.write_text("print('nope')\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = runner.main(
                    [
                        "--allowlist",
                        str(allowlist),
                        "--script",
                        str(script),
                        "--root",
                        str(root),
                        "--receipt",
                        str(root / "receipt.txt"),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("allowlist line is not a sha256", stderr.getvalue())

            repo = root / "repo"
            failing = commit_script(repo, "raise SystemExit(3)\n")
            allowlist.write_text(runner.file_sha256(failing) + "\n", encoding="utf-8")
            receipt = root / "fail.txt"
            self.assertEqual(
                runner.main(
                    [
                        "--allowlist",
                        str(allowlist),
                        "--script",
                        str(failing),
                        "--root",
                        str(repo),
                        "--receipt",
                        str(receipt),
                    ]
                ),
                1,
            )
            body = receipt.read_text(encoding="utf-8")
            self.assertIn("decision: allow", body)
            self.assertIn("exit: 3", body)

    def test_runner_does_not_import_a_network_module(self):
        text = (KIT / "runner.py").read_text(encoding="utf-8")
        for needle in (
            "import socket",
            "from socket",
            "import urllib",
            "import smtplib",
            "import http",
            "import requests",
            "shell=True",
        ):
            self.assertNotIn(needle, text)
