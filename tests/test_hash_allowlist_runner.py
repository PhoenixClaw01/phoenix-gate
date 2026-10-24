"""Behavior checks for the hash allowlist runner. Fixtures are synthetic."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import stat
import subprocess
import sys
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


def run_main(runner, allowlist: Path, script: Path, root: Path, receipt: Path):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = runner.main(
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
        )
    if receipt.is_symlink() or not receipt.exists():
        body = ""
    else:
        body = receipt.read_text(encoding="utf-8")
    return code, body, stdout.getvalue(), stderr.getvalue()


def worktree_status(repo: Path) -> str:
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_GLOBAL"):
        env.pop(key, None)
    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


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

    def test_hashed_bytes_run_when_the_path_changes(self):
        runner = load_script("runner.py", KIT)
        source = 'print("alpha")\nprint("FILE=" + __file__)\n'
        beta = b'print("beta")\nprint("FILE=" + __file__)\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            script = commit_script(repo, source)
            original = script.read_bytes()
            allowlist = root / "allowlist.txt"
            allowlist.write_text(hashlib.sha256(original).hexdigest() + "\n", encoding="utf-8")
            receipt = root / "receipt.txt"
            real_run = runner.subprocess.run
            seen = []

            def spy(argv, *args, **kwargs):
                if argv and argv[0] != "git":
                    script.write_bytes(beta)
                    seen.append((list(argv), kwargs.get("input")))
                return real_run(argv, *args, **kwargs)

            runner.subprocess.run = spy
            try:
                code, body, echoed, _stderr = run_main(runner, allowlist, script, repo, receipt)
            finally:
                runner.subprocess.run = real_run
            self.assertEqual(code, 0)
            self.assertEqual(echoed, body)
            self.assertEqual(script.read_bytes(), beta)
            self.assertIn("alpha", body)
            self.assertNotIn("beta", body)
            self.assertIn("FILE=<stdin>", body)
            self.assertIn("sha256: " + hashlib.sha256(original).hexdigest(), body)
            self.assertEqual(seen, [(runner.child_command(), original)])
            self.assertEqual(runner.child_command(), [sys.executable, "-I", "-B", "-"])

    def test_symlinks_are_refused(self):
        runner = load_script("runner.py", KIT)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            ran = repo / "ran.txt"
            source = "from pathlib import Path\nPath('ran.txt').write_text('yes\\n', encoding='utf-8')\nprint('via-target')\n"
            script = commit_script(repo, source)
            link = repo / "link.py"
            link.symlink_to(script.name)
            git(repo, "add", "link.py")
            git(repo, "commit", "-m", "add a linked name")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            code, body, _echoed, _stderr = run_main(runner, allowlist, link, repo, root / "link-receipt.txt")
            self.assertEqual(code, 1)
            self.assertIn("reason: symlink", body)
            self.assertIn("sha256: none", body)
            self.assertNotIn("via-target", body)
            self.assertFalse(ran.exists())

            outside = root / "outside"
            outside.mkdir()
            marker = outside / "escaped.txt"
            evil = outside / "evil.py"
            evil.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('escaped-link\\n', encoding='utf-8')\n"
                "print('escaped-link')\n",
                encoding="utf-8",
            )
            bridge = repo / "sub"
            bridge.symlink_to(outside, target_is_directory=True)
            git(repo, "add", "sub")
            git(repo, "commit", "-m", "add a linked directory")
            allowlist.write_text(runner.file_sha256(evil) + "\n", encoding="utf-8")
            code, body, _echoed, _stderr = run_main(
                runner,
                allowlist,
                bridge / "evil.py",
                repo,
                root / "bridge-receipt.txt",
            )
            self.assertEqual(code, 1)
            self.assertIn("reason: symlink", body)
            self.assertIn("sha256: none", body)
            self.assertNotIn("escaped-link", body)
            self.assertFalse(marker.exists())
            self.assertFalse(ran.exists())

            target = root / "secret.txt"
            target.write_text("kept\n", encoding="utf-8")
            receipt_link = root / "receipt-link.txt"
            receipt_link.symlink_to(target)
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            code, body, _echoed, stderr = run_main(runner, allowlist, script, repo, receipt_link)
            self.assertEqual(code, 2)
            self.assertIn("receipt is a symlink", stderr)
            self.assertEqual(target.read_text(encoding="utf-8"), "kept\n")
            self.assertFalse(ran.exists())
            self.assertEqual(body, "")

            existing = root / "existing.txt"
            existing.write_text("kept\n", encoding="utf-8")
            code, _body, _echoed, stderr = run_main(runner, allowlist, script, repo, existing)
            self.assertEqual(code, 2)
            self.assertIn("receipt exists", stderr)
            self.assertEqual(existing.read_text(encoding="utf-8"), "kept\n")
            self.assertFalse(ran.exists())

    def test_script_must_stay_inside_root(self):
        runner = load_script("runner.py", KIT)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "pried.txt"
            payload = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('yes\\n', encoding='utf-8')\n"
                "print('pried-open')\n"
            )
            outside = root / "outside.py"
            outside.write_text(payload, encoding="utf-8")
            repo = root / "repo"
            commit_script(repo, "print('inside')\n")
            sibling = Path(str(repo) + "-evil")
            sibling.mkdir()
            prefixed = sibling / "x.py"
            prefixed.write_text(payload, encoding="utf-8")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(outside) + "\n", encoding="utf-8")
            cases = (
                ("sibling", outside),
                ("parent", repo / ".." / "outside.py"),
                ("prefix", prefixed),
            )
            for name, script in cases:
                with self.subTest(name=name):
                    code, body, _echoed, _stderr = run_main(
                        runner,
                        allowlist,
                        script,
                        repo,
                        root / f"{name}-receipt.txt",
                    )
                    self.assertEqual(code, 1)
                    self.assertIn("reason: outside-root", body)
                    self.assertIn("sha256: none", body)
                    self.assertNotIn("pried-open", body)
                    self.assertFalse(marker.exists())

    def test_ignored_and_index_flags_are_dirty(self):
        runner = load_script("runner.py", KIT)
        source = "from pathlib import Path\nPath('ran.txt').write_text('yes\\n', encoding='utf-8')\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            script = commit_script(repo, source)
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
            git(repo, "add", ".gitignore")
            git(repo, "commit", "-m", "ignore logs")
            (repo / "secret.log").write_text("hidden\n", encoding="utf-8")
            self.assertEqual(worktree_status(repo), "")
            code, body, _echoed, _stderr = run_main(runner, allowlist, script, repo, root / "ignored.txt")
            self.assertEqual(code, 1)
            self.assertIn("reason: dirty-tree", body)
            self.assertFalse((repo / "ran.txt").exists())
            (repo / "secret.log").unlink()

            git(repo, "update-index", "--assume-unchanged", "script.py")
            self.assertEqual(worktree_status(repo), "")
            code, body, _echoed, _stderr = run_main(runner, allowlist, script, repo, root / "assume.txt")
            self.assertEqual(code, 1)
            self.assertIn("reason: dirty-tree", body)
            self.assertFalse((repo / "ran.txt").exists())
            git(repo, "update-index", "--no-assume-unchanged", "script.py")

            git(repo, "update-index", "--skip-worktree", "script.py")
            self.assertEqual(worktree_status(repo), "")
            code, body, _echoed, _stderr = run_main(runner, allowlist, script, repo, root / "skip.txt")
            self.assertEqual(code, 1)
            self.assertIn("reason: dirty-tree", body)
            self.assertFalse((repo / "ran.txt").exists())
            git(repo, "update-index", "--no-skip-worktree", "script.py")

            nested = repo / "nested"
            nested.mkdir()
            inner = nested / "inner.py"
            inner.write_text(source, encoding="utf-8")
            git(repo, "add", "nested/inner.py")
            git(repo, "commit", "-m", "add nested script")
            allowlist.write_text(runner.file_sha256(inner) + "\n", encoding="utf-8")
            code, body, _echoed, _stderr = run_main(
                runner,
                allowlist,
                inner,
                nested,
                root / "nested-receipt.txt",
            )
            self.assertEqual(code, 1)
            self.assertIn("reason: not-a-repo", body)
            self.assertFalse((nested / "ran.txt").exists())

            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            (repo / "extra.txt").write_text("untracked\n", encoding="utf-8")
            clean = root / "clean"
            commit_script(clean, "print('elsewhere')\n")
            saved = os.environ.get("GIT_DIR")
            os.environ["GIT_DIR"] = str(clean / ".git")
            try:
                code, body, _echoed, _stderr = run_main(
                    runner,
                    allowlist,
                    script,
                    repo,
                    root / "gitdir-receipt.txt",
                )
            finally:
                if saved is None:
                    os.environ.pop("GIT_DIR", None)
                else:
                    os.environ["GIT_DIR"] = saved
            self.assertEqual(code, 1)
            self.assertIn("reason: dirty-tree", body)
            self.assertFalse((repo / "ran.txt").exists())

    def test_repo_helpers_are_not_executed(self):
        runner = load_script("runner.py", KIT)
        saved = os.environ.get("GIT_CONFIG_GLOBAL")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            script = commit_script(repo, "print('helper-ok')\n")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            hook = root / "hook.sh"
            marker = root / "marker.txt"
            hook.write_text(f"#!/bin/sh\necho pwned >> {marker}\n", encoding="utf-8")
            hook.chmod(hook.stat().st_mode | stat.S_IEXEC)
            git(repo, "config", "core.fsmonitor", str(hook))
            git(repo, "config", "alias.status", f"!{hook}")
            git(repo, "config", "alias.rev-parse", f"!{hook}")
            git(repo, "config", "alias.ls-files", f"!{hook}")
            git(repo, "config", "alias.cat-file", f"!{hook}")
            git(repo, "config", "alias.config", f"!{hook}")
            global_config = root / "global.gitconfig"
            for key, value in (
                ("core.fsmonitor", str(hook)),
                ("alias.status", f"!{hook}"),
                ("alias.rev-parse", f"!{hook}"),
                ("alias.ls-files", f"!{hook}"),
                ("alias.cat-file", f"!{hook}"),
                ("alias.config", f"!{hook}"),
            ):
                subprocess.run(
                    ["git", "config", "--file", str(global_config), key, value],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            os.environ["GIT_CONFIG_GLOBAL"] = str(global_config)
            try:
                probed = runner.git_env(repo)
                self.assertEqual(probed["GIT_CONFIG_GLOBAL"], "/dev/null")
                self.assertEqual(probed["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(probed["GIT_ATTR_NOSYSTEM"], "1")
                self.assertEqual(probed["GIT_OPTIONAL_LOCKS"], "0")
                self.assertEqual(
                    probed["GIT_CEILING_DIRECTORIES"],
                    str(Path(os.path.realpath(repo)).parent),
                )
                for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "PYTHONPATH"):
                    self.assertNotIn(key, probed)
                argv = runner.git_argv(repo, "status")
                for flag in (
                    "core.fsmonitor=false",
                    "core.untrackedCache=false",
                    "alias.status=",
                    "alias.rev-parse=",
                    "alias.ls-files=",
                    "alias.cat-file=",
                    "alias.config=",
                    "--no-optional-locks",
                ):
                    self.assertIn(flag, argv)
                self.assertTrue(any(item.startswith("core.hooksPath=") for item in argv))
                code, body, _echoed, _stderr = run_main(
                    runner,
                    allowlist,
                    script,
                    repo,
                    root / "receipt.txt",
                )
            finally:
                if saved is None:
                    os.environ.pop("GIT_CONFIG_GLOBAL", None)
                else:
                    os.environ["GIT_CONFIG_GLOBAL"] = saved
            self.assertEqual(code, 0)
            self.assertIn("decision: allow", body)
            self.assertIn("helper-ok", body)
            self.assertFalse(marker.exists())

    def test_child_environment_is_minimal(self):
        runner = load_script("runner.py", KIT)
        keys = ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "LD_PRELOAD", "SENTINEL_PARENT")
        saved = {key: os.environ.get(key) for key in keys}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site = root / "site"
            site.mkdir()
            site_marker = root / "site-ran.txt"
            (site / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(site_marker)!r}).write_text('yes\\n', encoding='utf-8')\n",
                encoding="utf-8",
            )
            startup_marker = root / "startup-ran.txt"
            startup = root / "startup.py"
            startup.write_text(
                "from pathlib import Path\n"
                f"Path({str(startup_marker)!r}).write_text('yes\\n', encoding='utf-8')\n",
                encoding="utf-8",
            )
            home = root / "not-python"
            home.mkdir()
            lines = ["import os", "print('FILE=' + __file__)"]
            for key in keys:
                lines.append(f"print({key!r} + '=' + os.environ.get({key!r}, '<missing>'))")
            repo = root / "repo"
            script = commit_script(repo, "\n".join(lines) + "\n")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            os.environ["PYTHONPATH"] = str(site)
            os.environ["PYTHONSTARTUP"] = str(startup)
            os.environ["PYTHONHOME"] = str(home)
            os.environ["LD_PRELOAD"] = str(root / "nope.so")
            os.environ["SENTINEL_PARENT"] = "present"
            try:
                child = runner.child_env()
                for key in keys:
                    self.assertNotIn(key, child)
                code, body, _echoed, _stderr = run_main(
                    runner,
                    allowlist,
                    script,
                    repo,
                    root / "receipt.txt",
                )
            finally:
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertEqual(code, 0)
            self.assertIn("decision: allow", body)
            self.assertIn("FILE=<stdin>", body)
            for key in keys:
                self.assertIn(f"{key}=<missing>", body)
            self.assertFalse(site_marker.exists())
            self.assertFalse(startup_marker.exists())

    def test_restore_after_read_refuses(self):
        runner = load_script("runner.py", KIT)
        committed = "print('head-copy')\n"
        swapped = (
            "from pathlib import Path\n"
            "Path('ran.txt').write_text('yes\\n', encoding='utf-8')\n"
            "print('swapped')\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            script = commit_script(repo, committed)
            committed_bytes = script.read_bytes()
            swapped_bytes = swapped.encode("utf-8")
            script.write_bytes(swapped_bytes)
            allowlist = root / "allowlist.txt"
            allowlist.write_text(
                hashlib.sha256(committed_bytes).hexdigest()
                + "\n"
                + hashlib.sha256(swapped_bytes).hexdigest()
                + "\n",
                encoding="utf-8",
            )
            real_read = runner.read_under_root

            def restore_after(root_arg, script_arg):
                data = real_read(root_arg, script_arg)
                script.write_bytes(committed_bytes)
                return data

            runner.read_under_root = restore_after
            try:
                code, body, _echoed, _stderr = run_main(
                    runner, allowlist, script, repo, root / "receipt.txt"
                )
            finally:
                runner.read_under_root = real_read
            self.assertEqual(code, 1)
            self.assertIn("reason: dirty-tree", body)
            self.assertNotIn("swapped", body)
            self.assertNotIn("head-copy", body)
            self.assertFalse((repo / "ran.txt").exists())

            script.write_bytes(swapped_bytes)
            real_state = runner.tree_state
            runner.tree_state = lambda _root: "clean"
            runner.read_under_root = restore_after
            try:
                code, body, _echoed, _stderr = run_main(
                    runner, allowlist, script, repo, root / "forced.txt"
                )
            finally:
                runner.tree_state = real_state
                runner.read_under_root = real_read
            self.assertEqual(code, 1)
            self.assertIn("reason: changed", body)
            self.assertIn("sha256: none", body)
            self.assertNotIn("swapped", body)
            self.assertNotIn("head-copy", body)
            self.assertFalse((repo / "ran.txt").exists())

    def test_delete_untracked_after_read_refuses(self):
        runner = load_script("runner.py", KIT)
        payload = (
            "from pathlib import Path\n"
            "Path('ran.txt').write_text('yes\\n', encoding='utf-8')\n"
            "print('extra-ran')\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            commit_script(repo, "print('placeholder')\n")
            extra = repo / "extra.py"
            extra.write_text(payload, encoding="utf-8")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(
                hashlib.sha256(payload.encode("utf-8")).hexdigest() + "\n",
                encoding="utf-8",
            )
            real_read = runner.read_under_root

            def delete_after(root_arg, script_arg):
                data = real_read(root_arg, script_arg)
                if extra.exists():
                    extra.unlink()
                return data

            runner.read_under_root = delete_after
            try:
                code, body, _echoed, _stderr = run_main(
                    runner, allowlist, extra, repo, root / "receipt.txt"
                )
            finally:
                runner.read_under_root = real_read
            self.assertEqual(code, 1)
            self.assertIn("reason: dirty-tree", body)
            self.assertNotIn("extra-ran", body)
            self.assertFalse((repo / "ran.txt").exists())

    def test_untracked_allowlisted_script_refuses(self):
        runner = load_script("runner.py", KIT)
        payload = (
            "from pathlib import Path\n"
            "Path('ran.txt').write_text('yes\\n', encoding='utf-8')\n"
            "print('untracked-ran')\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            commit_script(repo, "print('placeholder')\n")
            extra = repo / "extra.py"
            extra.write_text(payload, encoding="utf-8")
            allowlist = root / "allowlist.txt"
            allowlist.write_text(
                hashlib.sha256(payload.encode("utf-8")).hexdigest() + "\n",
                encoding="utf-8",
            )
            code, body, _echoed, _stderr = run_main(
                runner, allowlist, extra, repo, root / "receipt.txt"
            )
            self.assertEqual(code, 1)
            self.assertIn("reason: dirty-tree", body)
            self.assertNotIn("untracked-ran", body)
            self.assertFalse((repo / "ran.txt").exists())

            real_state = runner.tree_state
            runner.tree_state = lambda _root: "clean"
            try:
                code, body, _echoed, _stderr = run_main(
                    runner, allowlist, extra, repo, root / "forced.txt"
                )
            finally:
                runner.tree_state = real_state
            self.assertEqual(code, 1)
            self.assertIn("reason: not-in-head", body)
            self.assertIn("sha256: none", body)
            self.assertNotIn("untracked-ran", body)
            self.assertFalse((repo / "ran.txt").exists())

    def test_repo_filter_drivers_do_not_run(self):
        runner = load_script("runner.py", KIT)
        source = (
            "from pathlib import Path\n"
            "Path('ran.txt').write_text('yes\\n', encoding='utf-8')\n"
            "print('filter-ok')\n"
        )

        def refuse(kind: str, place: str) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = root / "repo"
                script = commit_script(repo, source)
                sentinel = root / "sentinel.txt"
                hook = root / "filter.sh"
                quoted = "'" + str(sentinel).replace("'", "'\\''") + "'"
                hook.write_text(
                    "#!/bin/sh\n"
                    f"echo ran >> {quoted}\n"
                    "cat\n",
                    encoding="utf-8",
                )
                hook.chmod(hook.stat().st_mode | stat.S_IEXEC)
                if place == "include":
                    included = root / "included.gitconfig"
                    included.write_text(
                        f"[filter \"sample\"]\n\t{kind} = {hook}\n",
                        encoding="utf-8",
                    )
                    git(repo, "config", "include.path", str(included))
                else:
                    git(repo, "config", f"filter.sample.{kind}", str(hook))
                if place == "info":
                    info = repo / ".git" / "info"
                    info.mkdir(parents=True, exist_ok=True)
                    (info / "attributes").write_text("* filter=sample\n", encoding="utf-8")
                elif place == "nested":
                    nested = repo / "sub"
                    nested.mkdir()
                    (nested / ".gitattributes").write_text("* filter=sample\n", encoding="utf-8")
                    (nested / "note.txt").write_text("note\n", encoding="utf-8")
                    git(repo, "add", "sub")
                    git(repo, "commit", "-m", "select sample filter")
                else:
                    (repo / ".gitattributes").write_text("* filter=sample\n", encoding="utf-8")
                    git(repo, "add", ".gitattributes")
                    git(repo, "commit", "-m", "select sample filter")
                if sentinel.exists():
                    sentinel.unlink()
                allowlist = root / "allowlist.txt"
                allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
                argv = runner.git_argv(repo, "status")
                for flag in (
                    "filter.sample.clean=",
                    "filter.sample.smudge=",
                    "filter.sample.process=",
                    "filter.sample.required=false",
                ):
                    self.assertIn(flag, argv)
                self.assertFalse(sentinel.exists())
                code, body, _echoed, _stderr = run_main(
                    runner, allowlist, script, repo, root / f"{kind}-{place}.txt"
                )
                self.assertEqual(code, 1)
                self.assertIn("decision: refuse", body)
                self.assertIn("reason: unsafe-config", body)
                self.assertIn("sha256: none", body)
                self.assertNotIn("filter-ok", body)
                self.assertFalse(sentinel.exists())
                self.assertFalse((repo / "ran.txt").exists())

        for kind in ("clean", "smudge", "process"):
            with self.subTest(kind=kind, place="root"):
                refuse(kind, "root")
        for place in ("info", "nested", "include"):
            with self.subTest(kind="clean", place=place):
                refuse("clean", place)

    def test_repo_hooks_do_not_run_or_refresh_the_index(self):
        runner = load_script("runner.py", KIT)
        source = "print('hook-ok')\n"
        names = ("post-index-change", "reference-transaction", "pre-commit")

        def check(name: str, place: str, dirty: bool) -> None:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = root / "repo"
                script = commit_script(repo, source)
                sentinel = root / "sentinel.txt"
                hook_body = "#!/bin/sh\n" + "echo ran >> '" + str(sentinel).replace("'", "'\\''") + "'\n"
                if place == "hooksPath":
                    hook_dir = root / "alt-hooks"
                    hook_dir.mkdir()
                    hook = hook_dir / name
                    hook.write_text(hook_body, encoding="utf-8")
                    hook.chmod(hook.stat().st_mode | stat.S_IEXEC)
                    git(repo, "config", "core.hooksPath", str(hook_dir))
                else:
                    hook = repo / ".git" / "hooks" / name
                    hook.write_text(hook_body, encoding="utf-8")
                    hook.chmod(hook.stat().st_mode | stat.S_IEXEC)
                if dirty:
                    (repo / "extra.txt").write_text("extra\n", encoding="utf-8")
                allowlist = root / "allowlist.txt"
                allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
                index = repo / ".git" / "index"
                before = index.read_bytes()
                stamp = index.stat().st_mtime_ns
                argv = runner.git_argv(repo, "status", "--porcelain")
                self.assertIn("--no-optional-locks", argv)
                hooks_args = [item for item in argv if item.startswith("core.hooksPath=")]
                self.assertEqual(len(hooks_args), 1)
                hooks_path = hooks_args[0].split("=", 1)[1]
                self.assertTrue(os.path.isdir(hooks_path))
                self.assertEqual(os.listdir(hooks_path), [])
                self.assertNotEqual(
                    os.path.realpath(hooks_path),
                    os.path.realpath(repo / ".git" / "hooks"),
                )
                probed = runner.git_probe(
                    repo, "status", "--porcelain", "--ignored", "--untracked-files=all"
                )
                self.assertEqual(probed.returncode, 0)
                self.assertFalse(sentinel.exists())
                self.assertEqual(index.read_bytes(), before)
                self.assertEqual(index.stat().st_mtime_ns, stamp)
                code, body, _echoed, _stderr = run_main(
                    runner, allowlist, script, repo, root / "receipt.txt"
                )
                self.assertEqual(code, 1)
                self.assertIn("decision: refuse", body)
                self.assertIn("reason: unsafe-config", body)
                self.assertNotIn("hook-ok", body)
                self.assertFalse(sentinel.exists())
                self.assertEqual(index.read_bytes(), before)
                self.assertEqual(index.stat().st_mtime_ns, stamp)

        for name in names:
            for place in ("dotgit", "hooksPath"):
                for dirty in (False, True):
                    with self.subTest(name=name, place=place, dirty=dirty):
                        check(name, place, dirty)

    def test_linked_worktree_checks_the_common_git_dir(self):
        runner = load_script("runner.py", KIT)
        source = "print('worktree-ok')\n"

        def linked_pair(root: Path) -> tuple[Path, Path]:
            repo = root / "main"
            script = commit_script(repo, source)
            linked = root / "linked"
            git(repo, "worktree", "add", "--detach", str(linked), "HEAD")
            return repo, linked

        def hook_script(path: Path, sentinel: Path) -> None:
            quoted = "'" + str(sentinel).replace("'", "'\\''") + "'"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\necho ran >> " + quoted + "\n", encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IEXEC)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _repo, linked = linked_pair(root)
            script = linked / "script.py"
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            code, body, _echoed, _stderr = run_main(
                runner, allowlist, script, linked, root / "clean.txt"
            )
            self.assertEqual(code, 0)
            self.assertIn("decision: allow", body)
            self.assertIn("worktree-ok", body)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, linked = linked_pair(root)
            sentinel = root / "sentinel.txt"
            hook_script(repo / ".git" / "hooks" / "post-index-change", sentinel)
            script = linked / "script.py"
            allowlist = root / "allowlist.txt"
            allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
            code, body, _echoed, _stderr = run_main(
                runner, allowlist, script, linked, root / "hook.txt"
            )
            self.assertEqual(code, 1)
            self.assertIn("reason: unsafe-config", body)
            self.assertNotIn("worktree-ok", body)
            self.assertFalse(sentinel.exists())

        for key, target in (
            ("filter.sample.clean", "filter.sh"),
            ("core.hooksPath", "alt-hooks"),
            ("core.fsmonitor", "fsmonitor.sh"),
        ):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    repo, linked = linked_pair(root)
                    sentinel = root / "sentinel.txt"
                    if key == "core.hooksPath":
                        hook_dir = root / "alt-hooks"
                        hook_script(hook_dir / "post-index-change", sentinel)
                        value = str(hook_dir)
                    else:
                        command = root / target
                        hook_script(command, sentinel)
                        value = str(command)
                    git(repo, "config", "extensions.worktreeConfig", "true")
                    git(linked, "config", "--worktree", key, value)
                    if key == "filter.sample.clean":
                        (linked / ".gitattributes").write_text("* filter=sample\n", encoding="utf-8")
                    if sentinel.exists():
                        sentinel.unlink()
                    script = linked / "script.py"
                    allowlist = root / "allowlist.txt"
                    allowlist.write_text(runner.file_sha256(script) + "\n", encoding="utf-8")
                    code, body, _echoed, _stderr = run_main(
                        runner, allowlist, script, linked, root / "cfg.txt"
                    )
                    self.assertEqual(code, 1)
                    self.assertIn("reason: unsafe-config", body)
                    self.assertNotIn("worktree-ok", body)
                    self.assertFalse(sentinel.exists())
