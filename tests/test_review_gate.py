"""Behavior checks for the review gate. Fixtures are synthetic."""

from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kits" / "review-gate"
HEAD = "a" * 40
OLDER = "b" * 40


def load_script():
    path = KIT / "review_gate.py"
    spec = importlib.util.spec_from_file_location("review_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_main(module, args: list[str], *, cwd: Path | None = None) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = module.main(args, cwd=cwd)
    return code, stdout.getvalue(), stderr.getvalue()


class ReviewGateTests(unittest.TestCase):
    def test_pass_for_the_current_head_allows(self):
        module = load_script()
        verdict = KIT / "examples" / "pass-current.json"
        code, stdout, _stderr = run_main(module, ["--verdict", str(verdict), "--head", HEAD])
        self.assertEqual(code, 0)
        self.assertEqual(
            stdout,
            "\n".join(
                [
                    "decision: allow",
                    "reason: pass",
                    f"head: {HEAD}",
                    "approved: true",
                    "",
                ]
            ),
        )

    def test_comment_pass_allows_and_fail_refuses(self):
        module = load_script()
        passed = KIT / "examples" / "pass-comment.txt"
        failed = KIT / "examples" / "fail-comment.txt"
        code, stdout, _stderr = run_main(module, ["--verdict", str(passed), "--head", HEAD.upper()])
        self.assertEqual(code, 0)
        self.assertIn("approved: true", stdout)
        code, stdout, _stderr = run_main(module, ["--verdict", str(failed), "--head", HEAD])
        self.assertEqual(code, 1)
        self.assertIn("reason: no-pass", stdout)
        self.assertIn("approved: false", stdout)

    def test_stale_pass_on_an_older_sha_refuses(self):
        module = load_script()
        verdict = KIT / "examples" / "pass-older.json"
        code, stdout, _stderr = run_main(module, ["--verdict", str(verdict), "--head", HEAD])
        self.assertEqual(code, 1)
        self.assertIn("decision: refuse", stdout)
        self.assertIn("reason: stale", stdout)
        self.assertIn("approved: false", stdout)
        with tempfile.TemporaryDirectory() as tmp:
            note = Path(tmp) / "note.txt"
            note.write_text(f"PASS {OLDER}\nnote mentions {HEAD}\n", encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(note), "--head", HEAD])
        self.assertEqual(code, 1)
        self.assertIn("reason: stale", stdout)

    def test_current_pass_wins_over_an_older_line(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            note = Path(tmp) / "note.txt"
            note.write_text(f"PASS {OLDER}\nPASS {HEAD}\n", encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(note), "--head", HEAD])
        self.assertEqual(code, 0)
        self.assertIn("reason: pass", stdout)
        self.assertIn("approved: true", stdout)

    def test_later_fail_overrides_an_earlier_pass(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            later_fail = root / "later-fail.txt"
            later_fail.write_text(f"PASS {HEAD}\nnote\nFAIL {HEAD}\n", encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(later_fail), "--head", HEAD])
            self.assertEqual(code, 1)
            self.assertIn("decision: refuse", stdout)
            self.assertIn("reason: no-pass", stdout)
            self.assertIn("approved: false", stdout)

            unbound = root / "unbound-fail.txt"
            unbound.write_text(f"PASS {HEAD}\nFAIL\n", encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(unbound), "--head", HEAD])
            self.assertEqual(code, 1)
            self.assertIn("reason: no-pass", stdout)

            later_pass = root / "later-pass.txt"
            later_pass.write_text(f"FAIL {HEAD}\nPASS {HEAD}\n", encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(later_pass), "--head", HEAD])
            self.assertEqual(code, 0)
            self.assertIn("reason: pass", stdout)
            self.assertIn("approved: true", stdout)

    def test_keyed_pairs_stay_in_file_order(self):
        module = load_script()
        cases = (
            (f"verdict: PASS\nsha: {HEAD}\nFAIL {HEAD}\n", 1, "no-pass"),
            (f"verdict: FAIL\nsha: {HEAD}\nPASS {HEAD}\n", 0, "pass"),
            (f"FAIL {HEAD}\nverdict: PASS\nsha: {HEAD}\n", 0, "pass"),
            (f"PASS {HEAD}\nverdict: FAIL\nsha: {HEAD}\n", 1, "no-pass"),
            (f"verdict: PASS\nFAIL {HEAD}\nsha: {HEAD}\n", 1, "no-pass"),
            (f"verdict: FAIL\nPASS {HEAD}\nsha: {HEAD}\n", 0, "pass"),
            (f"PASS {HEAD}\nverdict: FAIL\nsha: {HEAD}\nPASS {HEAD}\n", 0, "pass"),
            (f"FAIL {HEAD}\nverdict: PASS\nsha: {HEAD}\nFAIL {HEAD}\n", 1, "no-pass"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            note = Path(tmp) / "note.txt"
            for body, code_expected, reason in cases:
                note.write_text(body, encoding="utf-8")
                code, stdout, _stderr = run_main(module, ["--verdict", str(note), "--head", HEAD])
                self.assertEqual(code, code_expected, body)
                self.assertIn(f"reason: {reason}", stdout, body)
                self.assertIn("approved: true" if code_expected == 0 else "approved: false", stdout, body)

    def test_pass_and_fail_are_whole_tokens(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hyphen = root / "hyphen.txt"
            hyphen.write_text(f"PASS-WITH-NOTES {HEAD}\n", encoding="utf-8")
            passing = root / "passing.txt"
            passing.write_text(f"PASSING {HEAD}\n", encoding="utf-8")
            payload = root / "payload.json"
            payload.write_text(
                '{"verdict": "PASS-WITH-NOTES", "sha": "' + HEAD + '"}\n',
                encoding="utf-8",
            )
            for path in (hyphen, passing, payload):
                code, stdout, _stderr = run_main(module, ["--verdict", str(path), "--head", HEAD])
                self.assertEqual(code, 1, path.name)
                self.assertIn("reason: no-pass", stdout)
                self.assertNotIn("reason: pass", stdout)
            notes = root / "notes.txt"
            notes.write_text(f"PASS {HEAD} ship it\n", encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(notes), "--head", HEAD])
            self.assertEqual(code, 0)
            self.assertIn("reason: pass", stdout)
            self.assertIn("approved: true", stdout)

    def test_pass_without_a_sha_refuses(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            note = Path(tmp) / "note.txt"
            note.write_text("verdict: PASS\n", encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(note), "--head", HEAD])
        self.assertEqual(code, 1)
        self.assertIn("reason: missing-sha", stdout)

    def test_keyed_verdict_allows_when_the_sha_matches(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            note = Path(tmp) / "note.txt"
            note.write_text(f"verdict: PASS\nsha: {HEAD}\n", encoding="utf-8")
            code, _stdout, _stderr = run_main(module, ["--verdict", str(note), "--head", HEAD])
        self.assertEqual(code, 0)

    def test_dry_run_prints_the_decision_and_does_not_approve(self):
        module = load_script()
        verdict = KIT / "examples" / "pass-current.json"
        code, stdout, _stderr = run_main(
            module, ["--verdict", str(verdict), "--head", HEAD, "--dry-run"]
        )
        self.assertEqual(code, 0)
        self.assertTrue(stdout.startswith("dry-run\n"))
        self.assertIn("decision: allow", stdout)
        self.assertIn("approved: false", stdout)
        older = KIT / "examples" / "pass-older.json"
        code, stdout, _stderr = run_main(
            module, ["--verdict", str(older), "--head", HEAD, "--dry-run"]
        )
        self.assertEqual(code, 1)
        self.assertIn("dry-run", stdout)
        self.assertIn("reason: stale", stdout)
        self.assertIn("approved: false", stdout)

    def test_bad_input_exits_2(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.txt"
            code, _stdout, stderr = run_main(module, ["--verdict", str(missing), "--head", HEAD])
            self.assertEqual(code, 2)
            self.assertIn("missing", stderr)
            broken = root / "broken.json"
            broken.write_text("{", encoding="utf-8")
            code, _stdout, stderr = run_main(module, ["--verdict", str(broken), "--head", HEAD])
            self.assertEqual(code, 2)
            self.assertIn("not readable", stderr)
            code, _stdout, stderr = run_main(
                module, ["--verdict", str(KIT / "examples" / "pass-current.json"), "--head", "short"]
            )
            self.assertEqual(code, 2)
            self.assertIn("head", stderr)
            code, _stdout, stderr = run_main(
                module,
                ["--verdict", str(KIT / "examples" / "pass-current.json")],
                cwd=root,
            )
            self.assertEqual(code, 2)
            self.assertIn("head", stderr)

    def test_sixty_four_hex_sha_matches_exactly(self):
        module = load_script()
        long_head = "c" * 64
        with tempfile.TemporaryDirectory() as tmp:
            note = Path(tmp) / "note.json"
            note.write_text('{"verdict": "PASS", "sha": "' + long_head + '"}\n', encoding="utf-8")
            code, stdout, _stderr = run_main(module, ["--verdict", str(note), "--head", long_head])
        self.assertEqual(code, 0)
        self.assertIn(f"head: {long_head}", stdout)

    def test_script_does_not_open_the_network(self):
        text = (KIT / "review_gate.py").read_text(encoding="utf-8")
        for needle in (
            "urllib",
            "socket",
            "requests",
            "http.client",
            "api.github.com",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
