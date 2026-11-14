"""Behavior checks for the red-team kit. Fixtures are synthetic."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kits" / "red-team"
GATE = ROOT / "kits" / "review-gate" / "review_gate.py"
WHEN = datetime(2026, 11, 14, 5, 0, tzinfo=timezone.utc)


def load_script(name: str):
    path = KIT / name
    spec = importlib.util.spec_from_file_location(f"red_team_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_gate():
    spec = importlib.util.spec_from_file_location("review_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_scrubber():
    path = ROOT / "kits" / "safe-helpers" / "export_scrub.py"
    spec = importlib.util.spec_from_file_location("export_scrub", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_injected():
    path = ROOT / "kits" / "kintsugi-audit" / "injected_instruction_check.py"
    spec = importlib.util.spec_from_file_location("injected_instruction_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_main(module, args: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = module.main(args)
    return code, stdout.getvalue(), stderr.getvalue()


def example(name: str) -> dict:
    return json.loads((KIT / "examples" / name).read_text(encoding="utf-8"))


def checked(module, document, head, *, repo="example/repo", pr=7):
    return module.validate_verdict(document, head=head, repo=repo, pr=pr)


def verdict_cli(path, head, *, repo="example/repo", pr="7") -> list[str]:
    return ["--verdict", str(path), "--head", head, "--repo", repo, "--pr", pr]


def write_verdict(directory: Path, document: dict) -> Path:
    path = directory / "verdict.json"
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    return path


class RedTeamSchemaTests(unittest.TestCase):
    def test_schema_file_lists_the_verdict_fields(self):
        module = load_script("verdict.py")
        schema = json.loads((KIT / "verdict.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["required"], list(module.REQUIRED_FIELDS))
        self.assertEqual(schema["properties"]["verdict"]["enum"], ["PASS", "FAIL"])
        self.assertEqual(
            schema["properties"]["blocking"]["items"]["properties"]["kind"]["enum"],
            ["attacker-reachable", "leak"],
        )
        self.assertEqual(
            schema["properties"]["kintsugi"]["items"]["properties"]["size"]["enum"],
            ["small", "medium", "large"],
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertIn("verdict.py", schema["$comment"])
        self.assertIn("author_id", schema["$comment"])
        self.assertIn("head_sha", schema["$comment"])

    def test_examples_match_the_head_they_name(self):
        module = load_script("verdict.py")
        current = example("pass-current.json")["head_sha"]
        for name in ("pass-current.json", "pass-with-kintsugi.json", "fail-blocking.json"):
            document = example(name)
            accepted = checked(module, document, head=current)
            self.assertEqual(accepted["verdict"], document["verdict"])
            self.assertEqual(accepted["sha"], current)
            self.assertNotEqual(accepted["reviewer_id"], accepted["author_id"])
        stale = example("stale.json")
        with self.assertRaises(module.RedTeamError) as caught:
            checked(module, stale, head=current)
        self.assertEqual(caught.exception.reason, "stale")
        self.assertEqual(checked(module, stale, head=stale["head_sha"])["verdict"], "PASS")

    def test_schema_rejects_a_broken_document(self):
        module = load_script("verdict.py")
        current = example("pass-current.json")["head_sha"]
        base = example("pass-current.json")
        missing = dict(base)
        del missing["repo"]
        extra = dict(base)
        extra["note"] = "aside"
        lowered = dict(base)
        lowered["verdict"] = "pass"
        bad_kind = example("fail-blocking.json")
        bad_kind = json.loads(json.dumps(bad_kind))
        bad_kind["blocking"][0]["kind"] = "style"
        missing_size = example("pass-with-kintsugi.json")
        missing_size = json.loads(json.dumps(missing_size))
        del missing_size["kintsugi"][0]["size"]
        for document in (missing, extra, lowered, bad_kind, missing_size, [], "PASS"):
            with self.assertRaises(module.RedTeamError) as caught:
                checked(module, document, head=current)
            self.assertEqual(caught.exception.reason, "bad-verdict")

    def test_pass_cannot_carry_a_blocking_finding(self):
        module = load_script("verdict.py")
        document = example("pass-current.json")
        document["blocking"] = [
            {"kind": "attacker-reachable", "summary": "an outside input reaches a state change"}
        ]
        with self.assertRaises(module.RedTeamError) as caught:
            checked(module, document, head=document["head_sha"])
        self.assertEqual(caught.exception.reason, "blocking-on-pass")

    def test_kintsugi_repairs_do_not_block(self):
        module = load_script("verdict.py")
        passed = example("pass-with-kintsugi.json")
        accepted = checked(module, passed, head=passed["head_sha"])
        self.assertEqual(accepted["verdict"], "PASS")
        self.assertEqual(accepted["blocking"], [])
        self.assertEqual(accepted["kintsugi"][0]["size"], "small")
        failed = example("pass-current.json")
        failed["verdict"] = "FAIL"
        failed["kintsugi"] = [{"repair": "give the helper a clearer name", "size": "medium"}]
        with self.assertRaises(module.RedTeamError) as caught:
            checked(module, failed, head=failed["head_sha"])
        self.assertEqual(caught.exception.reason, "fail-without-blocking")

    def test_author_and_reviewer_must_differ(self):
        module = load_script("verdict.py")
        document = example("pass-current.json")
        document["reviewer_id"] = document["author_id"]
        with self.assertRaises(module.RedTeamError) as caught:
            checked(module, document, head=document["head_sha"])
        self.assertEqual(caught.exception.reason, "author-is-reviewer")

    def test_sha_must_equal_head_sha(self):
        module = load_script("verdict.py")
        document = example("pass-current.json")
        document["sha"] = example("stale.json")["sha"]
        with self.assertRaises(module.RedTeamError) as caught:
            checked(module, document, head=document["head_sha"])
        self.assertEqual(caught.exception.reason, "sha-mismatch")

    def test_cli_accepts_the_current_head_and_rejects_a_stale_one(self):
        module = load_script("verdict.py")
        current = example("pass-current.json")["head_sha"]
        passed = KIT / "examples" / "pass-current.json"
        code, stdout, stderr = run_main(module, verdict_cli(passed, current.upper()))
        self.assertEqual(code, 0, stderr)
        self.assertIn("decision: accept", stdout)
        self.assertIn("reason: current", stdout)
        self.assertIn(f"head: {current}", stdout)
        self.assertIn("verdict: PASS", stdout)
        stale = KIT / "examples" / "stale.json"
        code, stdout, _stderr = run_main(module, verdict_cli(stale, current))
        self.assertEqual(code, 1)
        self.assertIn("decision: reject", stdout)
        self.assertIn("reason: stale", stdout)
        self.assertNotIn("reason: current", stdout)

    def test_cli_bad_input_exits_2(self):
        module = load_script("verdict.py")
        current = example("pass-current.json")["head_sha"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.json"
            code, _stdout, stderr = run_main(module, verdict_cli(missing, current))
            self.assertEqual(code, 2)
            self.assertIn("missing", stderr)
            broken = root / "broken.json"
            broken.write_text("{", encoding="utf-8")
            code, _stdout, stderr = run_main(module, verdict_cli(broken, current))
            self.assertEqual(code, 2)
            self.assertIn("not readable", stderr)
        code, _stdout, stderr = run_main(
            module, verdict_cli(KIT / "examples" / "pass-current.json", "short")
        )
        self.assertEqual(code, 2)
        self.assertIn("head", stderr)
        code, _stdout, stderr = run_main(
            module, verdict_cli(KIT / "examples" / "pass-current.json", current, repo="not-a-repo")
        )
        self.assertEqual(code, 2)
        self.assertIn("target", stderr)

    def test_repo_and_pr_must_match_the_target(self):
        module = load_script("verdict.py")
        document = example("pass-current.json")
        with self.assertRaises(module.RedTeamError) as repo_miss:
            checked(module, document, document["head_sha"], repo="example/other")
        self.assertEqual(repo_miss.exception.reason, "repo-mismatch")
        with self.assertRaises(module.RedTeamError) as pr_miss:
            checked(module, document, document["head_sha"], pr=8)
        self.assertEqual(pr_miss.exception.reason, "pr-mismatch")
        self.assertEqual(checked(module, document, document["head_sha"], pr="7")["verdict"], "PASS")

    def test_a_current_fail_prints_valid(self):
        module = load_script("verdict.py")
        current = example("fail-blocking.json")["head_sha"]
        failed = KIT / "examples" / "fail-blocking.json"
        code, stdout, stderr = run_main(module, verdict_cli(failed, current))
        self.assertEqual(code, 0, stderr)
        self.assertIn("decision: valid", stdout)
        self.assertIn("verdict: FAIL", stdout)
        self.assertNotIn("decision: accept", stdout)


class RedTeamRoutingTests(unittest.TestCase):
    def test_route_selects_the_backend_for_the_lane(self):
        module = load_script("routing.py")
        head = example("pass-current.json")["head_sha"]
        config = module.ReviewerConfig(
            (
                module.ReviewerRoute("reviewer-gamma", "local", ("*",)),
                module.ReviewerRoute("reviewer-beta", "local-alt", ("breakage",)),
                module.ReviewerRoute("reviewer-alpha", "local", ("default",)),
            )
        )
        job = module.ReviewJob("example/repo", 7, head, "author-one", lane="breakage")
        route = module.select_reviewer(config, job)
        self.assertEqual(route.reviewer_id, "reviewer-beta")
        self.assertEqual(route.backend, "local-alt")
        local_calls = {"n": 0}
        alt_calls = {"n": 0}

        class Counting:
            def __init__(self, bucket, draft):
                self.bucket = bucket
                self.draft = draft

            def review(self, review_job):
                self.bucket["n"] += 1
                self.assert_job(review_job)
                return self.draft

            def assert_job(self, review_job):
                if review_job.author_id != "author-one":
                    raise AssertionError(review_job.author_id)

        draft = module.ReviewDraft(verdict="PASS", kintsugi=({"repair": "give the helper a clearer name", "size": "small"},))
        backends = {
            "local": Counting(local_calls, module.ReviewDraft(verdict="PASS")),
            "local-alt": Counting(alt_calls, draft),
        }
        document = module.dispatch(config, job, backends, now=WHEN)
        self.assertEqual(local_calls["n"], 0)
        self.assertEqual(alt_calls["n"], 1)
        self.assertEqual(document["reviewer_id"], "reviewer-beta")
        self.assertEqual(document["author_id"], "author-one")
        self.assertEqual(document["sha"], head)
        self.assertEqual(document["head_sha"], head)
        self.assertEqual(document["kintsugi"][0]["size"], "small")
        self.assertEqual(document["timestamp"], "2026-11-14T05:00:00Z")

    def test_author_is_not_selected_to_review(self):
        module = load_script("routing.py")
        head = example("pass-current.json")["head_sha"]
        only_author = module.ReviewerConfig(
            (module.ReviewerRoute("author-one", "local", ("default",)),)
        )
        job = module.ReviewJob("example/repo", 7, head, "author-one")
        calls = {"n": 0}

        class Recorder:
            def review(self, _job):
                calls["n"] += 1
                return module.ReviewDraft(verdict="PASS")

        with self.assertRaises(module.RedTeamError) as caught:
            module.dispatch(only_author, job, {"local": Recorder()})
        self.assertEqual(caught.exception.reason, "author-is-reviewer")
        self.assertEqual(calls["n"], 0)
        fallback = module.ReviewerConfig(
            (
                module.ReviewerRoute("author-one", "local", ("breakage",)),
                module.ReviewerRoute("reviewer-gamma", "local", ("*",)),
            )
        )
        routed = module.select_reviewer(
            fallback, module.ReviewJob("example/repo", 7, head, "author-one", lane="breakage")
        )
        self.assertEqual(routed.reviewer_id, "reviewer-gamma")
        with self.assertRaises(module.RedTeamError) as built:
            module.build_verdict(
                job,
                job.author_id,
                module.ReviewDraft(verdict="PASS"),
                timestamp="2026-11-14T05:00:00Z",
            )
        self.assertEqual(built.exception.reason, "author-is-reviewer")

    def test_unknown_backend_and_empty_local_adapter_refuse(self):
        module = load_script("routing.py")
        head = example("pass-current.json")["head_sha"]
        config = module.load_config(example("reviewer-config.json"))
        job = module.ReviewJob("example/repo", 7, head, "author-one", lane="breakage")
        route = module.select_reviewer(config, job)
        self.assertEqual(route.reviewer_id, "reviewer-beta")
        self.assertEqual(route.backend, "local")
        with self.assertRaises(module.RedTeamError) as missing:
            module.dispatch(config, job, {}, now=WHEN)
        self.assertEqual(missing.exception.reason, "unknown-backend")
        with self.assertRaises(module.RedTeamError) as local:
            module.dispatch(config, job, module.builtin_backends(), now=WHEN)
        self.assertEqual(local.exception.reason, "local-adapter-does-not-review")

    def test_cli_prints_the_route_and_skips_the_author(self):
        module = load_script("routing.py")
        head = example("pass-current.json")["head_sha"]
        config = KIT / "examples" / "reviewer-config.json"
        code, stdout, stderr = run_main(
            module,
            [
                "--config",
                str(config),
                "--repo",
                "example/repo",
                "--pr",
                "7",
                "--head",
                head,
                "--author",
                "author-one",
                "--lane",
                "default",
            ],
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("decision: route", stdout)
        self.assertIn("reviewer: reviewer-alpha", stdout)
        self.assertIn("backend: local", stdout)
        self.assertNotIn("verdict:", stdout)
        code, stdout, _stderr = run_main(
            module,
            [
                "--config",
                str(config),
                "--repo",
                "example/repo",
                "--pr",
                "7",
                "--head",
                head,
                "--author",
                "reviewer-alpha",
                "--lane",
                "default",
            ],
        )
        self.assertEqual(code, 1)
        self.assertIn("reason: author-is-reviewer", stdout)
        code, stdout, _stderr = run_main(
            module,
            [
                "--config",
                str(config),
                "--repo",
                "example/repo",
                "--pr",
                "7",
                "--head",
                head,
                "--author",
                "author-one",
                "--lane",
                "breakage",
            ],
        )
        self.assertEqual(code, 0)
        self.assertIn("reviewer: reviewer-beta", stdout)
        self.assertIn("backend: local", stdout)

    def test_cli_refuses_an_unregistered_backend(self):
        module = load_script("routing.py")
        head = example("pass-current.json")["head_sha"]
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "routes": [
                            {
                                "reviewer_id": "reviewer-alpha",
                                "backend": "other",
                                "lanes": ["default"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            code, stdout, _stderr = run_main(
                module,
                [
                    "--config",
                    str(config),
                    "--repo",
                    "example/repo",
                    "--pr",
                    "7",
                    "--head",
                    head,
                    "--author",
                    "author-one",
                    "--lane",
                    "default",
                ],
            )
        self.assertEqual(code, 1)
        self.assertIn("reason: unknown-backend", stdout)
        self.assertNotIn("decision: route", stdout)

    def test_a_missing_lane_has_no_reviewer(self):
        module = load_script("routing.py")
        head = example("pass-current.json")["head_sha"]
        config = module.load_config(example("reviewer-config.json"))
        job = module.ReviewJob("example/repo", 7, head, "author-one", lane="docs")
        with self.assertRaises(module.RedTeamError) as caught:
            module.select_reviewer(config, job)
        self.assertEqual(caught.exception.reason, "no-reviewer")


class RedTeamReviewGateTests(unittest.TestCase):
    def test_pass_verdict_is_accepted_by_review_gate(self):
        verdict = load_script("verdict.py")
        routing = load_script("routing.py")
        gate = load_gate()
        head = example("pass-current.json")["head_sha"]
        config = routing.ReviewerConfig(
            (routing.ReviewerRoute("reviewer-alpha", "local", ("default",)),)
        )
        job = routing.ReviewJob("example/repo", 7, head, "author-one")
        draft = routing.ReviewDraft(
            verdict="PASS",
            kintsugi=({"repair": "give the helper a clearer name", "size": "small"},),
        )
        document = routing.dispatch(config, job, {"local": routing.LocalMockAdapter(draft)}, now=WHEN)
        self.assertEqual(
            verdict.validate_verdict(
                document, head=head, repo=document["repo"], pr=document["pr"]
            )["verdict"],
            "PASS",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = write_verdict(Path(tmp), document)
            code, stdout, stderr = run_main(gate, ["--verdict", str(path), "--head", head])
        self.assertEqual(code, 0, stderr)
        self.assertIn("decision: allow", stdout)
        self.assertIn("reason: pass", stdout)
        self.assertIn("approved: true", stdout)
        self.assertIn(f"head: {head}", stdout)
        fixture = KIT / "examples" / "pass-current.json"
        code, stdout, stderr = run_main(gate, ["--verdict", str(fixture), "--head", head])
        self.assertEqual(code, 0, stderr)
        self.assertIn("approved: true", stdout)

    def test_stale_and_fail_verdicts_are_refused_by_review_gate(self):
        gate = load_gate()
        head = example("pass-current.json")["head_sha"]
        stale = KIT / "examples" / "stale.json"
        code, stdout, _stderr = run_main(gate, ["--verdict", str(stale), "--head", head])
        self.assertEqual(code, 1)
        self.assertIn("reason: stale", stdout)
        self.assertIn("approved: false", stdout)
        failed = KIT / "examples" / "fail-blocking.json"
        code, stdout, _stderr = run_main(gate, ["--verdict", str(failed), "--head", head])
        self.assertEqual(code, 1)
        self.assertIn("reason: no-pass", stdout)
        self.assertIn("approved: false", stdout)

    def test_sixty_four_hex_sha_is_accepted_by_review_gate(self):
        routing = load_script("routing.py")
        gate = load_gate()
        head = "c0" * 32
        self.assertEqual(len(head), 64)
        config = routing.ReviewerConfig((routing.ReviewerRoute("reviewer-alpha", "local", ("default",)),))
        job = routing.ReviewJob("example/repo", 7, head, "author-one")
        document = routing.dispatch(
            config,
            job,
            {"local": routing.LocalMockAdapter(routing.ReviewDraft(verdict="PASS"))},
            now=WHEN,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = write_verdict(Path(tmp), document)
            code, stdout, stderr = run_main(gate, ["--verdict", str(path), "--head", head])
        self.assertEqual(code, 0, stderr)
        self.assertIn("approved: true", stdout)
        self.assertIn(f"head: {head}", stdout)


class RedTeamPublicCopyTests(unittest.TestCase):
    def test_kit_text_has_no_generic_hits_and_does_not_open_the_network(self):
        scrubber = load_scrubber()
        hits = []
        for path in sorted(KIT.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            text = path.read_text(encoding="utf-8")
            found = scrubber.hits(text)
            if found or scrubber.scrub(text) != text:
                hits.append(f"{path.relative_to(ROOT)} {found}")
        self.assertEqual(hits, [])
        for name in ("verdict.py", "routing.py"):
            text = (KIT / name).read_text(encoding="utf-8")
            for needle in ("urllib", "socket", "requests", "http.client", "httpx", "aiohttp"):
                self.assertNotIn(needle, text, name)

    def test_prompt_has_no_injected_instruction_and_readmes_link_the_kit(self):
        findings = load_injected().scan(KIT)
        self.assertEqual(findings, [])
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("(kits/red-team/README.md)", readme)
        index = (ROOT / "kits" / "README.md").read_text(encoding="utf-8")
        self.assertIn("(red-team/README.md)", index)
        prompt = (KIT / "REVIEW-PROMPT.md").read_text(encoding="utf-8")
        self.assertIn("attacker-reachable", prompt)
        self.assertIn("kintsugi", prompt)


if __name__ == "__main__":
    unittest.main()
