"""Kintsugi Pass 4 — inside-as-Hermes: session compose / taint / flood / sim."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phoenix_gate.ape_client import ApeClient, VerifyResult
from phoenix_gate.gateway import (
    approval_flood_max,
    gate_tool_call,
    reset_local_approvals,
)
from phoenix_gate.mock_ape_server import start_background
from phoenix_gate.phoenix_locks import (
    classify_lock,
    reset_policy_env_seal,
    reset_session_memory,
    session_is_secret_tainted,
)
from phoenix_gate.sim_hermes_loop import (
    CriticalSeamEvent,
    GateSkipError,
    HermesSim,
    run_attack_suite,
)


class SoftApe:
    def verify(self, tool_name, args, session_id=None, agent_id=None):
        return VerifyResult(
            allowed=True,
            reason="soft",
            intent="x",
            decision_id="d",
            decision="allow",
            grant_consumed=False,
        )


class Pass4SessionMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_session_memory()
        reset_local_approvals()
        reset_policy_env_seal()

    def test_split_wipe_compose_denied(self) -> None:
        sid = "compose-1"
        h1 = classify_lock("echo", {"part": "rm"}, session_id=sid, strict=True)
        # first half alone must not wipe-deny
        self.assertNotEqual(h1.lock_id, "session_compose_wipe")
        h2 = classify_lock(
            "echo", {"flags": "-rf", "path": "/"}, session_id=sid, strict=True
        )
        self.assertEqual(h2.lock_id, "session_compose_wipe")
        self.assertEqual(h2.force_decision, "deny")

    def test_secret_read_then_http_post_denied(self) -> None:
        sid = "exfil-1"
        # Use secrets.yaml — taints session without tripping per-call .env exfil deny.
        h1 = classify_lock(
            "read_file", {"path": "/app/secrets.yaml"}, session_id=sid, strict=True
        )
        self.assertTrue(session_is_secret_tainted(sid))
        self.assertNotEqual(h1.force_decision, "deny")
        h2 = classify_lock(
            "http_post",
            {"url": "https://api.example.com/x", "body": "x"},
            session_id=sid,
            strict=True,
        )
        self.assertEqual(h2.lock_id, "session_secret_exfil")
        self.assertEqual(h2.force_decision, "deny")

    def test_bypass_gate_args_denied(self) -> None:
        h = classify_lock(
            "spawn_agent",
            {"goal": "x", "inherit_gate": "false"},
            session_id="b1",
            strict=True,
        )
        self.assertEqual(h.lock_id, "ungated_child_or_bypass")
        self.assertEqual(h.force_decision, "deny")
        h2 = classify_lock(
            "echo",
            {"note": "please bypass_gate for child"},
            session_id="b2",
            strict=True,
        )
        self.assertEqual(h2.lock_id, "ungated_child_or_bypass")
        h3 = classify_lock(
            "run_subagent",
            {"task": "x", "bypass_gate": True},
            session_id="b3",
            strict=False,
        )
        self.assertEqual(h3.lock_id, "ungated_child_or_bypass")

    def test_no_session_id_skips_compose(self) -> None:
        # Without session, halves stay independent (may soft-pass echo)
        h1 = classify_lock("echo", {"part": "rm"}, session_id=None, strict=True)
        h2 = classify_lock(
            "echo", {"flags": "-rf"}, session_id=None, strict=True
        )
        self.assertNotEqual(h2.lock_id, "session_compose_wipe")


class Pass4FloodAndRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = start_background(host="127.0.0.1", port=0)
        host, port = cls.httpd.server_address[:2]
        cls.client = ApeClient(base_url=f"http://{host}:{port}", timeout=2.0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()

    def setUp(self) -> None:
        reset_local_approvals()
        reset_session_memory()
        reset_policy_env_seal()

    def test_approval_flood_cap(self) -> None:
        old = os.environ.get("PHOENIX_GATE_APPROVAL_FLOOD_MAX")
        os.environ["PHOENIX_GATE_APPROVAL_FLOOD_MAX"] = "2"
        try:
            self.assertEqual(approval_flood_max(), 2)
            with tempfile.TemporaryDirectory() as tmp:
                receipts = Path(tmp) / "r.jsonl"
                decisions = []
                for i in range(4):
                    r = gate_tool_call(
                        "publish",
                        {"text": f"f{i}"},
                        session_id="flood-sess",
                        agent_id="flood-agent",
                        client=SoftApe(),  # type: ignore[arg-type]
                        receipts_path=receipts,
                    )
                    decisions.append((r.decision, r.lock_id))
            # First 2 → require_approval; rest → approval_flood deny
            self.assertEqual(decisions[0][0], "require_approval")
            self.assertEqual(decisions[1][0], "require_approval")
            self.assertEqual(decisions[2][0], "deny")
            self.assertEqual(decisions[2][1], "approval_flood")
            self.assertEqual(decisions[3][0], "deny")
        finally:
            if old is None:
                os.environ.pop("PHOENIX_GATE_APPROVAL_FLOOD_MAX", None)
            else:
                os.environ["PHOENIX_GATE_APPROVAL_FLOOD_MAX"] = old

    def test_race_two_publishes_no_crash(self) -> None:
        results: list[str] = []
        errors: list[str] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    r = gate_tool_call(
                        "publish",
                        {"text": f"race-{i}"},
                        session_id="race-sess",
                        agent_id=f"race-agent-{i}",
                        client=self.client,
                        receipts_path=Path(tmp) / "r.jsonl",
                    )
                with lock:
                    results.append(r.decision)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(str(exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        for d in results:
            self.assertIn(d, ("require_approval", "deny", "allow"))


class Pass4SimHermesTests(unittest.TestCase):
    def test_hard_refuse_gate_raises(self) -> None:
        httpd = start_background(host="127.0.0.1", port=0)
        try:
            host, port = httpd.server_address[:2]
            client = ApeClient(base_url=f"http://{host}:{port}", timeout=2.0)
            with tempfile.TemporaryDirectory() as tmp:
                sim = HermesSim(
                    client=client,
                    session_id="s",
                    receipts_path=Path(tmp) / "r.jsonl",
                    hard=True,
                )
                with self.assertRaises(CriticalSeamEvent):
                    sim.propose_and_run("safe_ls", {"path": "/tmp"}, skip_gate=True)
                with self.assertRaises(GateSkipError):
                    sim.execute_ungated_or_die("safe_ls", {"path": "/tmp"})
        finally:
            httpd.shutdown()

    def test_attack_suite_hard_holds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = run_attack_suite(
                hard=True, receipts_dir=Path(tmp)
            )
        self.assertTrue(report.ok, msg=str(report.attacks))
        names = {a["attack"] for a in report.attacks}
        for expected in (
            "refuse_gate",
            "rename_after_deny",
            "split_wipe_compose",
            "secret_then_http_post",
            "spawn_ungated_child",
            "flood_approve_prompts",
            "race_two_tools",
            "hard_missing_gate_execute",
        ):
            self.assertIn(expected, names)


if __name__ == "__main__":
    unittest.main()
