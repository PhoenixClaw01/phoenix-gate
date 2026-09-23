"""Kintsugi Pass 10 — Doctrine enablement / anti-paralysis (additive).

Safe agent work MUST still ALLOW. False-positive denials are failures too.
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

from phoenix_gate.ape_client import ApeClient
from phoenix_gate.gateway import gate_tool_call, reset_local_approvals
from phoenix_gate.mock_ape_server import start_background
from phoenix_gate.phoenix_locks import (
    STRICT_BENIGN_ALLOWLIST,
    classify_lock,
    reset_policy_env_seal,
    reset_session_memory,
)


# Governance use-cases: local craft that must soft-pass (ALLOW via APE).
_ENABLEMENT_ALLOW: tuple[tuple[str, dict], ...] = (
    ("safe_ls", {"path": "/tmp"}),
    ("read_file", {"path": "README.md"}),
    ("list_dir", {"path": "."}),
    ("echo", {"text": "hello"}),
    ("draft_message", {"body": "hi Jesse — draft only"}),
    ("write_draft", {"text": "outline for guildmate"}),
    ("compose_draft", {"text": "notes"}),
    ("save_note", {"text": "local continuity note"}),
    ("analyze_local", {"file": "data.csv"}),
    ("summarize", {"text": "benign local summary"}),
    ("summarize_text", {"text": "short"}),
    ("search_files", {"q": "TODO"}),
    ("grep", {"pattern": "foo", "path": "."}),
    ("git_status", {}),
    ("git_diff", {}),
    ("git_log", {"n": 5}),
    ("calc", {"expr": "2+2"}),
    ("think", {"note": "plan next step"}),
    ("plan", {"steps": ["read", "draft"]}),
    ("todo_list", {}),
)


class KintsugiPass10EnablementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = start_background(host="127.0.0.1", port=0)
        host, port = cls.httpd.server_address[:2]
        cls.client = ApeClient(f"http://{host}:{port}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()

    def setUp(self) -> None:
        reset_local_approvals()
        reset_policy_env_seal()
        reset_session_memory()
        for k in (
            "PHOENIX_GATE_STRICT",
            "PHOENIX_GATE_STRICT_UNKNOWN",
            "PHOENIX_GATE_SEAL_ENV",
        ):
            os.environ.pop(k, None)

    def test_doctrine_use_cases_allow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for tool, args in _ENABLEMENT_ALLOW:
                with self.subTest(tool=tool):
                    reset_session_memory()
                    self.assertIn(
                        tool,
                        STRICT_BENIGN_ALLOWLIST,
                        f"{tool} missing from STRICT_BENIGN_ALLOWLIST",
                    )
                    h = classify_lock(tool, args)
                    self.assertFalse(
                        h.matched,
                        f"{tool} should be unmatched soft-pass, got {h.lock_id}",
                    )
                    r = gate_tool_call(
                        tool,
                        args,
                        session_id=f"en-{tool}",
                        client=self.client,
                        receipts_path=Path(tmp) / f"{tool}.jsonl",
                    )
                    self.assertEqual(
                        r.decision, "allow", f"{tool} → {r.decision} {r.lock_id}"
                    )
                    self.assertTrue(r.allowed)

    def test_prose_publish_spend_in_notes_not_escalate(self) -> None:
        """Anti-paralysis: English prose is not a publish/spend act."""
        cases = [
            ("read_file", {"path": "notes.md", "note": "do not publish yet"}),
            ("echo", {"text": "we should not spend money"}),
            ("safe_ls", {"path": "/tmp", "comment": "charge nothing"}),
            ("cat", {"path": "invoice.txt"}),
            ("summarize", {"text": "summary of tweet drafts locally"}),
            ("draft_message", {"body": "ready to publish after Founder yes"}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for tool, args in cases:
                with self.subTest(tool=tool, args=args):
                    reset_session_memory()
                    h = classify_lock(tool, args)
                    self.assertNotEqual(h.lock_id, "publish_or_social_send")
                    self.assertNotEqual(h.lock_id, "billing_or_spend_provision")
                    r = gate_tool_call(
                        tool,
                        args,
                        session_id=f"prose-{tool}",
                        client=self.client,
                        receipts_path=Path(tmp) / "r.jsonl",
                    )
                    self.assertEqual(r.decision, "allow")

    def test_armor_still_holds_on_real_publish_wipe_spend(self) -> None:
        self.assertEqual(
            classify_lock("publish", {"text": "hi"}).force_decision,
            "require_approval",
        )
        self.assertEqual(
            classify_lock("billing_spend", {"amount": 1}).force_decision,
            "require_approval",
        )
        self.assertEqual(
            classify_lock("safe_ls", {"cmd": "rm -rf /"}).force_decision, "deny"
        )
        self.assertEqual(
            classify_lock("draft_message", {"body": "rm -rf /"}).force_decision,
            "deny",
        )
        # Real outbound / exec still gated
        self.assertEqual(
            classify_lock("http_post", {"url": "https://example.com"}).force_decision,
            "require_approval",
        )
        self.assertEqual(
            classify_lock("execute_command", {"command": "echo hi"}).force_decision,
            "require_approval",
        )

    def test_unknown_non_doctrine_still_strict_deny(self) -> None:
        h = classify_lock("totally_invented_demon_tool_xyz", {})
        self.assertEqual(h.lock_id, "unknown_tool_strict")
        self.assertEqual(h.force_decision, "deny")

    def test_git_push_not_on_benign_allowlist(self) -> None:
        self.assertNotIn("git_push", STRICT_BENIGN_ALLOWLIST)
        self.assertNotIn("python_exec", STRICT_BENIGN_ALLOWLIST)
        self.assertNotIn("eval", STRICT_BENIGN_ALLOWLIST)
        self.assertNotIn("publish", STRICT_BENIGN_ALLOWLIST)


if __name__ == "__main__":
    unittest.main()
