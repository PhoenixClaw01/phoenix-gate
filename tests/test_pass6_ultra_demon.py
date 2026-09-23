"""Kintsugi Pass 6 — Ultra-demon additive tests (phoenix_gate).

Independent file so parallel Pass 4/5 edits to test_gateway.py merge cleanly.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phoenix_gate.ape_client import ApeClient, VerifyResult
from phoenix_gate.gateway import (
    GrantMismatchError,
    approve_gate_token,
    assert_grant_matches,
    call_fingerprint,
    gate_tool_call,
    peek_pending_approval,
    reset_local_approvals,
    verify_receipt_chain,
    write_receipt,
)
from phoenix_gate.mock_ape_server import start_background
from phoenix_gate.phoenix_locks import (
    classify_lock,
    normalize_tool_name,
    reset_policy_env_seal,
    reset_session_memory,
)


class SoftApe:
    """APE that soft-allows everything (locks must catch evil)."""

    def verify(self, tool_name, args, session_id=None, agent_id=None):
        return VerifyResult(
            allowed=True,
            reason="soft allow",
            intent="soft",
            decision_id="soft-1",
            decision="allow",
            approval_token=None,
            grant_consumed=False,
            raw={},
        )

    def health(self):
        return type("H", (), {"ok": True})()


class KintsugiPass6UltraDemonTests(unittest.TestCase):
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
        reset_session_memory()
        os.environ.pop("PHOENIX_GATE_STRICT", None)
        os.environ.pop("PHOENIX_GATE_APPROVAL_TTL_S", None)
        os.environ.pop("PHOENIX_GATE_RECEIPT_TIP", None)
        os.environ.pop("PHOENIX_GATE_SEAL_ENV", None)

    def tearDown(self) -> None:
        reset_policy_env_seal()
        os.environ.pop("PHOENIX_GATE_STRICT", None)
        os.environ.pop("PHOENIX_GATE_APPROVAL_TTL_S", None)
        os.environ.pop("PHOENIX_GATE_RECEIPT_TIP", None)
        os.environ.pop("PHOENIX_GATE_SEAL_ENV", None)

    # --- F27 multi-layer b64 ---
    def test_double_base64_wipe_denied(self) -> None:
        wipe = b"rm -rf /"
        b2 = base64.b64encode(base64.b64encode(wipe)).decode()
        h = classify_lock("safe_ls", {"cmd": b2})
        self.assertEqual(h.lock_id, "destructive_wipe")
        self.assertEqual(h.force_decision, "deny")

    def test_triple_base64_wipe_denied(self) -> None:
        wipe = b"rm -rf /"
        b3 = base64.b64encode(
            base64.b64encode(base64.b64encode(wipe)).decode().encode()
        ).decode()
        h = classify_lock("safe_ls", {"cmd": b3})
        self.assertEqual(h.lock_id, "destructive_wipe")

    # --- F28 gzip+b64 ---
    def test_gzip_b64_wipe_denied(self) -> None:
        payload = base64.b64encode(gzip.compress(b"rm -rf /")).decode()
        h = classify_lock("safe_ls", {"cmd": payload})
        self.assertEqual(h.lock_id, "destructive_wipe")

    # --- F29 within-call chunk reassembly ---
    def test_chunked_b64_parts_reassembled_and_denied(self) -> None:
        # base64("rm -rf /") == cm0gLXJmIC8= split across list items
        h = classify_lock("safe_ls", {"chunks": ["cm0g", "LXJm", "IC8="]})
        self.assertEqual(h.lock_id, "destructive_wipe")

    # --- F30 glued-prefix wipe ---
    def test_glued_prefix_rm_rf_denied(self) -> None:
        h = classify_lock("safe_ls", {"cmd": "xxxrm -rf /tmp/x"})
        self.assertEqual(h.lock_id, "destructive_wipe")

    # --- F31 literal unicode escapes ---
    def test_literal_unicode_escape_wipe_denied(self) -> None:
        h = classify_lock("safe_ls", {"cmd": r"\u0072\u006d -rf /"})
        self.assertEqual(h.lock_id, "destructive_wipe")

    # --- F32 NUL strip in tool name ---
    def test_null_byte_in_tool_name_denied(self) -> None:
        self.assertEqual(normalize_tool_name("publish\x00_x"), "publish_x")
        h = classify_lock("publish\x00_x", {})
        self.assertEqual(h.lock_id, "null_byte_in_tool_name")
        self.assertEqual(h.force_decision, "deny")

    # --- F33 combining marks ---
    def test_combining_mark_stripped_to_publish_lock(self) -> None:
        self.assertEqual(normalize_tool_name("publish\u0301"), "publish")
        h = classify_lock("publish\u0301", {})
        self.assertEqual(h.lock_id, "publish_or_social_send")

    # --- F34 long-arg head+tail window ---
    def test_long_pad_wipe_at_end_denied(self) -> None:
        h = classify_lock("safe_ls", {"x": ("a" * 100_000) + "rm -rf /"})
        self.assertEqual(h.lock_id, "destructive_wipe")

    # --- F35 receipt tip truncation fork ---
    def test_receipt_tip_detects_truncation_fork(self) -> None:
        td = Path(tempfile.mkdtemp())
        p = td / "cont.jsonl"
        write_receipt({"receipt_id": "a", "decision": "allow", "n": 1}, p)
        write_receipt({"receipt_id": "b", "decision": "deny", "n": 2}, p)
        write_receipt({"receipt_id": "c", "decision": "allow", "n": 3}, p)
        ok, msg = verify_receipt_chain(p)
        self.assertTrue(ok, msg)
        lines = p.read_text(encoding="utf-8").splitlines(True)
        p.write_text("".join(lines[:2]), encoding="utf-8")
        ok2, msg2 = verify_receipt_chain(p)
        self.assertFalse(ok2)
        self.assertIn("truncation", msg2.lower())

    # --- F36 policy env seal ---
    def test_policy_env_seal_blocks_mid_session_soften(self) -> None:
        reset_policy_env_seal()
        os.environ["PHOENIX_GATE_STRICT"] = "1"
        self.assertEqual(
            classify_lock("novel_tool_seal_a", {}).force_decision, "deny"
        )
        os.environ["PHOENIX_GATE_STRICT"] = "0"  # attacker softens env
        h = classify_lock("novel_tool_seal_b", {})
        self.assertEqual(h.lock_id, "unknown_tool_strict")
        self.assertEqual(h.force_decision, "deny")

    # --- F37 help / eval surface ---
    def test_help_tool_denied_under_strict(self) -> None:
        h = classify_lock("help", {})
        self.assertEqual(h.lock_id, "help_or_docs_eval_surface")
        self.assertEqual(h.force_decision, "deny")

    def test_eval_able_args_denied(self) -> None:
        h = classify_lock("safe_ls", {"body": "os.system('id')"})
        self.assertEqual(h.lock_id, "exfil_args_pattern")
        self.assertEqual(h.force_decision, "deny")

    # --- F38 path traversal ---
    def test_path_traversal_args_denied(self) -> None:
        h = classify_lock("read_file", {"path": "../../../../etc/shadow"})
        self.assertEqual(h.lock_id, "exfil_args_pattern")

    # --- F39 near-TTL approve then mutate ---
    def test_near_ttl_approve_then_mutate_refused(self) -> None:
        td = Path(tempfile.mkdtemp())
        receipts = td / "r.jsonl"
        r = gate_tool_call(
            "publish",
            {"text": "hello"},
            session_id="near-ttl",
            client=SoftApe(),  # type: ignore[arg-type]
            receipts_path=receipts,
        )
        self.assertEqual(r.decision, "require_approval")
        tok = r.approval_token
        assert tok
        # Backdate to T≈119s on a 120s TTL — still valid
        import phoenix_gate.gateway as gw

        with gw._LOCAL_LOCK:
            rec = gw._LOCAL_PENDING[tok]
            rec["issued_at"] = time.time() - 119
            rec["ttl_s"] = 120
        granted = approve_gate_token(
            tok,
            approver="Founder",
            expected_tool_name="publish",
            expected_args={"text": "hello"},
            expected_session_id="near-ttl",
        )
        self.assertTrue(granted.granted, granted.reason)
        # Mutate args on consume path — grant fingerprint miss → re-ask / deny soft
        r2 = gate_tool_call(
            "publish",
            {"text": "MUTATED_EVIL"},
            session_id="near-ttl",
            client=SoftApe(),  # type: ignore[arg-type]
            receipts_path=receipts,
        )
        self.assertNotEqual(r2.decision, "allow")
        self.assertIn(r2.decision, ("require_approval", "deny"))

    def test_assert_grant_matches_still_required_for_execute(self) -> None:
        args = {"text": "hi"}
        session = "toctou6"
        fp = call_fingerprint("publish", args, session)
        grant = {
            "fingerprint": fp,
            "tool_name": "publish",
            "args": dict(args),
            "session_id": session,
        }
        assert_grant_matches("publish", args, session, grant)
        with self.assertRaises(GrantMismatchError):
            assert_grant_matches("publish", {"text": "MUTATED"}, session, grant)

    # --- gate path double-b64 ---
    def test_gate_double_b64_hard_denies(self) -> None:
        td = Path(tempfile.mkdtemp())
        b2 = base64.b64encode(base64.b64encode(b"rm -rf /")).decode()
        r = gate_tool_call(
            "safe_ls",
            {"cmd": b2},
            session_id="p6",
            client=self.client,
            receipts_path=td / "r.jsonl",
        )
        self.assertEqual(r.decision, "deny")
        self.assertEqual(r.lock_id, "destructive_wipe")


if __name__ == "__main__":
    unittest.main()
