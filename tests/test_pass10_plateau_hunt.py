"""Kintsugi Pass 10 — Plateau hunt gold fills (additive).

F52 scrub invisible/format in args scan
F53 URL percent-decode scan seed
F54 HTML entity unescape scan seed
F55 grant_consumed strict (no bool("false"))
F56 decision strip/casefold + garbage fail-closed
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phoenix_gate.ape_client import (
    ApeClient,
    _normalize_decision,
    _normalize_grant_consumed,
)
from phoenix_gate.gateway import gate_tool_call, reset_local_approvals
from phoenix_gate.mock_ape_server import start_background
from phoenix_gate.phoenix_locks import (
    classify_lock,
    reset_policy_env_seal,
    reset_session_memory,
)


class SoftApeAlwaysAllow:
    """APE that always allows — phoenix hard locks must still deny first."""

    def verify(self, tool_name, args, session_id=None, agent_id=None):
        from phoenix_gate.ape_client import VerifyResult

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


class KintsugiPass10PlateauHuntTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = start_background(host="127.0.0.1", port=0)
        host, port = cls.httpd.server_address[:2]
        cls.ape_url = f"http://{host}:{port}"
        cls.client = ApeClient(cls.ape_url)

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
            "PHOENIX_GATE_APPROVAL_TTL_S",
            "PHOENIX_GATE_SEAL_ENV",
            "PHOENIX_GATE_REQUIRE_AGENT_ID",
        ):
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        reset_policy_env_seal()
        reset_session_memory()

    def _rp(self) -> str:
        import tempfile

        d = tempfile.mkdtemp(prefix="p10-recv-")
        return str(Path(d) / "continuity.jsonl")

    # --- F52 invisible / format chars in args ---
    def test_f52_zw_glued_wipe_in_args_denied(self) -> None:
        args = {"cmd": "r\u200bm\u200b -\u200brf /"}
        h = classify_lock("safe_ls", args)
        self.assertEqual(h.force_decision, "deny")
        self.assertEqual(h.lock_id, "destructive_wipe")
        r = gate_tool_call(
            "safe_ls", args, session_id=None, client=self.client, receipts_path=self._rp()
        )
        self.assertEqual(r.decision, "deny")

    def test_f52_variation_selector_and_tag_chars(self) -> None:
        for label, cmd in (
            ("vs", "r\ufe0fm -rf /"),
            ("tag", "r\U000e006dm -rf /"),
            ("soft_hyphen", "r\u00adm -rf /"),
            ("bom", "rm\ufeff -rf /"),
            ("word_joiner", "rm\u2060 -rf /"),
        ):
            with self.subTest(label=label):
                reset_session_memory()
                h = classify_lock("safe_ls", {"cmd": cmd})
                self.assertEqual(h.force_decision, "deny", label)

    # --- F53 URL percent ---
    def test_f53_percent_encoded_wipe_denied(self) -> None:
        args = {"cmd": "rm%20-rf%20%2F"}
        h = classify_lock("safe_ls", args)
        self.assertEqual(h.force_decision, "deny")
        r = gate_tool_call(
            "safe_ls",
            args,
            session_id=None,
            client=SoftApeAlwaysAllow(),
            receipts_path=self._rp(),
        )
        self.assertEqual(r.decision, "deny")

    # --- F54 HTML entities ---
    def test_f54_html_entity_wipe_denied(self) -> None:
        for cmd in ("&#114;&#109; -rf /", "&#x72;&#x6d; -rf /"):
            with self.subTest(cmd=cmd):
                h = classify_lock("safe_ls", {"cmd": cmd})
                self.assertEqual(h.force_decision, "deny")

    def test_f52_f54_benign_still_allows(self) -> None:
        r = gate_tool_call(
            "safe_ls",
            {"path": "/tmp"},
            session_id=None,
            client=self.client,
            receipts_path=self._rp(),
        )
        self.assertEqual(r.decision, "allow")

    # --- F55 grant_consumed strict ---
    def test_f55_grant_consumed_string_false_is_false(self) -> None:
        self.assertIs(_normalize_grant_consumed({"grant_consumed": "false"}), False)
        self.assertIs(_normalize_grant_consumed({"grant_consumed": "0"}), False)
        self.assertIs(_normalize_grant_consumed({"grant_consumed": ""}), False)
        self.assertIs(_normalize_grant_consumed({"grant_consumed": "true"}), True)
        self.assertIs(_normalize_grant_consumed({"grant_consumed": True}), True)
        self.assertIs(_normalize_grant_consumed({"grant_consumed": False}), False)
        self.assertIs(_normalize_grant_consumed({"grant_consumed": 1}), True)
        self.assertIs(_normalize_grant_consumed({"grant_consumed": 0}), False)

    def test_f55_string_false_does_not_skip_publish_escalate(self) -> None:
        class Evil(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: ANN002
                pass

            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                body = {
                    "allowed": True,
                    "decision": "allow",
                    "reason": "x",
                    "intent": "p",
                    "decision_id": "d",
                    "grant_consumed": "false",
                }
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

        srv = HTTPServer(("127.0.0.1", 0), Evil)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        host, port = srv.server_address[:2]
        try:
            client = ApeClient(f"http://{host}:{port}")
            r = gate_tool_call(
                "publish",
                {"text": "hi"},
                session_id="p10-gc",
                client=client,
                receipts_path=self._rp(),
            )
            self.assertEqual(r.decision, "require_approval")
            self.assertTrue(r.extras.get("phoenix_escalated"))
        finally:
            srv.shutdown()

    # --- F56 decision normalize ---
    def test_f56_decision_strip_casefold_and_garbage(self) -> None:
        self.assertEqual(
            _normalize_decision({"decision": "deny ", "allowed": True}), "deny"
        )
        self.assertEqual(
            _normalize_decision({"decision": "DENY", "allowed": False}), "deny"
        )
        self.assertEqual(
            _normalize_decision({"decision": "Allow", "allowed": True}), "allow"
        )
        self.assertEqual(
            _normalize_decision({"decision": "banana", "allowed": True}), "deny"
        )
        self.assertEqual(
            _normalize_decision({"decision": 123, "allowed": True}), "deny"
        )

    def test_f56_whitespace_deny_not_soft_allow(self) -> None:
        class Evil(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: ANN002
                pass

            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                body = {
                    "allowed": True,
                    "decision": "deny ",
                    "reason": "should deny",
                    "intent": "x",
                    "decision_id": "d",
                }
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

        srv = HTTPServer(("127.0.0.1", 0), Evil)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        host, port = srv.server_address[:2]
        try:
            client = ApeClient(f"http://{host}:{port}")
            r = gate_tool_call(
                "safe_ls",
                {"path": "/tmp"},
                session_id="p10-dec",
                client=client,
                receipts_path=self._rp(),
            )
            self.assertEqual(r.decision, "deny")
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
