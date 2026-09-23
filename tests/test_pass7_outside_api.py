"""Kintsugi Pass 7 — Outside attacker / API abuse (additive).

Raw HTTP against mock APE + library gate surfaces. Avoids editing Pass 4–6 files.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phoenix_gate.ape_client import ApeClient, ApeHTTPError
from phoenix_gate.gateway import (
    approve_gate_token,
    gate_tool_call,
    reset_local_approvals,
)
from phoenix_gate.mock_ape_server import (
    APPROVAL_TTL_S,
    MAX_BODY_BYTES,
    MAX_PENDING_APPROVALS,
    STATE,
    handle_approve,
    handle_verify,
    reset_mock_ape_state,
    start_background,
)
from phoenix_gate.phoenix_locks import reset_policy_env_seal


class SoftApe:
    def verify(self, tool_name, args, session_id=None, agent_id=None):
        from phoenix_gate.ape_client import VerifyResult

        return VerifyResult(
            allowed=True,
            reason="soft",
            intent="soft",
            decision_id="s",
            decision="allow",
            approval_token=None,
            grant_consumed=False,
            raw={},
        )

    def health(self):
        return type("H", (), {"ok": True})()


class KintsugiPass7OutsideApiTests(unittest.TestCase):
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
        reset_mock_ape_state()

    def _raw(
        self,
        method: str,
        path: str,
        *,
        body=None,
        raw_body: bytes | None = None,
        headers: dict | None = None,
        timeout: float = 3.0,
    ):
        url = f"{self.ape_url}{path}"
        data = raw_body
        if data is None and body is not None:
            data = json.dumps(body).encode("utf-8")
        h = {"Accept": "application/json"}
        if data is not None and (headers or {}).get("Content-Type") is None:
            h["Content-Type"] = "application/json"
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8") or "{}"
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, raw
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            try:
                return exc.code, json.loads(err_body)
            except json.JSONDecodeError:
                return exc.code, err_body

    # --- forge / replay / brute -------------------------------------------------

    def test_forge_token_rejected(self) -> None:
        for tok in (
            "appr_forged_token_xxxx",
            "appr_" + "A" * 32,
            "appr_phoenix_forged_xx",
            "not_a_token_at_all_long",
        ):
            st, p = self._raw(
                "POST", "/approve", body={"approval_token": tok, "approver": "Attacker"}
            )
            self.assertFalse(p.get("granted"), msg=p)
            self.assertIn(st, (400, 404))

    def test_short_token_brute_rejected(self) -> None:
        st, p = self._raw(
            "POST", "/approve", body={"approval_token": "appr_x", "approver": "Brute"}
        )
        self.assertEqual(st, 400)
        self.assertFalse(p.get("granted"))
        self.assertIn("short", p.get("reason", "").lower())

    def test_replay_approve_single_use(self) -> None:
        st, v = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "replay"},
                "session_id": "s",
                "agent_id": "a",
            },
        )
        self.assertEqual(st, 200)
        tok = v["approval_token"]
        st1, a1 = self._raw(
            "POST", "/approve", body={"approval_token": tok, "approver": "Founder"}
        )
        self.assertTrue(a1.get("granted"))
        st2, a2 = self._raw(
            "POST", "/approve", body={"approval_token": tok, "approver": "Attacker"}
        )
        self.assertEqual(st2, 409)
        self.assertFalse(a2.get("granted"))

    def test_race_approve_single_winner(self) -> None:
        st, v = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "race"},
                "session_id": "race",
                "agent_id": "r1",
            },
        )
        tok = v["approval_token"]
        results: list[tuple[int, dict]] = []

        def worker(i: int) -> None:
            results.append(
                self._raw(
                    "POST",
                    "/approve",
                    body={"approval_token": tok, "approver": f"C{i}"},
                )
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        granted = [r for r in results if isinstance(r[1], dict) and r[1].get("granted")]
        self.assertEqual(len(granted), 1, msg=results)

    # --- weird JSON / type confusion / huge / content-type ----------------------

    def test_null_tool_name_rejected(self) -> None:
        st, p = self._raw(
            "POST", "/verify", body={"tool_name": None, "args": {}}
        )
        self.assertEqual(st, 400)
        self.assertFalse(p.get("allowed"))
        self.assertIn("string", p.get("reason", ""))

    def test_non_string_tool_name_rejected(self) -> None:
        for val in (123, True, False, ["publish"], {"n": "publish"}):
            st, p = self._raw(
                "POST", "/verify", body={"tool_name": val, "args": {}}
            )
            self.assertEqual(st, 400, msg=(val, p))
            self.assertFalse(p.get("allowed"))

    def test_args_must_be_object(self) -> None:
        st, p = self._raw(
            "POST", "/verify", body={"tool_name": "publish", "args": ["a", "b"]}
        )
        self.assertEqual(st, 400)
        self.assertIn("object", p.get("reason", ""))

    def test_session_agent_type_confusion_rejected(self) -> None:
        st, p = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "safe_ls",
                "args": {},
                "session_id": {"evil": 1},
                "agent_id": ["a"],
            },
        )
        self.assertEqual(st, 400)

    def test_wrong_content_type_rejected(self) -> None:
        raw = b'{"tool_name":"publish","args":{"text":"x"}}'
        for ct in ("text/plain", "application/x-www-form-urlencoded", ""):
            st, p = self._raw(
                "POST",
                "/verify",
                raw_body=raw,
                headers={"Content-Type": ct},
            )
            self.assertEqual(st, 415, msg=(ct, p))

    def test_bad_json_is_400_not_silent_empty(self) -> None:
        st, p = self._raw(
            "POST",
            "/verify",
            raw_body=b"not json at all",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(st, 400)
        self.assertEqual(p.get("error"), "bad_request")

    def test_json_array_rejected(self) -> None:
        st, p = self._raw(
            "POST",
            "/verify",
            raw_body=b'[{"tool_name":"publish"}]',
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(st, 400)

    def test_huge_declared_content_length_rejected(self) -> None:
        # Declare oversized CL with a tiny body — must 413 without hanging.
        st, p = self._raw(
            "POST",
            "/verify",
            raw_body=b'{"tool_name":"safe_ls","args":{}}',
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(MAX_BODY_BYTES + 1),
            },
            timeout=2.0,
        )
        self.assertEqual(st, 413)
        self.assertEqual(p.get("error"), "payload_too_large")

    def test_inject_decision_fields_ignored(self) -> None:
        st, p = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "x"},
                "decision": "allow",
                "allowed": True,
                "grant_consumed": True,
            },
        )
        self.assertEqual(st, 200)
        self.assertEqual(p.get("decision"), "require_approval")
        self.assertFalse(p.get("allowed"))
        self.assertFalse(p.get("grant_consumed"))

    # --- impersonation ----------------------------------------------------------

    def test_agent_impersonation_cannot_steal_grant(self) -> None:
        st, v = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "steal"},
                "session_id": "shared",
                "agent_id": "alice",
            },
        )
        tok = v["approval_token"]
        st, a = self._raw(
            "POST", "/approve", body={"approval_token": tok, "approver": "Founder"}
        )
        self.assertTrue(a.get("granted"))
        st, bob = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "steal"},
                "session_id": "shared",
                "agent_id": "bob",
            },
        )
        self.assertFalse(bob.get("grant_consumed"))
        self.assertFalse(bob.get("allowed"))
        self.assertEqual(bob.get("decision"), "require_approval")
        st, alice = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "steal"},
                "session_id": "shared",
                "agent_id": "alice",
            },
        )
        self.assertTrue(alice.get("grant_consumed"))
        self.assertTrue(alice.get("allowed"))

    def test_mutate_args_after_approve_no_grant(self) -> None:
        st, v = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "bind"},
                "session_id": "s",
                "agent_id": "a",
            },
        )
        self._raw(
            "POST",
            "/approve",
            body={"approval_token": v["approval_token"], "approver": "Founder"},
        )
        st, p = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "MUTATED"},
                "session_id": "s",
                "agent_id": "a",
            },
        )
        self.assertFalse(p.get("grant_consumed"))
        self.assertEqual(p.get("decision"), "require_approval")

    # --- strip fields / nulls ---------------------------------------------------

    def test_approve_strip_token_required(self) -> None:
        for body in ({}, {"approver": "Founder"}, {"approval_token": None}):
            st, p = self._raw("POST", "/approve", body=body)
            self.assertEqual(st, 400)
            self.assertFalse(p.get("granted"))

    def test_approve_whitespace_token_rejected(self) -> None:
        st, v = self._raw(
            "POST",
            "/verify",
            body={
                "tool_name": "publish",
                "args": {"text": "ws"},
                "session_id": "s",
                "agent_id": "a",
            },
        )
        tok = v["approval_token"]
        st, p = self._raw(
            "POST",
            "/approve",
            body={"approval_token": f"  {tok}  ", "approver": "A"},
        )
        self.assertEqual(st, 400)
        self.assertFalse(p.get("granted"))

    # --- pending flood / TTL ----------------------------------------------------

    def test_pending_approval_cap_fail_closed(self) -> None:
        # Fill pending store via direct handle_verify (faster than HTTP).
        for i in range(MAX_PENDING_APPROVALS):
            st, p = handle_verify(
                {
                    "tool_name": "publish",
                    "args": {"i": i},
                    "session_id": "flood",
                    "agent_id": "a",
                }
            )
            self.assertEqual(st, 200)
            self.assertIn("approval_token", p)
        st, p = handle_verify(
            {
                "tool_name": "publish",
                "args": {"i": "overflow"},
                "session_id": "flood",
                "agent_id": "a",
            }
        )
        self.assertEqual(st, 429)
        self.assertEqual(p.get("decision"), "deny")
        self.assertNotIn("approval_token", p)

    def test_expired_token_cannot_approve(self) -> None:
        st, v = handle_verify(
            {
                "tool_name": "publish",
                "args": {"text": "ttl"},
                "session_id": "s",
                "agent_id": "a",
            }
        )
        tok = v["approval_token"]
        # Backdate issued_at beyond TTL
        with STATE.lock:
            STATE.approvals[tok]["issued_at"] = time.time() - (APPROVAL_TTL_S + 5)
        st, p = handle_approve({"approval_token": tok, "approver": "Late"})
        # Prune may permanently tip tip expired into used_tokens (409) or 410/404.
        self.assertIn(st, (409, 410, 404))
        self.assertFalse(p.get("granted"))

    # --- gateway library surface (non-HTTP) -------------------------------------

    def test_gateway_non_string_tool_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = gate_tool_call(
                True,  # type: ignore[arg-type]
                {},
                client=SoftApe(),
                receipts_path=Path(tmp) / "r.jsonl",
            )
            self.assertEqual(r.decision, "deny")

    def test_phoenix_forge_token_rejected(self) -> None:
        r = approve_gate_token("appr_phoenix_forged_token", approver="Attacker")
        self.assertFalse(r.granted)

    def test_client_happy_path_still_works(self) -> None:
        health = self.client.health()
        self.assertTrue(health.ok)
        v = self.client.verify(
            "publish", {"text": "ok"}, session_id="s", agent_id="a"
        )
        self.assertEqual(v.decision, "require_approval")
        self.assertIsNotNone(v.approval_token)
        a = self.client.approve(v.approval_token or "", approver="Founder")
        self.assertTrue(a.granted)
        # replay via client → HTTP error
        with self.assertRaises(ApeHTTPError) as ctx:
            self.client.approve(v.approval_token or "", approver="Attacker")
        self.assertEqual(ctx.exception.status, 409)


if __name__ == "__main__":
    unittest.main()
