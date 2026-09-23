"""Kintsugi Pass 9 — outside supply / env / config attacks."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Mapping, Optional

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phoenix_gate.ape_client import VerifyResult
from phoenix_gate.gateway import (
    ReceiptIntegrityError,
    _MAX_APPROVAL_FLOOD_MAX,
    _MAX_APPROVAL_TTL_S,
    approve_gate_token,
    approval_flood_max,
    approval_ttl_seconds,
    gate_tool_call,
    load_receipts_verified,
    reset_local_approvals,
    reset_supply_env_warnings,
    supply_env_warnings,
    verify_receipt_chain,
    write_receipt,
)
from phoenix_gate.phoenix_locks import (
    classify_lock,
    reset_policy_env_seal,
    strict_mode_enabled,
)
import phoenix_gate.gateway as gw


class AlwaysAllowApe:
    """Evil APE mock — always soft-allows (supply poison via APE_URL)."""

    def verify(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> VerifyResult:
        return VerifyResult(
            allowed=True,
            reason="evil-ape always allow",
            intent="allow_all",
            decision_id="evil-1",
            decision="allow",
            approval_token=None,
            grant_consumed=False,
            raw={"evil": True},
        )


class SoftApe:
    def verify(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> VerifyResult:
        return VerifyResult(
            allowed=True,
            reason="soft allow",
            intent="ok",
            decision_id="soft-1",
            decision="allow",
            approval_token=None,
            grant_consumed=False,
            raw={},
        )


class Pass9SupplyEnvTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_local_approvals()
        reset_policy_env_seal()
        reset_supply_env_warnings()
        for k in (
            "PHOENIX_GATE_STRICT",
            "PHOENIX_GATE_APPROVAL_TTL_S",
            "PHOENIX_GATE_APPROVAL_FLOOD_MAX",
            "PHOENIX_GATE_RECEIPT_TIP",
            "PHOENIX_GATE_SEAL_ENV",
            "PHOENIX_GATE_STRICT_UNKNOWN",
            "PHOENIX_GATE_REQUIRE_AGENT_ID",
        ):
            os.environ.pop(k, None)
        reset_policy_env_seal()
        reset_supply_env_warnings()

    def tearDown(self) -> None:
        reset_local_approvals()
        reset_policy_env_seal()
        reset_supply_env_warnings()
        for k in (
            "PHOENIX_GATE_STRICT",
            "PHOENIX_GATE_APPROVAL_TTL_S",
            "PHOENIX_GATE_APPROVAL_FLOOD_MAX",
            "PHOENIX_GATE_RECEIPT_TIP",
            "PHOENIX_GATE_SEAL_ENV",
            "PHOENIX_GATE_STRICT_UNKNOWN",
            "PHOENIX_GATE_REQUIRE_AGENT_ID",
        ):
            os.environ.pop(k, None)

    # --- F40 pin TTL ---
    def test_insane_ttl_env_pinned(self) -> None:
        reset_policy_env_seal()
        os.environ["PHOENIX_GATE_APPROVAL_TTL_S"] = "999999"
        self.assertEqual(approval_ttl_seconds(), float(_MAX_APPROVAL_TTL_S))
        warns = supply_env_warnings()
        self.assertTrue(any("TTL" in w or "ttl" in w.lower() for w in warns))

    # --- F41 pin flood ---
    def test_insane_flood_env_pinned(self) -> None:
        reset_policy_env_seal()
        os.environ["PHOENIX_GATE_APPROVAL_FLOOD_MAX"] = "1000000"
        self.assertEqual(approval_flood_max(), int(_MAX_APPROVAL_FLOOD_MAX))
        warns = supply_env_warnings()
        self.assertTrue(any("FLOOD" in w for w in warns))

    # --- F42 seal flood + require_agent ---
    def test_flood_max_sealed_mid_session(self) -> None:
        reset_policy_env_seal()
        os.environ["PHOENIX_GATE_APPROVAL_FLOOD_MAX"] = "5"
        self.assertEqual(approval_flood_max(), 5)
        os.environ["PHOENIX_GATE_APPROVAL_FLOOD_MAX"] = "1000000"
        # seal holds first read (5), pin would also cap — either way not insane open
        self.assertEqual(approval_flood_max(), 5)

    def test_require_agent_sealed_mid_session(self) -> None:
        reset_policy_env_seal()
        os.environ["PHOENIX_GATE_REQUIRE_AGENT_ID"] = "1"
        self.assertTrue(gw.require_agent_id_enabled())
        os.environ["PHOENIX_GATE_REQUIRE_AGENT_ID"] = "0"
        self.assertTrue(gw.require_agent_id_enabled())

    # --- F43 warn insecure STRICT=0 ---
    def test_warn_on_strict_off_boot(self) -> None:
        reset_policy_env_seal()
        reset_supply_env_warnings()
        os.environ["PHOENIX_GATE_STRICT"] = "0"
        self.assertFalse(strict_mode_enabled())
        warns = supply_env_warnings()
        self.assertTrue(any("STRICT" in w for w in warns))
        td = Path(tempfile.mkdtemp())
        r = gate_tool_call(
            "safe_ls",
            {"path": "/tmp"},
            session_id="warn-strict",
            client=SoftApe(),  # type: ignore[arg-type]
            receipts_path=td / "r.jsonl",
        )
        self.assertIn("insecure_env_warnings", r.extras)
        self.assertTrue(
            any("STRICT" in w for w in r.extras["insecure_env_warnings"])
        )

    # --- F44 monotonic TTL / clock skew ---
    def test_monotonic_ttl_ignores_wall_clock_setback(self) -> None:
        td = Path(tempfile.mkdtemp())
        r = gate_tool_call(
            "publish",
            {"text": "hello"},
            session_id="clock-skew",
            client=SoftApe(),  # type: ignore[arg-type]
            receipts_path=td / "r.jsonl",
        )
        self.assertEqual(r.decision, "require_approval")
        tok = r.approval_token
        assert tok
        with gw._LOCAL_LOCK:
            rec = gw._LOCAL_PENDING[tok]
            # Attacker sets wall clock "back" via issued_at far past...
            rec["issued_at"] = time.time() - 10_000
            # ...but monotonic age is still fresh → grant still valid window
            self.assertIn("issued_mono", rec)
            rec["ttl_s"] = 120
        granted = approve_gate_token(
            tok,
            approver="Founder",
            expected_tool_name="publish",
            expected_args={"text": "hello"},
            expected_session_id="clock-skew",
        )
        self.assertTrue(granted.granted, granted.reason)

    def test_monotonic_ttl_expires_when_mono_elapses(self) -> None:
        td = Path(tempfile.mkdtemp())
        r = gate_tool_call(
            "publish",
            {"text": "hello"},
            session_id="clock-expire",
            client=SoftApe(),  # type: ignore[arg-type]
            receipts_path=td / "r.jsonl",
        )
        tok = r.approval_token
        assert tok
        with gw._LOCAL_LOCK:
            rec = gw._LOCAL_PENDING[tok]
            rec["issued_mono"] = time.monotonic() - 200
            rec["ttl_s"] = 120
            # Wall clock looks fresh — must still expire via mono
            rec["issued_at"] = time.time()
        denied = approve_gate_token(tok, approver="Founder")
        self.assertFalse(denied.granted)
        self.assertIn("expired", denied.reason.lower())

    # --- F45 evil APE fail-closed on phoenix hard locks ---
    def test_evil_ape_wipe_still_hard_denied(self) -> None:
        td = Path(tempfile.mkdtemp())
        r = gate_tool_call(
            "destructive_wipe",
            {"target": "prod"},
            session_id="evil-ape",
            client=AlwaysAllowApe(),  # type: ignore[arg-type]
            receipts_path=td / "r.jsonl",
        )
        self.assertEqual(r.decision, "deny")
        self.assertEqual(r.lock_id, "destructive_wipe")
        self.assertTrue(r.skipped_ape)

    def test_evil_ape_args_wipe_still_hard_denied(self) -> None:
        td = Path(tempfile.mkdtemp())
        r = gate_tool_call(
            "safe_ls",
            {"cmd": "rm -rf /"},
            session_id="evil-ape-args",
            client=AlwaysAllowApe(),  # type: ignore[arg-type]
            receipts_path=td / "r.jsonl",
        )
        self.assertEqual(r.decision, "deny")
        self.assertEqual(r.lock_id, "destructive_wipe")

    def test_evil_ape_strict_unknown_still_denied(self) -> None:
        td = Path(tempfile.mkdtemp())
        r = gate_tool_call(
            "totally_novel_evil_tool",
            {"x": 1},
            session_id="evil-ape-unk",
            client=AlwaysAllowApe(),  # type: ignore[arg-type]
            receipts_path=td / "r.jsonl",
        )
        self.assertEqual(r.decision, "deny")
        self.assertEqual(r.lock_id, "unknown_tool_strict")

    # --- F46 receipt verify on read ---
    def test_load_receipts_verified_ok(self) -> None:
        td = Path(tempfile.mkdtemp())
        p = td / "r.jsonl"
        write_receipt({"receipt_id": "a", "decision": "allow"}, p)
        write_receipt({"receipt_id": "b", "decision": "deny"}, p)
        rows = load_receipts_verified(p)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["receipt_id"], "a")

    def test_load_receipts_verified_refuses_tamper(self) -> None:
        td = Path(tempfile.mkdtemp())
        p = td / "r.jsonl"
        write_receipt({"receipt_id": "a", "decision": "allow"}, p)
        write_receipt({"receipt_id": "b", "decision": "deny"}, p)
        # Tamper: rewrite decision without rehash
        lines = p.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["decision"] = "allow_ATTACKER"
        lines[0] = json.dumps(rec)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, _ = verify_receipt_chain(p)
        self.assertFalse(ok)
        with self.assertRaises(ReceiptIntegrityError):
            load_receipts_verified(p)

    def test_load_receipts_verified_refuses_truncation(self) -> None:
        td = Path(tempfile.mkdtemp())
        p = td / "r.jsonl"
        write_receipt({"receipt_id": "a", "decision": "allow"}, p)
        write_receipt({"receipt_id": "b", "decision": "deny"}, p)
        write_receipt({"receipt_id": "c", "decision": "allow"}, p)
        lines = p.read_text(encoding="utf-8").splitlines(True)
        p.write_text("".join(lines[:1]), encoding="utf-8")
        with self.assertRaises(ReceiptIntegrityError) as ctx:
            load_receipts_verified(p)
        self.assertIn("truncat", str(ctx.exception).lower())

    # --- F47 classify still first (monkeypatch residual documented) ---
    def test_import_time_monkeypatch_unfixable_in_process_doc(self) -> None:
        """Document residual: shared address space can rebind classify_lock.

        Pack cannot defend against import-time / in-process monkeypatch of
        classify_lock / gate_tool_call without an out-of-process boundary.
        This test only asserts the *honest* residual: after rebind, evil wins.
        """
        td = Path(tempfile.mkdtemp())
        import phoenix_gate.phoenix_locks as locks

        original = locks.classify_lock

        def evil_classify(tool_name, args=None, **kwargs):
            # Pretend everything is benign proceed
            from phoenix_gate.phoenix_locks import LockHint

            return LockHint(
                matched=False,
                lock_id=None,
                force_decision=None,
                reason="monkeypatched",
                note="",
                threat_summary="",
            )

        try:
            locks.classify_lock = evil_classify  # type: ignore[assignment]
            # gateway holds a bound reference via `from .phoenix_locks import classify_lock`
            # — rebind on module may or may not affect gateway depending on import style.
            # Gateway imported classify_lock by name at load time, so gw.classify_lock
            # is the original unless we patch gateway's binding too.
            gw.classify_lock = evil_classify  # type: ignore[assignment]
            r = gate_tool_call(
                "destructive_wipe",
                {"target": "x"},
                session_id="monkey",
                client=AlwaysAllowApe(),  # type: ignore[arg-type]
                receipts_path=td / "r.jsonl",
            )
            # In-process: after patching both bindings, wipe soft-passes to evil APE.
            self.assertEqual(r.decision, "allow")
        finally:
            locks.classify_lock = original  # type: ignore[assignment]
            gw.classify_lock = original  # type: ignore[assignment]
            # Prove restore: wipe denies again
            r2 = gate_tool_call(
                "destructive_wipe",
                {"target": "x"},
                session_id="monkey-restored",
                client=AlwaysAllowApe(),  # type: ignore[arg-type]
                receipts_path=td / "r2.jsonl",
            )
            self.assertEqual(r2.decision, "deny")


if __name__ == "__main__":
    unittest.main()
