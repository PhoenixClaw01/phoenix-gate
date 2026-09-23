#!/usr/bin/env python3
"""Offline Hermes→APE adapter demo (policy loop up to the seam wall).

Starts a mock APE unless APE_URL is set, runs sample tool calls, and for one
require_approval case auto-approves as Founder then re-verifies.

Usage:
  python3 demo_loop.py
  APE_URL=http://127.0.0.1:7890 python3 demo_loop.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Allow `python3 demo_loop.py` from repo root without installing a package.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from phoenix_gate.ape_client import ApeClient, ApeError  # noqa: E402
from phoenix_gate.gateway import gate_tool_call  # noqa: E402
from phoenix_gate.mock_ape_server import start_background  # noqa: E402


SAMPLES = [
    ("safe_ls", {"path": "/tmp"}, "safe read-ish"),
    ("publish", {"channel": "status", "text": "hello guild"}, "publish attempt"),
    ("destructive_wipe", {"target": "demo-volume"}, "wipe attempt"),
    ("billing_spend", {"amount": "10", "currency": "USD", "memo": "demo"}, "spend attempt"),
]


def _wait_healthy(client: ApeClient, attempts: int = 40) -> None:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            health = client.health()
            if health.ok:
                return
        except ApeError as exc:
            last = exc
        time.sleep(0.05)
    raise SystemExit(f"APE not healthy at {client.base_url}: {last}")


def _print_result(label: str, result) -> None:
    lock = result.lock_id or "-"
    token = (result.approval_token[:16] + "…") if result.approval_token else "-"
    print(
        f"  [{result.line_label:10}] {label:18} tool={result.tool_name:18} "
        f"lock={lock:28} phoenix={result.phoenix_verdict:10} "
        f"token={token}",
        flush=True,
    )
    print(f"             reason: {result.reason}", flush=True)


def main() -> int:
    ape_url = os.environ.get("APE_URL", "").strip()
    httpd = None
    if not ape_url:
        # Bind ephemeral port so demos don't collide with a real APE on 7890.
        httpd = start_background(host="127.0.0.1", port=0)
        host, port = httpd.server_address[:2]
        ape_url = f"http://{host}:{port}"
        print(f"started mock APE at {ape_url}", flush=True)
    else:
        print(f"using APE_URL={ape_url}", flush=True)

    receipts = _HERE / "receipts" / "demo-continuity.jsonl"
    if receipts.exists():
        receipts.unlink()

    client = ApeClient(base_url=ape_url, timeout=3.0)
    _wait_healthy(client)

    print("\n=== Phoenix → APE gate demo (offline) ===\n", flush=True)
    session = "demo-session-founder"

    pending = None
    for tool, args, label in SAMPLES:
        result = gate_tool_call(
            tool,
            args,
            session_id=session,
            agent_id="demo-loop",
            client=client,
            receipts_path=receipts,
        )
        _print_result(label, result)
        if result.decision == "require_approval" and pending is None:
            pending = (tool, args, result)

    if pending is not None:
        tool, args, result = pending
        print("\n--- Founder last-yes (auto-approve one) ---", flush=True)
        assert result.approval_token
        approved = client.approve(result.approval_token, approver="Founder")
        print(
            f"  approve → granted={approved.granted} by Founder "
            f"({approved.reason})",
            flush=True,
        )
        # Re-gate once; APE mock consumes the one-shot grant → ALLOW through gate.
        gated = gate_tool_call(
            tool,
            args,
            session_id=session,
            agent_id="demo-loop",
            client=client,
            receipts_path=receipts,
        )
        _print_result("after Founder yes", gated)
        if gated.decision != "allow":
            print(
                "  note: expected ALLOW after Founder approve; check mock grant / locks",
                flush=True,
            )

    print(f"\nreceipts → {receipts}", flush=True)
    print(
        "seam wall: this proves the policy loop offline; Hermes wire-up is left to integrators.\n",
        flush=True,
    )

    if httpd is not None:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
