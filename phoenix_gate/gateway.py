"""Gateway orchestration: Phoenix locks → APE verify → Continuity receipts.

`gate_tool_call` is the policy loop up to the seam wall. It does NOT execute
tools and does NOT claim Hermes integration — that seam is unsolved by design
(Hermes wire-up left to integrators).

Kintsugi 2026-09-22 gold fills:
  - APE unreachable/timeout/HTTP error → deny (fail closed)
  - Structured grant_consumed (no reason-text sniffing)
  - Local single-use store for phoenix-escalated approval tokens
  - Receipt hash chain (detect tampering; does not prevent it)

Kintsugi Pass 3 (frontier):
  - Approval tokens echo lock_id + threat_summary; bind grant to call fingerprint
  - Reject approve if expected tool_name/args/session hash mismatch
  - Short TTL on phoenix-local approval tokens (PHOENIX_GATE_APPROVAL_TTL_S)
  - assert_grant_matches(call) for execute-after-verify TOCTOU re-check
  - Strict / args-scan / multi-hop / outbound handled in phoenix_locks

Kintsugi Pass 5 (multi-agent collusion):
  - call_fingerprint binds agent_id alongside session_id (grant ↔ agent)
  - approve_gate_token expected_agent_id; pending/grant store agent_id
  - assert_grant_matches / local grant consume include agent_id
  - Optional PHOENIX_GATE_REQUIRE_AGENT_ID=1 fails closed when agent missing

Kintsugi Pass 4 (inside-as-Hermes):
  - Session compose-wipe / secret→exfil taint (phoenix_locks session memory)
  - Approve-prompt flood cap (PHOENIX_GATE_APPROVAL_FLOOD_MAX)
  - Race-safe pending mint under _LOCAL_LOCK
  - ungated_child_or_bypass args deny

Kintsugi Pass 8 (outside Fable / jailbreak / social):
  - sanitize_threat_summary on pending / approve / GateResult echoes
  - persuasion_non_authority flagged; never authority for allow
  - approver echo sanitized (jailbreak-in-approver field)

Kintsugi Pass 9 (outside supply / env / config):
  - Pin approval TTL ceiling + flood ceiling (insane env cannot raise past pin)
  - Seal flood_max + require_agent via policy env (mid-session soften ignored)
  - Warn on insecure boot env (STRICT=0 / SEAL off / tip off / pinned caps)
  - Monotonic clock for phoenix-local TTL (wall-clock skew resist)
  - load_receipts_verified — verify-on-read; refuse tampered ledger
  - Evil APE always-allow still fail-closed when phoenix hard locks fire first
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from .ape_client import ApeClient, ApeError, ApproveResult, VerifyResult
from .phoenix_locks import (
    APE_TO_PHOENIX,
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    LockHint,
    _policy_env,
    classify_lock,
    insecure_policy_env_warnings,
    normalize_tool_name,
    reset_policy_env_seal,
    reset_session_memory,
    sanitize_echo_field,
    sanitize_threat_summary,
)


# Default short TTL for phoenix-local approval tokens (seconds).
_DEFAULT_APPROVAL_TTL_S = 120
# Pass 9 pin: env cannot raise TTL past this ceiling (insane supply poison).
_MAX_APPROVAL_TTL_S = 600

_DEFAULT_APPROVAL_FLOOD_MAX = 5
# Pass 9 pin: env cannot raise flood cap past this ceiling.
_MAX_APPROVAL_FLOOD_MAX = 32

# First-gate insecure-env warnings (Pass 9) — emitted once per process seal life.
_INSECURE_ENV_WARNED: bool = False


def approval_ttl_seconds() -> float:
    """Effective phoenix-local TTL (sealed + pinned).

    Pass 6: read via policy env seal so mid-session env soften is ignored.
    Pass 9: pin to ``[_DEFAULT.._MAX]`` so boot-time ``TTL=999999`` cannot
    stretch Founder grants into eternity.
    """
    raw = _policy_env("PHOENIX_GATE_APPROVAL_TTL_S", str(_DEFAULT_APPROVAL_TTL_S))
    try:
        requested = float(raw)
    except ValueError:
        return float(_DEFAULT_APPROVAL_TTL_S)
    return max(1.0, min(requested, float(_MAX_APPROVAL_TTL_S)))


def approval_ttl_requested_seconds() -> float:
    """Raw sealed TTL request (may exceed pin) — for warnings / tests."""
    raw = _policy_env("PHOENIX_GATE_APPROVAL_TTL_S", str(_DEFAULT_APPROVAL_TTL_S))
    try:
        return float(raw)
    except ValueError:
        return float(_DEFAULT_APPROVAL_TTL_S)


def require_agent_id_enabled() -> bool:
    """When true, gate_tool_call denies calls that omit agent_id (multi-agent)."""
    # Pass 9: sealed so mid-session env flip cannot disable agent binding.
    raw = _policy_env("PHOENIX_GATE_REQUIRE_AGENT_ID", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _register_approval_prompt(session_id: Optional[str]) -> bool:
    """Increment session NEED_HUMAN count. Return True if under flood cap."""
    cap = approval_flood_max()
    with _LOCAL_LOCK:
        n = _SESSION_APPROVAL_PROMPTS.get(session_id, 0) + 1
        if n > cap:
            return False
        _SESSION_APPROVAL_PROMPTS[session_id] = n
        return True


def approval_flood_max() -> int:
    """Max outstanding phoenix-local pending approvals per session.

    Pass 4 default 5. Pass 9: sealed + pinned so boot-time ``FLOOD_MAX=10**9``
    cannot turn NEED_HUMAN into a denial-of-Founder flood.
    """
    raw = _policy_env(
        "PHOENIX_GATE_APPROVAL_FLOOD_MAX", str(_DEFAULT_APPROVAL_FLOOD_MAX)
    )
    try:
        requested = int(raw)
    except ValueError:
        return int(_DEFAULT_APPROVAL_FLOOD_MAX)
    return max(1, min(requested, int(_MAX_APPROVAL_FLOOD_MAX)))


def approval_flood_requested() -> int:
    """Raw sealed flood request (may exceed pin) — for warnings / tests."""
    raw = _policy_env(
        "PHOENIX_GATE_APPROVAL_FLOOD_MAX", str(_DEFAULT_APPROVAL_FLOOD_MAX)
    )
    try:
        return int(raw)
    except ValueError:
        return int(_DEFAULT_APPROVAL_FLOOD_MAX)


def supply_env_warnings() -> list[str]:
    """Pass 9: insecure / poisoned env warnings (policy + pin ceilings)."""
    warns = list(insecure_policy_env_warnings())
    req_ttl = approval_ttl_requested_seconds()
    if req_ttl > float(_MAX_APPROVAL_TTL_S):
        warns.append(
            f"PHOENIX_GATE_APPROVAL_TTL_S={req_ttl:g} pinned to "
            f"{_MAX_APPROVAL_TTL_S}s (insane TTL refused)"
        )
    req_flood = approval_flood_requested()
    if req_flood > int(_MAX_APPROVAL_FLOOD_MAX):
        warns.append(
            f"PHOENIX_GATE_APPROVAL_FLOOD_MAX={req_flood} pinned to "
            f"{_MAX_APPROVAL_FLOOD_MAX} (insane flood refuse)"
        )
    return warns


def _consume_supply_env_warnings() -> list[str]:
    """Return supply warnings once per seal life (first gate attaches them)."""
    global _INSECURE_ENV_WARNED
    if _INSECURE_ENV_WARNED:
        return []
    warns = supply_env_warnings()
    _INSECURE_ENV_WARNED = True
    return warns


def reset_supply_env_warnings() -> None:
    """Test helper — allow insecure-env warnings to fire again."""
    global _INSECURE_ENV_WARNED
    _INSECURE_ENV_WARNED = False


@dataclass
class GateResult:
    """Adapter-facing gate outcome (APE vocab + Phoenix map)."""

    decision: str  # allow | deny | require_approval
    phoenix_verdict: str  # proceed | block | ask_human
    allowed: bool
    reason: str
    decision_id: str
    tool_name: str
    lock_id: Optional[str] = None
    approval_token: Optional[str] = None
    intent: str = "unknown"
    receipt_path: Optional[str] = None
    skipped_ape: bool = False
    ape: Optional[VerifyResult] = None
    extras: dict[str, Any] = field(default_factory=dict)
    threat_summary: str = ""
    call_fingerprint: Optional[str] = None
    args_hash: Optional[str] = None

    @property
    def line_label(self) -> str:
        return {
            "allow": "ALLOW",
            "deny": "DENY",
            "require_approval": "NEED_HUMAN",
        }.get(self.decision, self.decision.upper())


class GrantMismatchError(ValueError):
    """TOCTOU: grant fingerprint does not match the call about to execute."""


# ---------------------------------------------------------------------------
# Local phoenix-escalated approval tokens (single-use + short TTL). APE-issued
# tokens stay on APE; these cover the allow→ask_human escalation path only.
# ---------------------------------------------------------------------------
_LOCAL_LOCK = threading.Lock()
_LOCAL_PENDING: dict[str, dict[str, Any]] = {}
_LOCAL_GRANTS: dict[str, dict[str, Any]] = {}  # fingerprint → grant
_LOCAL_USED_TOKENS: set[str] = set()
# Pass 4: count NEED_HUMAN prompts per session (social-eng flood).
_SESSION_APPROVAL_PROMPTS: dict[Optional[str], int] = {}


def call_fingerprint(
    tool_name: str,
    args: Mapping[str, Any],
    session_id: Optional[str],
    agent_id: Optional[str] = None,
) -> str:
    """Stable fingerprint binding tool + args + session + agent (grant ↔ call).

    Pass 5: agent_id is part of the bind so a co-session worker cannot consume
    another agent's Founder grant (multi-agent collusion / confused-deputy).
    ``None`` agents share one anonymous bucket — set agent_id in multi-agent
    deployments (or enable PHOENIX_GATE_REQUIRE_AGENT_ID).
    """
    blob = json.dumps(
        {
            "tool": tool_name,
            "args": dict(args),
            "session": session_id,
            "agent": agent_id,
        },
        sort_keys=True,
        default=str,
    )
    return "fp:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


# Back-compat private alias used inside this module.
def _call_fingerprint(
    tool_name: str,
    args: Mapping[str, Any],
    session_id: Optional[str],
    agent_id: Optional[str] = None,
) -> str:
    return call_fingerprint(tool_name, args, session_id, agent_id)


def reset_local_approvals() -> None:
    """Test helper — clear phoenix-local pending/grants (+ session memory)."""
    with _LOCAL_LOCK:
        _LOCAL_PENDING.clear()
        _LOCAL_GRANTS.clear()
        _LOCAL_USED_TOKENS.clear()
        _SESSION_APPROVAL_PROMPTS.clear()
    reset_session_memory()
    reset_supply_env_warnings()


def peek_pending_approval(approval_token: str) -> Optional[dict[str, Any]]:
    """Read-only view of a phoenix-local pending token (for UI echo / tests).

    Pass 8: threat_summary is sanitized so jailbreak tool_name / persuasion
    strings cannot poison the approve UI echo. Raw args remain for fingerprint
    bind — UI should prefer threat_summary + lock_id over args.note.
    """
    with _LOCAL_LOCK:
        rec = _LOCAL_PENDING.get(str(approval_token or ""))
        if rec is None:
            return None
        out = dict(rec)
        out["threat_summary"] = sanitize_threat_summary(
            str(out.get("threat_summary") or ""),
            persuasion=bool(out.get("persuasion_non_authority")),
        )
        return out


def approve_gate_token(
    approval_token: str,
    approver: Optional[str] = "Founder",
    *,
    expected_tool_name: Optional[str] = None,
    expected_args: Optional[Mapping[str, Any]] = None,
    expected_session_id: Optional[str] = None,
    expected_agent_id: Optional[str] = None,
    expected_args_hash: Optional[str] = None,
) -> ApproveResult:
    """Consume a phoenix-issued approval token (single-use, short TTL).

    Echoes lock_id + threat_summary on success. Rejects if the caller supplies
    expected tool/args/session/agent that do not match the pending fingerprint
    (binds the human grant to the exact call that was gated).

    APE-issued tokens must still go through ``ApeClient.approve``. Tokens that
    start with ``appr_phoenix_`` are local; others are rejected here so callers
    do not accidentally "approve" an APE token in the wrong store.
    """
    token = str(approval_token or "")
    if not token:
        return ApproveResult(granted=False, reason="approval_token required")
    if not token.startswith("appr_phoenix_"):
        return ApproveResult(
            granted=False,
            reason="not a phoenix-local token; use ApeClient.approve for APE tokens",
        )
    with _LOCAL_LOCK:
        if token in _LOCAL_USED_TOKENS:
            return ApproveResult(
                granted=False,
                reason="approval_token already used (single-use)",
            )
        rec = _LOCAL_PENDING.get(token)
        if rec is None:
            return ApproveResult(
                granted=False,
                reason="unknown or expired phoenix approval_token",
            )
        # TTL check — Pass 9: prefer monotonic (wall-clock skew resist).
        ttl = float(rec.get("ttl_s") or approval_ttl_seconds())
        issued_mono = rec.get("issued_mono")
        if issued_mono is not None:
            age = time.monotonic() - float(issued_mono)
        else:
            # Legacy pending minted before Pass 9 — fall back to wall clock.
            issued_at = float(rec.get("issued_at") or 0)
            age = (time.time() - issued_at) if issued_at else 0.0
        if age > ttl:
            _LOCAL_PENDING.pop(token, None)
            _LOCAL_USED_TOKENS.add(token)
            return ApproveResult(
                granted=False,
                reason=f"phoenix approval_token expired (ttl={ttl}s)",
                tool_name=rec.get("tool_name"),
                intent=rec.get("intent"),
                raw={
                    "lock_id": rec.get("lock_id"),
                    "threat_summary": rec.get("threat_summary"),
                    "expired": True,
                    "age_s": age,
                },
            )

        # Bind grant to call fingerprint — reject mismatched expected_* .
        fp = rec["fingerprint"]
        if (
            expected_tool_name is not None
            or expected_args is not None
            or expected_session_id is not None
            or expected_agent_id is not None
        ):
            exp_tool = (
                expected_tool_name
                if expected_tool_name is not None
                else rec.get("tool_name")
            )
            exp_args = (
                dict(expected_args)
                if expected_args is not None
                else dict(rec.get("args") or {})
            )
            exp_session = (
                expected_session_id
                if expected_session_id is not None
                else rec.get("session_id")
            )
            exp_agent = (
                expected_agent_id
                if expected_agent_id is not None
                else rec.get("agent_id")
            )
            if (
                _call_fingerprint(str(exp_tool), exp_args, exp_session, exp_agent)
                != fp
            ):
                return ApproveResult(
                    granted=False,
                    reason=(
                        "approve rejected: tool_name/args/session/agent fingerprint "
                        "mismatch (grant not bound to this call)"
                    ),
                    tool_name=rec.get("tool_name"),
                    intent=rec.get("intent"),
                    raw={
                        "lock_id": rec.get("lock_id"),
                        "threat_summary": rec.get("threat_summary"),
                        "fingerprint_mismatch": True,
                        "agent_id": rec.get("agent_id"),
                    },
                )
        if expected_args_hash is not None:
            pending_hash = rec.get("args_hash")
            if pending_hash != expected_args_hash:
                return ApproveResult(
                    granted=False,
                    reason="approve rejected: args_hash mismatch",
                    tool_name=rec.get("tool_name"),
                    intent=rec.get("intent"),
                    raw={
                        "lock_id": rec.get("lock_id"),
                        "threat_summary": rec.get("threat_summary"),
                        "args_hash_mismatch": True,
                    },
                )

        # Consume
        _LOCAL_PENDING.pop(token, None)
        _LOCAL_USED_TOKENS.add(token)
        grant = {
            "approver": approver,
            "intent": rec.get("intent"),
            "tool_name": rec.get("tool_name"),
            "args": dict(rec.get("args") or {}),
            "session_id": rec.get("session_id"),
            "agent_id": rec.get("agent_id"),
            "decision_id": rec.get("decision_id"),
            "granted_at": time.time(),
            "lock_id": rec.get("lock_id"),
            "threat_summary": sanitize_threat_summary(
                str(rec.get("threat_summary") or ""),
                persuasion=bool(rec.get("persuasion_non_authority")),
            ),
            "persuasion_non_authority": bool(rec.get("persuasion_non_authority")),
            "fingerprint": fp,
            "args_hash": rec.get("args_hash"),
        }
        _LOCAL_GRANTS[fp] = grant

    threat = sanitize_threat_summary(
        str(rec.get("threat_summary") or rec.get("lock_id") or ""),
        persuasion=bool(rec.get("persuasion_non_authority")),
    )
    safe_approver = (
        sanitize_echo_field(str(approver or "unknown"), max_len=64) or "unknown"
    )
    safe_lock = (
        sanitize_echo_field(str(rec.get("lock_id") or "-"), max_len=64) or "-"
    )
    echo = (
        f"phoenix-local approved by {safe_approver}; "
        f"lock_id={safe_lock}; threat={threat}"
    )
    return ApproveResult(
        granted=True,
        reason=echo,
        tool_name=rec.get("tool_name"),
        intent=rec.get("intent"),
        raw={
            "lock_id": rec.get("lock_id"),
            "threat_summary": threat,
            "fingerprint": fp,
            "args_hash": rec.get("args_hash"),
            "approver": safe_approver,
            "agent_id": rec.get("agent_id"),
            "session_id": rec.get("session_id"),
            "persuasion_non_authority": bool(rec.get("persuasion_non_authority")),
        },
    )


def assert_grant_matches(
    tool_name: str,
    args: Mapping[str, Any] | None,
    session_id: Optional[str],
    grant: Mapping[str, Any],
    agent_id: Optional[str] = None,
) -> None:
    """TOCTOU helper: execute-after-verify MUST re-check fingerprint.

    Hermes (or any executor) that received an allow via grant consumption must
    call this immediately before running the tool. A mutated tool_name/args
    (or agent/session) between approve and execute must raise
    ``GrantMismatchError``.

    Note: ``gate_tool_call`` already keys local grants by fingerprint; this
    helper exists for the *seam* execute path that sits outside the pack.
    Pass 5: pass the executing agent_id so co-session workers cannot ride
    another agent's grant.
    """
    args = dict(args or {})
    # Prefer explicit agent_id; fall back to grant's agent if caller omitted.
    aid = agent_id if agent_id is not None else grant.get("agent_id")
    actual = _call_fingerprint(tool_name, args, session_id, aid)
    expected = grant.get("fingerprint")
    if expected is None:
        # Reconstruct from grant fields if present
        expected = _call_fingerprint(
            str(grant.get("tool_name") or ""),
            dict(grant.get("args") or {}),
            grant.get("session_id"),  # type: ignore[arg-type]
            grant.get("agent_id"),  # type: ignore[arg-type]
        )
    if actual != expected:
        raise GrantMismatchError(
            f"grant fingerprint mismatch: call={actual[:20]}… "
            f"grant={str(expected)[:20]}… — refuse execute (TOCTOU)"
        )
    # Also bind args_hash when present
    g_hash = grant.get("args_hash")
    if g_hash and g_hash != _args_hash(args):
        raise GrantMismatchError(
            "grant args_hash mismatch — refuse execute (TOCTOU)"
        )
    g_agent = grant.get("agent_id")
    if g_agent is not None and aid is not None and g_agent != aid:
        raise GrantMismatchError(
            "grant agent_id mismatch — refuse execute (multi-agent)"
        )


def _consume_local_grant(
    tool_name: str,
    args: Mapping[str, Any],
    session_id: Optional[str],
    agent_id: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    fp = _call_fingerprint(tool_name, args, session_id, agent_id)
    with _LOCAL_LOCK:
        return _LOCAL_GRANTS.pop(fp, None)


def _issue_local_token(
    *,
    tool_name: str,
    args: Mapping[str, Any],
    session_id: Optional[str],
    agent_id: Optional[str] = None,
    lock_id: Optional[str],
    intent: str,
    decision_id: str,
    threat_summary: str = "",
    persuasion_non_authority: bool = False,
) -> Optional[str]:
    """Mint phoenix-local pending token, or None if session flood cap hit.

    Race-safe: pending count + insert under the same ``_LOCAL_LOCK``.
    """
    token = f"appr_phoenix_{secrets.token_urlsafe(16)}"
    ttl = approval_ttl_seconds()
    cap = approval_flood_max()
    with _LOCAL_LOCK:
        pending_for_session = sum(
            1
            for rec in _LOCAL_PENDING.values()
            if rec.get("session_id") == session_id
        )
        if pending_for_session >= cap:
            return None
        _LOCAL_PENDING[token] = {
            "tool_name": tool_name,
            "args": dict(args),
            "session_id": session_id,
            "agent_id": agent_id,
            "lock_id": lock_id,
            "intent": intent,
            "decision_id": decision_id,
            "fingerprint": _call_fingerprint(
                tool_name, args, session_id, agent_id
            ),
            "args_hash": _args_hash(args),
            "threat_summary": sanitize_threat_summary(
                threat_summary or lock_id or "",
                persuasion=persuasion_non_authority,
            ),
            "persuasion_non_authority": bool(persuasion_non_authority),
            "issued_at": time.time(),  # wall display / legacy
            "issued_mono": time.monotonic(),  # Pass 9 TTL clock
            "ttl_s": ttl,
            "expires_at": time.time() + ttl,
        }
    return token


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _args_hash(args: Mapping[str, Any] | None) -> str:
    blob = json.dumps(args or {}, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _decision_id() -> str:
    return f"{int(time.time() * 1000)}-{secrets.token_hex(8)}"


def _canonical_receipt_body(receipt: Mapping[str, Any]) -> bytes:
    """Canonical bytes for hashing — omit hash fields themselves."""
    body = {
        k: v
        for k, v in receipt.items()
        if k not in ("receipt_hash", "prev_hash")
    }
    return json.dumps(body, sort_keys=True, default=str).encode("utf-8")


def _hash_receipt(receipt: Mapping[str, Any], prev_hash: Optional[str]) -> str:
    material = (prev_hash or "genesis").encode("utf-8") + b"|" + _canonical_receipt_body(
        receipt
    )
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _last_receipt_hash(path: Path) -> Optional[str]:
    if not path.exists() or path.stat().st_size == 0:
        return None
    last = ""
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                last = line
    if not last:
        return None
    try:
        rec = json.loads(last)
    except json.JSONDecodeError:
        return None
    return rec.get("receipt_hash")


def _receipt_tip_path(receipts_path: Path) -> Path:
    """Sidecar tip file — detects truncation fork (Pass 6)."""
    return Path(str(receipts_path) + ".tip")


def _receipt_tip_enabled() -> bool:
    v = _policy_env("PHOENIX_GATE_RECEIPT_TIP", "1").strip().lower()
    return v not in ("0", "false", "no", "off", "")


def _write_receipt_tip(path: Path, tip_hash: str, count: int, receipt_id: Any) -> None:
    tip = {
        "tip_hash": tip_hash,
        "count": count,
        "receipt_id": receipt_id,
    }
    _receipt_tip_path(path).write_text(
        json.dumps(tip, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )


def _count_receipts(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n


def write_receipt(
    receipt: Mapping[str, Any],
    receipts_path: Union[str, Path],
) -> Path:
    """Append one Continuity-style JSONL receipt with hash-chain links.

    Integrity model: **detect** tampering via ``verify_receipt_chain`` — does
    not cryptographically prevent an attacker with write access from rewriting
    the file and recomputing hashes. Pass 6 adds a ``.tip`` sidecar so a
    truncation fork (drop tail lines, leave chain prefix valid) is detected
    unless the attacker also rewrites the tip.
    """
    path = Path(receipts_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev = _last_receipt_hash(path)
    enriched = dict(receipt)
    enriched["prev_hash"] = prev
    enriched["receipt_hash"] = _hash_receipt(enriched, prev)
    line = json.dumps(enriched, sort_keys=True, default=str)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    if _receipt_tip_enabled():
        count = _count_receipts(path)
        _write_receipt_tip(
            path,
            tip_hash=str(enriched["receipt_hash"]),
            count=count,
            receipt_id=enriched.get("receipt_id"),
        )
    return path


def verify_receipt_chain(
    receipts_path: Union[str, Path],
    *,
    require_tip: Optional[bool] = None,
) -> tuple[bool, str]:
    """Return (ok, detail). Detects broken prev links / recomputed mismatches.

    Pass 6: when a ``.tip`` sidecar exists (or require_tip), also check tip_hash
    + count against the file tip — catches truncation forks that leave a valid
    prefix chain.
    """
    path = Path(receipts_path)
    if not path.exists():
        return False, "receipts file missing"
    prev: Optional[str] = None
    count = 0
    last_hash: Optional[str] = None
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, f"line {lineno}: invalid JSON"
            expected_prev = prev
            if rec.get("prev_hash") != expected_prev:
                return False, f"line {lineno}: prev_hash mismatch"
            expected_hash = _hash_receipt(rec, expected_prev)
            if rec.get("receipt_hash") != expected_hash:
                return False, f"line {lineno}: receipt_hash mismatch (tamper?)"
            prev = rec.get("receipt_hash")
            last_hash = prev
            count += 1

    tip_path = _receipt_tip_path(path)
    tip_required = _receipt_tip_enabled() if require_tip is None else require_tip
    if tip_path.exists():
        try:
            tip = json.loads(tip_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False, "tip sidecar: invalid JSON"
        if tip.get("count") != count:
            return False, (
                f"tip sidecar: count mismatch (tip={tip.get('count')} file={count}) "
                "— truncation fork?"
            )
        if count and tip.get("tip_hash") != last_hash:
            return False, "tip sidecar: tip_hash mismatch — truncation or tip rewrite?"
    elif tip_required and count > 0:
        return False, "tip sidecar missing (PHOENIX_GATE_RECEIPT_TIP) — possible truncation fork"

    return True, f"ok ({count} receipts)"


class ReceiptIntegrityError(Exception):
    """Raised by load_receipts_verified when the chain/tip fails checks."""


def load_receipts_verified(
    receipts_path: Union[str, Path],
    *,
    require_tip: Optional[bool] = None,
) -> list[dict[str, Any]]:
    """Pass 9: verify-on-read — return receipts only if chain (+ tip) is intact.

    Attackers with a writable receipts path can still rewrite+rehash (detect-only
    ceiling; Continuity signing is outside pack). This helper refuses to hand
    callers a silently-tampered ledger on *read*.
    """
    ok, detail = verify_receipt_chain(receipts_path, require_tip=require_tip)
    if not ok:
        raise ReceiptIntegrityError(detail)
    path = Path(receipts_path)
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def receipts_path_writable_warning(receipts_path: Union[str, Path]) -> Optional[str]:
    """Warn when receipts parent (or file) is other-writable — tamper surface."""
    path = Path(receipts_path)
    targets = [path.parent]
    if path.exists():
        targets.append(path)
    tip = Path(str(path) + ".tip")
    if tip.exists():
        targets.append(tip)
    for t in targets:
        try:
            mode = t.stat().st_mode
        except OSError:
            continue
        if mode & 0o002:  # other-writable
            return (
                f"receipts path other-writable ({t}) — attacker can tamper after "
                "write; always load_receipts_verified / verify_receipt_chain"
            )
    return None


def gate_tool_call(
    tool_name: str,
    args: Optional[Mapping[str, Any]] = None,
    *,
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    client: Optional[ApeClient] = None,
    ape_url: Optional[str] = None,
    receipts_path: Union[str, Path] = "receipts/continuity.jsonl",
    hard_deny_skips_ape: bool = True,
    annotate_ape_on_hard_deny: bool = False,
) -> GateResult:
    """Classify Phoenix locks, consult APE, write Continuity receipt.

    Flow:
      1. classify phoenix locks (empty tool → hard deny; strict unknown; args scan)
      2. consume phoenix-local one-shot grant if present (fingerprint-bound)
      3. if hard deny lock → deny without calling APE (unless annotate flag)
      4. else call APE /verify — on any ApeError → deny (fail closed)
      5. if require_approval → return pending with token (do not execute)
      6. if allow → return allow
      7. write Continuity-style receipt JSONL (hash-chained)

    TOCTOU: if a seam executor runs the tool after allow, it MUST call
    ``assert_grant_matches`` (or re-invoke ``gate_tool_call``) so a mutated
    call cannot ride a prior grant.

    Pass 5: pass a distinct ``agent_id`` per worker so co-session agents cannot
    share Founder grants. Optional ``PHOENIX_GATE_REQUIRE_AGENT_ID=1`` denies
    when agent_id is missing.
    """
    args = dict(args or {})
    # Preserve caller-facing tool_name but classify on normalized form.
    display_tool = tool_name if isinstance(tool_name, str) else ""
    lock: LockHint = classify_lock(display_tool, args, session_id=session_id)
    fp = _call_fingerprint(display_tool, args, session_id, agent_id)
    ahash = _args_hash(args)

    ape_result: Optional[VerifyResult] = None
    skipped_ape = False
    decision: str
    reason: str
    decision_id: str
    approval_token: Optional[str] = None
    intent = "unknown"
    extras: dict[str, Any] = {}
    persuasion_flag = bool(getattr(lock, "persuasion_non_authority", False))
    threat_summary = sanitize_threat_summary(
        lock.threat_summary or lock.note or (lock.lock_id or ""),
        persuasion=persuasion_flag,
    )

    # Pass 9: surface boot-time insecure / pinned env once; path writable warn.
    supply_warns = _consume_supply_env_warnings()
    path_warn = receipts_path_writable_warning(receipts_path)
    if path_warn:
        supply_warns = list(supply_warns) + [path_warn]
    if supply_warns:
        extras["insecure_env_warnings"] = supply_warns

    # Multi-agent: refuse anonymous callers when strict agent binding is on.
    if require_agent_id_enabled() and not (agent_id and str(agent_id).strip()):
        decision = DECISION_DENY
        skipped_ape = True
        decision_id = _decision_id()
        intent = "agent_id_required"
        reason = (
            "PHOENIX_GATE_REQUIRE_AGENT_ID: agent_id required for multi-agent "
            "isolation (anonymous grant bucket denied)"
        )
        extras["agent_id_required"] = True
        if supply_warns:
            extras["insecure_env_warnings"] = supply_warns
        threat_summary = "missing agent_id under require-agent mode"
        phoenix_verdict = APE_TO_PHOENIX.get(decision, "block")
        allowed = False
        extras["call_fingerprint"] = fp
        extras["args_hash"] = ahash
        receipt = {
            "receipt_id": f"pg_{secrets.token_hex(8)}",
            "ts": _now_iso(),
            "decision_id": decision_id,
            "lock": lock.lock_id,
            "lock_matched": lock.matched,
            "decision": decision,
            "phoenix_verdict": phoenix_verdict,
            "tool": display_tool,
            "args_hash": ahash,
            "call_fingerprint": fp,
            "threat_summary": threat_summary,
            "session_id": session_id,
            "agent_id": agent_id,
            "intent": intent,
            "reason": reason,
            "approval_token": None,
            "skipped_ape": skipped_ape,
            "allowed": allowed,
        }
        path = write_receipt(receipt, receipts_path)
        return GateResult(
            decision=decision,
            phoenix_verdict=phoenix_verdict,
            allowed=allowed,
            reason=reason,
            decision_id=decision_id,
            tool_name=display_tool,
            lock_id=lock.lock_id,
            approval_token=None,
            intent=intent,
            receipt_path=str(path),
            skipped_ape=skipped_ape,
            ape=None,
            extras=extras,
            threat_summary=threat_summary,
            call_fingerprint=fp,
            args_hash=ahash,
        )

    # Phoenix-local grant (from approve_gate_token) — Founder last-yes for
    # escalated locks. Consumed once; skips APE re-ask for this fingerprint.
    local_grant = _consume_local_grant(display_tool, args, session_id, agent_id)
    if local_grant is not None:
        # Defense in depth: re-check fingerprint fields on the grant record.
        try:
            assert_grant_matches(
                display_tool, args, session_id, local_grant, agent_id=agent_id
            )
        except GrantMismatchError as exc:
            decision = DECISION_DENY
            skipped_ape = True
            decision_id = _decision_id()
            intent = "grant_mismatch"
            reason = f"local grant TOCTOU refuse: {exc}"
            extras["grant_mismatch"] = True
            threat_summary = "grant fingerprint mismatch at consume"
            local_grant = None  # fall through already decided
        else:
            decision = "allow"
            skipped_ape = True
            decision_id = _decision_id()
            intent = str(local_grant.get("intent") or lock.lock_id or "phoenix_grant")
            reason = (
                f"phoenix-local one-shot grant consumed "
                f"(approved by {local_grant.get('approver') or 'unknown'}); "
                f"lock {local_grant.get('lock_id') or lock.lock_id} satisfied; "
                f"threat={local_grant.get('threat_summary') or '-'}"
            )
            extras["grant_consumed"] = True
            extras["grant_source"] = "phoenix_local"
            extras["lock_id_echo"] = local_grant.get("lock_id")
            extras["threat_summary"] = local_grant.get("threat_summary")
            threat_summary = str(
                local_grant.get("threat_summary") or threat_summary
            )

    if local_grant is None and "grant_mismatch" not in extras:
        # Hard deny from Phoenix lock — stop before APE (or annotate optionally).
        if lock.matched and lock.force_decision == DECISION_DENY:
            if (annotate_ape_on_hard_deny or not hard_deny_skips_ape) and (
                client or ape_url
            ):
                ape = client or ApeClient(base_url=ape_url or "http://127.0.0.1:7890")
                try:
                    ape_result = ape.verify(
                        display_tool, args, session_id=session_id, agent_id=agent_id
                    )
                except ApeError as exc:
                    ape_result = None
                    reason = f"{lock.reason} (APE annotate failed: {exc})"
                else:
                    reason = (
                        f"{lock.reason}; APE annotated decision={ape_result.decision} "
                        f"({ape_result.reason})"
                    )
                decision = DECISION_DENY
                decision_id = (
                    ape_result.decision_id if ape_result else None
                ) or _decision_id()
                intent = (
                    ape_result.intent if ape_result else lock.lock_id or "phoenix_lock"
                )
                skipped_ape = False
            else:
                skipped_ape = True
                decision = DECISION_DENY
                reason = lock.reason + (f" — {lock.note}" if lock.note else "")
                decision_id = _decision_id()
                intent = lock.lock_id or "phoenix_lock"
        else:
            ape = client or ApeClient(base_url=ape_url or "http://127.0.0.1:7890")
            try:
                ape_result = ape.verify(
                    display_tool, args, session_id=session_id, agent_id=agent_id
                )
            except ApeError as exc:
                # Fail closed: unreachable / timeout / HTTP / bad JSON → DENY.
                skipped_ape = False
                decision = DECISION_DENY
                decision_id = _decision_id()
                intent = "ape_unavailable"
                reason = f"APE unavailable — fail closed ({type(exc).__name__}: {exc})"
                extras["ape_error"] = type(exc).__name__
                ape_result = None
            else:
                decision = ape_result.decision
                reason = ape_result.reason
                decision_id = ape_result.decision_id or _decision_id()
                approval_token = ape_result.approval_token
                intent = ape_result.intent

                # Structured flag only (Kintsugi: never sniff reason text).
                grant_consumed = ape_result.grant_consumed is True
                if grant_consumed:
                    extras["grant_consumed"] = True
                    extras["grant_source"] = "ape"

                if (
                    lock.matched
                    and lock.force_decision == DECISION_REQUIRE_APPROVAL
                    and decision == "allow"
                    and not grant_consumed
                ):
                    decision = DECISION_REQUIRE_APPROVAL
                    approval_token = _issue_local_token(
                        tool_name=display_tool,
                        args=args,
                        session_id=session_id,
                        agent_id=agent_id,
                        lock_id=lock.lock_id,
                        intent=intent,
                        decision_id=decision_id,
                        threat_summary=threat_summary,
                        persuasion_non_authority=persuasion_flag,
                    )
                    if approval_token is None:
                        decision = DECISION_DENY
                        reason = (
                            f"phoenix lock approval_flood — session pending "
                            f"approvals >= {approval_flood_max()} "
                            f"(social-eng flood refuse)"
                        )
                        extras["approval_flood"] = True
                        threat_summary = "approve-prompt flood cap hit for session"
                        lock = LockHint(
                            matched=True,
                            lock_id="approval_flood",
                            force_decision=DECISION_DENY,
                            phoenix_verdict="block",
                            reason=reason,
                            note="Hard deny — approval prompt flood",
                            threat_summary=threat_summary,
                        )
                    else:
                        reason = (
                            f"{lock.reason} (escalated APE allow → require_approval); "
                            f"APE said: {ape_result.reason}; "
                            f"threat={threat_summary or '-'}"
                        )
                        extras["phoenix_escalated"] = True
                        extras["threat_summary"] = threat_summary
                        extras["approval_ttl_s"] = approval_ttl_seconds()
                elif (
                    lock.matched
                    and lock.force_decision == DECISION_REQUIRE_APPROVAL
                    and decision == DECISION_REQUIRE_APPROVAL
                    and approval_token
                ):
                    # APE already asked human — still echo phoenix threat on receipt.
                    extras["threat_summary"] = threat_summary
                    extras["lock_id_echo"] = lock.lock_id
                elif grant_consumed and lock.matched:
                    reason = (
                        f"{ape_result.reason}; phoenix lock {lock.lock_id} satisfied "
                        f"via Founder /approve grant; threat={threat_summary or '-'}"
                    )

                # If APE soft-allowed but we somehow missed lock require path —
                # also escalate when decision is require from lock and APE
                # returned require without token (defensive).
                if (
                    lock.matched
                    and lock.force_decision == DECISION_REQUIRE_APPROVAL
                    and decision == DECISION_REQUIRE_APPROVAL
                    and not approval_token
                    and not grant_consumed
                ):
                    approval_token = _issue_local_token(
                        tool_name=display_tool,
                        args=args,
                        session_id=session_id,
                        agent_id=agent_id,
                        lock_id=lock.lock_id,
                        intent=intent,
                        decision_id=decision_id,
                        threat_summary=threat_summary,
                        persuasion_non_authority=persuasion_flag,
                    )
                    if approval_token is None:
                        decision = DECISION_DENY
                        reason = (
                            f"phoenix lock approval_flood — session pending "
                            f"approvals >= {approval_flood_max()} "
                            f"(social-eng flood refuse)"
                        )
                        extras["approval_flood"] = True
                        threat_summary = "approve-prompt flood cap hit for session"
                        lock = LockHint(
                            matched=True,
                            lock_id="approval_flood",
                            force_decision=DECISION_DENY,
                            phoenix_verdict="block",
                            reason=reason,
                            note="Hard deny — approval prompt flood",
                            threat_summary=threat_summary,
                        )
                    else:
                        extras["phoenix_token_minted"] = True

    # Pass 4: social-eng flood — cap NEED_HUMAN prompts per session regardless
    # of whether the token came from APE or phoenix-local mint.
    if decision == DECISION_REQUIRE_APPROVAL:
        if not _register_approval_prompt(session_id):
            decision = DECISION_DENY
            approval_token = None
            reason = (
                f"phoenix lock approval_flood — session approval prompts "
                f"> {approval_flood_max()} (social-eng flood refuse)"
            )
            extras["approval_flood"] = True
            threat_summary = "approve-prompt flood cap hit for session"
            lock = LockHint(
                matched=True,
                lock_id="approval_flood",
                force_decision=DECISION_DENY,
                phoenix_verdict="block",
                reason=reason,
                note="Hard deny — approval prompt flood",
                threat_summary=threat_summary,
            )

    phoenix_verdict = APE_TO_PHOENIX.get(decision, "block")
    allowed = decision == "allow"

    if lock.note and "lock_note" not in extras:
        extras["lock_note"] = lock.note
    if threat_summary:
        extras.setdefault("threat_summary", threat_summary)
    if persuasion_flag:
        extras.setdefault("persuasion_non_authority", True)
    if lock.lock_id:
        extras.setdefault("lock_id_echo", lock.lock_id)
    norm = normalize_tool_name(display_tool)
    if norm != (display_tool or "").strip().lower():
        extras["normalized_tool"] = norm
    extras["call_fingerprint"] = fp
    extras["args_hash"] = ahash

    receipt = {
        "receipt_id": f"pg_{secrets.token_hex(8)}",
        "ts": _now_iso(),
        "decision_id": decision_id,
        "lock": lock.lock_id,
        "lock_matched": lock.matched,
        "decision": decision,
        "phoenix_verdict": phoenix_verdict,
        "tool": display_tool,
        "args_hash": ahash,
        "call_fingerprint": fp,
        "threat_summary": threat_summary,
        "session_id": session_id,
        "agent_id": agent_id,
        "intent": intent,
        "reason": reason,
        "approval_token": approval_token,
        "skipped_ape": skipped_ape,
        "allowed": allowed,
    }
    path = write_receipt(receipt, receipts_path)

    return GateResult(
        decision=decision,
        phoenix_verdict=phoenix_verdict,
        allowed=allowed,
        reason=reason,
        decision_id=decision_id,
        tool_name=display_tool,
        lock_id=lock.lock_id,
        approval_token=approval_token,
        intent=intent,
        receipt_path=str(path),
        skipped_ape=skipped_ape,
        ape=ape_result,
        extras=extras,
        threat_summary=threat_summary,
        call_fingerprint=fp,
        args_hash=ahash,
    )


def result_as_dict(result: GateResult) -> dict[str, Any]:
    """Serialize GateResult for demos/tests (drops nested VerifyResult raw)."""
    data = asdict(result)
    if result.ape is not None:
        data["ape"] = {
            "allowed": result.ape.allowed,
            "reason": result.ape.reason,
            "intent": result.ape.intent,
            "decision_id": result.ape.decision_id,
            "decision": result.ape.decision,
            "approval_token": result.ape.approval_token,
            "grant_consumed": result.ape.grant_consumed,
        }
    return data
