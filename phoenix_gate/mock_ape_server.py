"""Tiny stdlib mock APE for offline demos (enough /health /verify /approve).

Embeds a simplified policy so the Hermes→APE adapter loop can run without a
real ODS APE container. Not a substitute for upstream APE.

Kintsugi 2026-09-22: grant_consumed structured flag, empty tool deny,
argv-smuggle flatten, expanded aliases, single-use tokens/grants.
Pass 7 (outside API abuse): JSON content-type + body-size caps, typed
tool_name/args/session/agent, token-format checks, pending TTL/cap, 400 on
bad JSON (no silent empty-object coerce).
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MockApeState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.approvals: dict[str, dict[str, Any]] = {}
        self.grants: dict[str, dict[str, Any]] = {}  # fingerprint → grant
        self.used_tokens: set[str] = set()  # detect reuse attempts
        self.audit: list[dict[str, Any]] = []

    def decision_id(self) -> str:
        return f"{int(time.time() * 1000)}-{secrets.token_hex(8)}"


STATE = MockApeState()

# Pass 7 — outside-attacker wire limits (stdlib mock only).
MAX_BODY_BYTES = 256 * 1024  # 256 KiB
MAX_PENDING_APPROVALS = 256
APPROVAL_TTL_S = 300.0  # pending token lifetime
TOKEN_PREFIX = "appr_"
TOKEN_MIN_LEN = 12  # prefix + entropy floor (issued tokens ~37)


def reset_mock_ape_state() -> None:
    """Test helper — clear approvals/grants/used/audit (Pass 7 flood tests)."""
    with STATE.lock:
        STATE.approvals.clear()
        STATE.grants.clear()
        STATE.used_tokens.clear()
        STATE.audit.clear()



def _prune_expired_approvals(now: Optional[float] = None) -> int:
    """Drop pending approvals past TTL. Returns number removed."""
    now = time.time() if now is None else now
    removed = 0
    expired = [
        tok
        for tok, rec in STATE.approvals.items()
        if (now - float(rec.get("issued_at") or 0)) > APPROVAL_TTL_S
    ]
    for tok in expired:
        STATE.approvals.pop(tok, None)
        STATE.used_tokens.add(tok)  # block late replay of expired
        removed += 1
    return removed


def _require_string_or_none(value: Any, field: str) -> tuple[Optional[str], Optional[str]]:
    """Return (value, error). None allowed; non-str rejected (type confusion)."""
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, f"{field} must be a string or null"
    return value, None


def _validate_approval_token_shape(token: Any) -> tuple[Optional[str], Optional[str]]:
    """Reject forged/short/non-string tokens before store lookup."""
    if token is None or token is False or token == "":
        return None, "approval_token required"
    if not isinstance(token, str):
        return None, "approval_token must be a string"
    if not token.startswith(TOKEN_PREFIX):
        return None, "approval_token format invalid"
    if len(token) < TOKEN_MIN_LEN:
        return None, "approval_token too short"
    # No whitespace / control chars (strip-smuggle)
    if token != token.strip() or any(ord(c) < 32 for c in token):
        return None, "approval_token format invalid"
    return token, None




def _args_fingerprint(
    tool_name: str,
    args: dict,
    session_id: Optional[str],
    agent_id: Optional[str] = None,
) -> str:
    blob = json.dumps(
        {
            "tool": tool_name,
            "args": args,
            "session": session_id,
            "agent": agent_id,
        },
        sort_keys=True,
        default=str,
    )
    return blob


def _flatten_for_policy(args: dict) -> str:
    """Join list argv so rm/-rf smuggling is visible to regex."""
    parts: list[str] = []
    for key, value in (args or {}).items():
        parts.append(str(key))
        if isinstance(value, (list, tuple)):
            parts.append(" ".join(str(v) for v in value))
            parts.extend(str(v) for v in value)
        elif isinstance(value, dict):
            parts.append(_flatten_for_policy(value))
        else:
            parts.append(str(value))
    return " ".join(parts)


def evaluate_policy(tool_name: str, args: dict) -> tuple[str, str, str]:
    """Return (decision, reason, intent) using a tiny embedded policy.

    Safe read-ish / doctrine-benign tools → allow.
    Publish / social / make_on / billing / shell → require_approval (**tool_name**).
    Wipe / sku invent / rm -rf → deny (F59: key-aware on doctrine-benign tools).
    Empty tool → deny.
    Unknown → allow (APE allowlist softness for demo; Phoenix locks may escalate).

    Pass 10 enablement: soft locks match **tool_name**, not English prose in args
    ("do not publish yet" / "spend time" must not NEED_HUMAN).
    """
    name = (tool_name or "").strip().lower()
    if not name:
        return "deny", "mock policy: empty tool_name denied", "invalid"

    flat = _flatten_for_policy(args if isinstance(args, dict) else {})
    hay = f"{name} {flat}".lower()
    args_d = args if isinstance(args, dict) else {}

    # Hard wipe — aligned with Phoenix F59 (acts, not vocabulary on benign).
    # Import lazily to keep mock usable as a thin demo server.
    from phoenix_gate.phoenix_locks import STRICT_BENIGN_ALLOWLIST

    _high = {
        "cmd", "command", "script", "code", "shell", "exec", "argv", "bash",
        "stdin", "sql", "md", "html", "css", "js", "powershell",
    }
    _needle = {
        "pattern", "q", "query", "grep", "regex", "needle", "search", "find", "glob",
    }
    _prose = {
        "note", "comment", "message", "description", "rationale", "summary",
        "memo", "remark", "msg",
    }
    _doc_text = {
        "echo", "summarize", "summarize_text", "summarize_local", "format_text",
        "markdown_preview", "think", "plan", "reason", "remember", "recall",
        "describe_data", "count_tokens",
    }

    def _kn(k: object) -> str:
        return str(k).strip().lower().replace("-", "_")

    wipe_tool = bool(
        re.search(
            r"(^|[_-])(wipe|shred|destructive_wipe|factory_reset|delete_all|"
            r"truncate_db|drop_table|shutil_rmtree)($|[_-])",
            name,
        )
        or name
        in {
            "wipe",
            "shred",
            "destructive_wipe",
            "factory_reset",
            "delete_all",
            "truncate_db",
            "drop_table",
            "shutil_rmtree",
        }
    )
    high_flat = " ".join(
        str(v) for k, v in args_d.items() if _kn(k) in _high
    ).lower()
    content_parts = []
    for k, v in args_d.items():
        lk = _kn(k)
        if lk in _high or lk in _needle or lk in _prose:
            continue
        if name in _doc_text and lk == "text":
            continue
        content_parts.append(str(v))
    content_flat = " ".join(content_parts).lower()

    wipe_args = False
    if name in STRICT_BENIGN_ALLOWLIST:
        if re.search(r"rm\s+-rf", high_flat) or re.search(
            r"(curl|wget).{0,80}\|\s*(ba)?sh|\|\s*(ba)?sh", high_flat
        ):
            wipe_args = True
        elif re.search(r"rm\s+-rf", content_flat):
            wipe_args = True
    else:
        if re.search(r"(wipe|rm\s+-rf|shred|destructive|factory[_-]?reset)", hay):
            wipe_args = True
        if re.search(r"(curl|wget).{0,80}\|\s*(ba)?sh|\|\s*(ba)?sh", hay):
            wipe_args = True

    if wipe_tool or wipe_args:
        return "deny", "mock policy: destructive wipe class", "destructive"
    if re.search(r"(sku[_-]?invent|invent[_-]?sku)", hay):
        return "deny", "mock policy: sku invent denied", "commerce"

    # Soft escalate — tool_name oriented (anti-paralysis).
    if re.search(
        r"(publish|social[_-]?send|send[_-]?social|tweet|post_to_social|post_to_x|"
        r"broadcast|wall_post|webhook_post|bluesky_post|mastodon_post|discord_send)",
        name,
    ):
        return "require_approval", "mock policy: publish needs human", "publish"
    if re.search(r"(make[_-]?on|enable[_-]?scenario|scenario[_-]?on)", name):
        return "require_approval", "mock policy: make_on needs human", "scenario"
    if re.search(
        r"(billing|billing_spend|provision_spend|payment_send|send_payment)"
        r"|(^|[_-])(spend|charge|pay)($|[_-])",
        name,
    ) or name in ("pay", "charge", "spend"):
        return "require_approval", "mock policy: spend needs human", "billing"
    if re.search(
        r"\b(execute_command|shell|bash|run_shell|run_command|exec|system|"
        r"powershell|subprocess|os_system)\b",
        name,
    ) or name in (
        "execute_command",
        "shell",
        "bash",
        "run_shell",
        "run_command",
        "exec",
        "system",
        "run",
        "eval",
    ):
        return "require_approval", "mock policy: shell/exec needs human", "exec"

    # Doctrine-benign read / draft / analyze / git-read / calc (Pass 10).
    _benign = {
        "ls",
        "list_dir",
        "list_directory",
        "list_files",
        "read_file",
        "open_file",
        "view_file",
        "show_file",
        "pwd",
        "echo",
        "safe_ls",
        "cat",
        "head",
        "tail",
        "wc",
        "stat",
        "file_stat",
        "file_info",
        "get_file_info",
        "getcwd",
        "draft_message",
        "write_draft",
        "compose_draft",
        "edit_draft",
        "save_draft",
        "save_note",
        "take_notes",
        "append_note",
        "local_note",
        "notebook_edit",
        "analyze_local",
        "analyze_csv",
        "analyze_data",
        "summarize",
        "summarize_text",
        "summarize_local",
        "local_analyze",
        "describe_data",
        "format_text",
        "markdown_preview",
        "count_tokens",
        "search_files",
        "grep",
        "find_files",
        "ripgrep",
        "rg",
        "glob_files",
        "git_status",
        "git_diff",
        "git_log",
        "git_show",
        "git_blame",
        "git_branch",
        "calc",
        "calculate",
        "think",
        "plan",
        "reason",
        "remember",
        "recall",
        "todo_list",
        "list_todos",
    }
    if name in _benign:
        return "allow", "mock policy: safe read-ish tool", "read"
    if re.search(r"\bls\b", name) and "rm" not in hay:
        return "allow", "mock policy: ls-like allow", "read"

    return "allow", "mock policy: default allow", "unknown"



def handle_verify(body: dict) -> tuple[int, dict]:
    # Pass 7: reject type-confused fields (str(None)=="None" previously soft-allowed).
    if "tool_name" not in body:
        tool_raw: Any = ""
    else:
        tool_raw = body.get("tool_name")
    if tool_raw is None:
        return 400, {
            "allowed": False,
            "reason": "tool_name must be a string (null rejected)",
            "intent": "invalid",
            "decision": "deny",
            "decision_id": STATE.decision_id(),
            "grant_consumed": False,
        }
    if not isinstance(tool_raw, str):
        return 400, {
            "allowed": False,
            "reason": "tool_name must be a string",
            "intent": "invalid",
            "decision": "deny",
            "decision_id": STATE.decision_id(),
            "grant_consumed": False,
        }
    tool_name = tool_raw

    if "args" not in body or body.get("args") is None:
        args: dict = {}
    else:
        args = body.get("args")  # type: ignore[assignment]
        if not isinstance(args, dict):
            return 400, {
                "allowed": False,
                "reason": "args must be a JSON object",
                "intent": "invalid",
                "decision": "deny",
                "decision_id": STATE.decision_id(),
                "grant_consumed": False,
            }

    session_id, err = _require_string_or_none(body.get("session_id"), "session_id")
    if err:
        return 400, {
            "allowed": False,
            "reason": err,
            "intent": "invalid",
            "decision": "deny",
            "decision_id": STATE.decision_id(),
            "grant_consumed": False,
        }
    agent_id, err = _require_string_or_none(body.get("agent_id"), "agent_id")
    if err:
        return 400, {
            "allowed": False,
            "reason": err,
            "intent": "invalid",
            "decision": "deny",
            "decision_id": STATE.decision_id(),
            "grant_consumed": False,
        }

    fp = _args_fingerprint(tool_name, args, session_id, agent_id)
    with STATE.lock:
        _prune_expired_approvals()
        grant = STATE.grants.pop(fp, None)

    did = STATE.decision_id()

    if grant is not None:
        resp = {
            "allowed": True,
            "reason": (
                f"one-shot approval grant consumed "
                f"(approved by {grant.get('approver') or 'unknown'})"
            ),
            "intent": grant.get("intent", "unknown"),
            "decision_id": did,
            "decision": "allow",
            "grant_consumed": True,
        }
        with STATE.lock:
            STATE.audit.append({"ts": _now(), "event": "verify_grant", **resp, "tool": tool_name})
        return 200, resp

    decision, reason, intent = evaluate_policy(tool_name, args)
    resp: dict[str, Any] = {
        "allowed": decision == "allow",
        "reason": reason,
        "intent": intent,
        "decision_id": did,
        "decision": decision,
        "grant_consumed": False,
    }
    if decision == "require_approval":
        token = f"appr_{secrets.token_urlsafe(24)}"
        resp["allowed"] = False
        with STATE.lock:
            _prune_expired_approvals()
            if len(STATE.approvals) >= MAX_PENDING_APPROVALS:
                # Fail closed: do not mint under flood (outside DoS / brute pad).
                resp["decision"] = "deny"
                resp["allowed"] = False
                resp["reason"] = (
                    f"mock APE: pending approval cap ({MAX_PENDING_APPROVALS}) "
                    "reached — refuse mint"
                )
                resp["intent"] = "flood"
                STATE.audit.append(
                    {"ts": _now(), "event": "verify_flood_cap", "tool": tool_name, **resp}
                )
                return 429, resp
            resp["approval_token"] = token
            STATE.approvals[token] = {
                "tool_name": tool_name,
                "args": args,
                "session_id": session_id,
                "agent_id": agent_id,
                "intent": intent,
                "reason": reason,
                "decision_id": did,
                "issued_at": time.time(),
                "fingerprint": fp,
            }
    with STATE.lock:
        STATE.audit.append({"ts": _now(), "event": "verify", "tool": tool_name, **resp})
    return 200, resp


def handle_approve(body: dict) -> tuple[int, dict]:
    token_s, shape_err = _validate_approval_token_shape(body.get("approval_token"))
    if shape_err or token_s is None:
        return 400, {"granted": False, "reason": shape_err or "approval_token required"}
    approver = body.get("approver")
    if approver is not None and not isinstance(approver, str):
        return 400, {"granted": False, "reason": "approver must be a string or null"}
    with STATE.lock:
        _prune_expired_approvals()
        if token_s in STATE.used_tokens:
            return 409, {
                "granted": False,
                "reason": "approval_token already used (single-use)",
            }
        rec = STATE.approvals.pop(token_s, None)
        if rec is None:
            return 404, {"granted": False, "reason": "unknown or expired approval_token"}
        # TTL (defense in depth if prune raced)
        issued_at = float(rec.get("issued_at") or 0)
        if issued_at and (time.time() - issued_at) > APPROVAL_TTL_S:
            STATE.used_tokens.add(token_s)
            return 410, {
                "granted": False,
                "reason": f"approval_token expired (ttl={APPROVAL_TTL_S}s)",
            }
        STATE.used_tokens.add(token_s)
        STATE.grants[rec["fingerprint"]] = {
            "approver": approver,
            "intent": rec.get("intent"),
            "tool_name": rec.get("tool_name"),
            "decision_id": rec.get("decision_id"),
            "granted_at": time.time(),
        }
        entry = {
            "ts": _now(),
            "event": "approve",
            "approver": approver,
            "tool": rec.get("tool_name"),
            "token_prefix": token_s[:12],
        }
        STATE.audit.append(entry)
    return 200, {
        "granted": True,
        "reason": f"approved by {approver or 'unknown'}",
        "tool_name": rec.get("tool_name"),
        "intent": rec.get("intent"),
    }


class MockApeHandler(BaseHTTPRequestHandler):
    server_version = "MockAPE/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter demo
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _read_json(self) -> tuple[Optional[dict], Optional[tuple[int, dict]]]:
        """Return (body, error_response). error_response is (status, payload)."""
        ct = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ct != "application/json":
            return None, (
                415,
                {
                    "error": "unsupported_media_type",
                    "reason": "Content-Type must be application/json",
                },
            )
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return None, (
                400,
                {"error": "bad_request", "reason": "invalid Content-Length"},
            )
        if length < 0:
            return None, (
                400,
                {"error": "bad_request", "reason": "invalid Content-Length"},
            )
        if length > MAX_BODY_BYTES:
            # Do not read the body — fail closed on declared size.
            return None, (
                413,
                {
                    "error": "payload_too_large",
                    "reason": f"body exceeds {MAX_BODY_BYTES} bytes",
                },
            )
        if length == 0:
            return {}, None
        raw = self.rfile.read(length)
        if len(raw) > MAX_BODY_BYTES:
            return None, (
                413,
                {
                    "error": "payload_too_large",
                    "reason": f"body exceeds {MAX_BODY_BYTES} bytes",
                },
            )
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, (
                400,
                {"error": "bad_request", "reason": "JSON body required"},
            )
        if data is None:
            return None, (
                400,
                {"error": "bad_request", "reason": "JSON object required (not null)"},
            )
        if not isinstance(data, dict):
            return None, (
                400,
                {"error": "bad_request", "reason": "JSON object required"},
            )
        return data, None

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, {"status": "ok", "mock": True, "timestamp": _now()})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        body, err = self._read_json()
        if err is not None:
            status, payload = err
            self._send(status, payload)
            return
        assert body is not None
        if path == "/verify":
            status, payload = handle_verify(body)
            self._send(status, payload)
            return
        if path == "/approve":
            status, payload = handle_approve(body)
            self._send(status, payload)
            return
        self._send(404, {"error": "not found"})


def make_server(host: str = "127.0.0.1", port: int = 7890, verbose: bool = False) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), MockApeHandler)
    httpd.verbose = verbose  # type: ignore[attr-defined]
    return httpd


def serve_forever(host: str = "127.0.0.1", port: int = 7890, verbose: bool = False) -> None:
    httpd = make_server(host, port, verbose=verbose)
    print(f"mock APE listening on http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nmock APE stopping", flush=True)
    finally:
        httpd.server_close()


def start_background(host: str = "127.0.0.1", port: int = 7890) -> ThreadingHTTPServer:
    httpd = make_server(host, port, verbose=False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="mock-ape")
    thread.start()
    return httpd


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Mock APE server for Phoenix adapter demos")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7890)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    serve_forever(args.host, args.port, verbose=args.verbose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
