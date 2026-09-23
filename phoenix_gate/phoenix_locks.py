"""Phoenix named-lock classifier (sanitized examples for demo / offline loop).

Maps tool_name + args → optional force_decision hint BEFORE / alongside APE.

Phoenix spine vocabulary:
  proceed     ↔ APE allow
  block       ↔ APE deny
  ask_human   ↔ APE require_approval

These matchers are illustrative sanitized names from the Phase A policy stub
(publish/social_send, make_on, billing_spend, destructive_wipe, sku_invent).
They do NOT encode Capture, SlipVault, ledger, or tenant secrets.

Kintsugi 2026-09-22: normalize unicode/zero-width, expand aliases, fail-closed
on empty tool names, tighten short-token matching, catch argv-smuggled wipes.

Kintsugi Pass 3 (frontier 2026-09-22/23):
  - Strict mode (PHOENIX_GATE_STRICT=1 default): unknown tools deny unless benign allowlist
  - Args always scanned for wipe/exfil even when tool_name looks safe
  - Best-effort one-layer base64/hex decode into scan haystack
  - http_post / outbound class gated (exfil URL/body → require_approval or deny)
  - Multi-hop SpawnAgent / run_subagent → require_approval (deny under strict_unknown=deny)
  - Whitespace / RTL / ZW tool-name normalize extended

Kintsugi Pass 6 (ultra-demon 2026-09-22/23):
  - Multi-layer b64/hex (depth 3) + gzip/zlib inflate into scan haystack
  - Chunk reassembly: concat arg values for decode/scan
  - Literal \\uXXXX / \\xXX unescape in scan haystack
  - Wipe regex without fragile leading word-boundary (glued-prefix bypass)
  - NUL + combining-mark strip in tool_name normalize
  - Head+tail scan window (long-arg DoS / wipe-at-end)
  - help/docs eval-surface lock; path-traversal / NUL args deny
  - Policy env seal (PHOENIX_GATE_* frozen after first read; reset for tests)

Kintsugi Pass 8 (outside Fable / jailbreak / social 2026-09-22/23):
  - sanitize_threat_summary / sanitize_echo_field — never echo raw jailbreak tool_name/args
  - Persuasion / authority-claim strings are non-authority (never escalate to allow)
  - Polyglot + comment scan seeds (markdown fences, HTML/C/# comments, JSON values)
  - Split-value wipe (rm + -rf across keys) + rm-rf optional-space regex

Kintsugi Pass 9 (outside supply / env / config 2026-09-22/23):
  - insecure_policy_env_warnings() surfaces boot-time STRICT=0 / SEAL off / tip off
  - Critical TTL/flood pins + remaining policy keys live in gateway (see gateway.py)

Kintsugi Pass 10 (plateau hunt 2026-09-22/23):
  - Scrub ZW/bidi/BOM + Mn + Cf from *args* scan haystack (tool_name already scrubbed)
  - URL percent-decode + HTML entity unescape one layer into scan seeds
  - (APE client) strict grant_consumed + decision strip/casefold/fail-closed — see ape_client.py
  - Enablement: expanded STRICT_BENIGN_ALLOWLIST (draft/analyze/git-read/calc)
  - Soft-lock args_regex skipped for benign tools (prose FP: publish/spend in notes)
  - F59: key-aware wipe args-always on benign (search needles + prose keys);
    hard-deny lock args_regex also skipped on benign (acts via tool_name + high-risk keys)
  - F60: exact-only name tokens for shell/charge/spend/tweet (no shell_history_read FP)
"""

from __future__ import annotations

import base64
import html
import binascii
import gzip
import hashlib
import os
import re
import threading
import unicodedata
import urllib.parse
import zlib
from collections import deque
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence


# APE decision vocabulary used as force hints.
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_REQUIRE_APPROVAL = "require_approval"

PHOENIX_TO_APE = {
    "proceed": DECISION_ALLOW,
    "block": DECISION_DENY,
    "ask_human": DECISION_REQUIRE_APPROVAL,
}

APE_TO_PHOENIX = {
    DECISION_ALLOW: "proceed",
    DECISION_DENY: "block",
    DECISION_REQUIRE_APPROVAL: "ask_human",
}

# Zero-width / bidi / BOM / soft-hyphen / word-joiner — stripped so rename tricks
# and prompt-injection-ish tool names cannot evade locks.
_ZW_RE = re.compile(
    "[\u00ad\u200b\u200c\u200d\u200e\u200f\u202a-\u202e"
    "\u2060-\u2064\u2066-\u2069\ufeff\u180e]"
)

# Whitespace (incl. unicode spaces) — removed entirely after NFKC so
# "pub lish" / "publish\\n" collapse toward the real lock name.
_WS_RE = re.compile(
    r"[\s\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+"
)

# Read-ish tools that may soft-pass strict-unknown (demo + common inspect).
STRICT_BENIGN_ALLOWLIST: frozenset[str] = frozenset(
    {
        # --- inspect / read (Pass 3) ---
        "safe_ls",
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
        "cat",
        "head",
        "tail",
        "wc",
        "stat",
        "file_stat",
        "file_info",
        "get_file_info",
        "getcwd",
        # --- local draft / notes (NOT publish) — Pass 10 enablement ---
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
        # --- local analysis / summarize ---
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
        # --- local search ---
        "search_files",
        "grep",
        "find_files",
        "ripgrep",
        "rg",
        "glob_files",
        # --- git read-only (not push) ---
        "git_status",
        "git_diff",
        "git_log",
        "git_show",
        "git_blame",
        "git_branch",
        # --- local reason / calc / plan ---
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
)


@dataclass(frozen=True)
class LockRule:
    lock_id: str
    ape_decision: str  # allow | deny | require_approval
    tool_name_any: Sequence[str]
    args_regex_any: Sequence[str]
    note: str = ""


@dataclass(frozen=True)
class LockHint:
    matched: bool
    lock_id: Optional[str] = None
    force_decision: Optional[str] = None  # APE vocab when matched
    phoenix_verdict: Optional[str] = None  # proceed|block|ask_human
    reason: str = ""
    note: str = ""
    threat_summary: str = ""
    persuasion_non_authority: bool = False  # Pass 8: jailbreak / authority claims ignored


# Sanitized named locks — same spirit as stub/ape-policy-pack/.
DEFAULT_LOCKS: tuple[LockRule, ...] = (
    LockRule(
        lock_id="publish_or_social_send",
        ape_decision=DECISION_REQUIRE_APPROVAL,
        tool_name_any=(
            "publish",
            "publish_message",
            "publish_status",
            "status_publish",
            "msg_publish",
            "social_send",
            "send_social",
            "social_post",
            "social_broadcast",
            "post_to_social",
            "post_to_x",
            "x_post",
            "wall_post",
            "bluesky_post",
            "mastodon_post",
            "discord_send",
            "webhook_post",
            "tweet",
            "tweet_now",
            "broadcast",
        ),
        args_regex_any=(
            r"(?i)\b(publish|tweet|broadcast)\b",
            r"(?i)\b(social[_-]?send|send[_-]?social|social[_-]?post|social[_-]?broadcast)\b",
            r"(?i)\bpost[_-]?to[_-]?(social|x|twitter)\b",
            r"(?i)\b(x[_-]?post|wall[_-]?post|bluesky[_-]?post|mastodon[_-]?post)\b",
            r"(?i)\b(discord[_-]?send|webhook[_-]?post)\b",
        ),
        note="Founder last-yes / kill-switch lane",
    ),
    LockRule(
        lock_id="make_scenario_on",
        ape_decision=DECISION_REQUIRE_APPROVAL,
        tool_name_any=("make_on", "scenario_on", "enable_scenario"),
        args_regex_any=(
            r"(?i)\bmake[_-]?on\b",
            r"(?i)\benable[_-]?(scenario|live)\b",
        ),
        note="Turning a live scenario on needs Founder last-yes",
    ),
    LockRule(
        lock_id="billing_or_spend_provision",
        ape_decision=DECISION_REQUIRE_APPROVAL,
        # Avoid bare "pay" — it false-positives on payload_*, payment_read, etc.
        tool_name_any=(
            "billing_spend",
            "provision_spend",
            "charge",
            "pay",
            "payment_send",
            "send_payment",
        ),
        args_regex_any=(
            r"(?i)\b(billing|invoice)\b",
            r"(?i)\b(provision[_-]?spend|billing[_-]?spend)\b",
            r"(?i)\b(charge|spend)\b",
        ),
        note="Spend / billing acts escalate to human",
    ),
    LockRule(
        lock_id="destructive_wipe",
        ape_decision=DECISION_DENY,
        tool_name_any=(
            "destructive_wipe",
            "wipe",
            "factory_reset",
            "factoryreset",
            "format_disk",
            "delete_all",
            "truncate_db",
            "drop_table",
            "shutil_rmtree",
        ),
        args_regex_any=(
            # Catch rm -rf with or without trailing path; also spaced argv forms.
            r"(?i)\b(wipe|shred|format\s+disk|factory[_-]?reset)\b",
            # Pass 6: no leading \\b — glued prefix (xxxrm -rf) must still hit
            r"(?i)rm\s+-rf\b",
            r"(?i)\bdestructive[_-]?wipe\b",
            r"(?i)\b(delete[_-]?all|truncate[_-]?db|drop[_-]?table|shutil[_-]?rmtree)\b",
            # Shell-in-args: pipe-to-shell / curl|bash class (fail closed).
            r"(?i)(curl|wget)\b[^\n]{0,80}\|\s*(ba)?sh\b",
            r"(?i)\|\s*(ba)?sh\b",
        ),
        note="Hard deny — irreversible wipe class",
    ),
    LockRule(
        lock_id="sku_or_checkout_invent",
        ape_decision=DECISION_DENY,
        tool_name_any=("sku_invent", "invent_sku", "create_checkout_sku"),
        args_regex_any=(
            r"(?i)\b(invent[_-]?sku|sku[_-]?invent)\b",
            r"(?i)\bcheckout[_-]?sku\b",
        ),
        note="Hard deny — inventing commerce SKUs",
    ),
    LockRule(
        lock_id="shell_or_exec",
        ape_decision=DECISION_REQUIRE_APPROVAL,
        tool_name_any=(
            "execute_command",
            "shell",
            "bash",
            "run_shell",
            "run_command",
            "run",
            "exec",
            "system",
            "os_system",
            "subprocess",
            "powershell",
            "cmd_exe",
            "node_eval",
            "eval",
            "py_exec",
        ),
        args_regex_any=(
            r"(?i)\b(execute[_-]?command|run[_-]?shell|run[_-]?command)\b",
            r"(?i)\b(os[_-]?system|subprocess|powershell|cmd[_-]?exe)\b",
            r"(?i)\b(node[_-]?eval|py[_-]?exec)\b",
        ),
        note="Shell/exec class always needs Founder last-yes",
    ),
    # Pass 3: multi-hop / subagent spawn — OpenAI-demon-escape class lateral move.
    LockRule(
        lock_id="multi_hop_subagent",
        ape_decision=DECISION_REQUIRE_APPROVAL,
        tool_name_any=(
            "spawn_agent",
            "spawnagent",
            "run_subagent",
            "run_agent",
            "delegate_agent",
            "create_agent",
            "fork_agent",
            "subagent",
            "multi_agent",
            "agent_spawn",
            "launch_agent",
            "task_delegate",
        ),
        args_regex_any=(
            r"(?i)\b(spawn[_-]?agent|run[_-]?subagent|run[_-]?agent)\b",
            r"(?i)\b(delegate[_-]?agent|fork[_-]?agent|create[_-]?agent)\b",
            r"(?i)\b(multi[_-]?agent|launch[_-]?agent|task[_-]?delegate)\b",
        ),
        note="Multi-hop / subagent spawn needs Founder last-yes (strict may deny)",
    ),
    # Pass 3: outbound HTTP class — no longer intentional soft-allow.
    LockRule(
        lock_id="outbound_http",
        ape_decision=DECISION_REQUIRE_APPROVAL,
        tool_name_any=(
            "http_post",
            "http_put",
            "http_patch",
            "http_request",
            "http_fetch",
            "fetch_url",
            "web_post",
            "webhook",
            "webhook_send",
            "requests_post",
            "axios_post",
            "curl_post",
        ),
        args_regex_any=(
            r"(?i)\b(http[_-]?(post|put|patch|request|fetch))\b",
            r"(?i)\b(webhook[_-]?send|requests[_-]?post|axios[_-]?post|curl[_-]?post)\b",
        ),
        note="Outbound HTTP always ask_human — exfil body/url escalates further below",
    ),
    # Pass 6: help/docs surface — often returns eval-able snippets; strict may deny.
    LockRule(
        lock_id="help_or_docs_eval_surface",
        ape_decision=DECISION_REQUIRE_APPROVAL,
        tool_name_any=(
            "help",
            "tool_help",
            "get_help",
            "man",
            "docs",
            "tool_docs",
            "describe_tool",
            "system_help",
            "assistant_help",
            "opcode_help",
        ),
        args_regex_any=(
            r"(?i)\b(tool[_-]?help|get[_-]?help|describe[_-]?tool|system[_-]?help)\b",
            r"(?i)\b(opcode[_-]?help|assistant[_-]?help)\b",
        ),
        note="Help/docs tool surface needs Founder last-yes (strict may deny)",
    ),
)


# Patterns that fire on *args* regardless of tool_name (safe-looking tools).
_EXFIL_ARGS_RES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"(?i)\b(webhook\.site|requestbin|pipedream\.net|ngrok\.io|ngrok-free\.app)\b",
        r"(?i)discord(?:app)?\.com/api/webhooks/",
        r"(?i)\b(pastebin\.com|hastebin|ghostbin|dpaste)\b",
        r"(?i)\b(exfil|exfiltrate|data[_-]?exfil)\b",
        r"(?i)(/etc/passwd|/etc/shadow|\.ssh/id_rsa|\.env\b|aws_secret|api[_-]?key\s*=)",
        r"(?i)\b(authorization:\s*bearer\s+[a-z0-9._\-]{20,})\b",
        r"(?i)\b(begin\s+(rsa\s+)?private\s+key)\b",
        # Pass 6: path traversal / NUL / eval-able payloads in args
        r"(?i)(\.\./|\.\.\\){2,}",
        r"(?i)\b(os\.system|subprocess\.(?:call|run|Popen)|__import__\s*\(|eval\s*\(|exec\s*\()",
    )
)

# NUL byte in haystack — compiled separately (raw NUL not friendly in all editors)
_NUL_ARGS_RE = re.compile(r"\x00")

# High-confidence *command* wipe / pipe-shell — always scanned (key-aware on benign).
_WIPE_CMD_ARGS_RES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"(?i)rm\s*-rf\b",  # Pass 6 glued + Pass 8 optional-space / rm-rf
        r"(?i)(curl|wget)\b[^\n]{0,80}\|\s*(ba)?sh\b",
        r"(?i)\|\s*(ba)?sh\b",
    )
)

# Vocabulary wipe words — fire on non-benign tools; benign prose may discuss policy.
_WIPE_VOCAB_ARGS_RES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"(?i)\b(wipe|shred|factory[_-]?reset|delete[_-]?all|truncate[_-]?db|drop[_-]?table)\b",
    )
)

# Union kept for session-compose / callers that scan "any wipe shape".
_WIPE_ARGS_RES: tuple[re.Pattern[str], ...] = _WIPE_CMD_ARGS_RES + _WIPE_VOCAB_ARGS_RES

# F59: on doctrine-benign tools, these arg keys are livelihood (not acts).
_SEARCH_NEEDLE_KEYS: frozenset[str] = frozenset(
    {
        "pattern",
        "q",
        "query",
        "grep",
        "regex",
        "needle",
        "search",
        "find",
        "glob",
    }
)
_PROSE_ARG_KEYS: frozenset[str] = frozenset(
    {
        "note",
        "comment",
        "message",
        "description",
        "rationale",
        "summary",
        "memo",
        "remark",
        "msg",
    }
)
# Tools whose primary `text` payload is documentary (not an exec channel).
_DOC_TEXT_TOOLS: frozenset[str] = frozenset(
    {
        "echo",
        "summarize",
        "summarize_text",
        "summarize_local",
        "format_text",
        "markdown_preview",
        "think",
        "plan",
        "reason",
        "remember",
        "recall",
        "describe_data",
        "count_tokens",
    }
)
# High-risk keys — always wipe-scanned even on benign tools (smuggle / exec shape).
_WIPE_HIGH_RISK_KEYS: frozenset[str] = frozenset(
    {
        "cmd",
        "command",
        "script",
        "code",
        "shell",
        "exec",
        "argv",
        "bash",
        "stdin",
        "sql",
        "md",
        "html",
        "css",
        "js",
        "powershell",
    }
)

# F60: high-FP lock tokens — exact tool_name only (sep-token match too greedy).
_EXACT_ONLY_NAME_TOKENS: frozenset[str] = frozenset(
    {
        "run",
        "exec",
        "pay",
        "eval",
        "bash",
        "shell",
        "charge",
        "spend",
        "tweet",
        "wipe",
        "help",
        "docs",
        "man",
    }
)


# ---------------------------------------------------------------------------
# Pass 6: policy env seal — freeze PHOENIX_GATE_* after first read so an agent
# that can mutate process env mid-session cannot soften strict/TTL/unknown.
# Tests call reset_policy_env_seal() in setUp before mutating env.
# ---------------------------------------------------------------------------
_POLICY_ENV_SEAL: dict[str, str] | None = None
_MAX_DECODE_DEPTH = 3
_MAX_SCAN_CHARS = 65536
_UNICODE_ESC_RE = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\U([0-9a-fA-F]{8})"
)


def reset_policy_env_seal() -> None:
    """Test / reload helper — clear sealed PHOENIX_GATE_* snapshot."""
    global _POLICY_ENV_SEAL
    _POLICY_ENV_SEAL = None


def _policy_env_seal_enabled() -> bool:
    # Read raw (unsealed) so operators can disable seal itself via env at boot.
    v = os.environ.get("PHOENIX_GATE_SEAL_ENV", "1").strip().lower()
    return v not in ("0", "false", "no", "off", "")


def _policy_env(name: str, default: str) -> str:
    """Return env value; when seal is on, freeze each key on first read."""
    global _POLICY_ENV_SEAL
    if not _policy_env_seal_enabled():
        return os.environ.get(name, default)
    if _POLICY_ENV_SEAL is None:
        _POLICY_ENV_SEAL = {}
    if name not in _POLICY_ENV_SEAL:
        _POLICY_ENV_SEAL[name] = os.environ.get(name, default)
    return _POLICY_ENV_SEAL[name]


def strict_mode_enabled() -> bool:
    """PHOENIX_GATE_STRICT defaults ON (1) for demo / Founder craft bar."""
    v = _policy_env("PHOENIX_GATE_STRICT", "1").strip().lower()
    return v not in ("0", "false", "no", "off", "")


def strict_unknown_decision() -> str:
    """Unknown-tool decision under strict: deny (default) or require_approval."""
    v = _policy_env("PHOENIX_GATE_STRICT_UNKNOWN", "deny").strip().lower()
    if v in ("require_approval", "ask_human", "approve", "approval"):
        return DECISION_REQUIRE_APPROVAL
    return DECISION_DENY


def insecure_policy_env_warnings() -> list[str]:
    """Pass 9: human-readable warnings for boot-time insecure / softened policy env.

    Does not change decisions — pins and seals live elsewhere. Callers (gateway)
    attach these to the first GateResult extras so operators see the soften.
    """
    warns: list[str] = []
    if not strict_mode_enabled():
        warns.append(
            "PHOENIX_GATE_STRICT is off — unknown tools may soft-pass to APE "
            "(boot-time poison or intentional demo soften)"
        )
    if not _policy_env_seal_enabled():
        warns.append(
            "PHOENIX_GATE_SEAL_ENV is off — mid-session env soften is possible"
        )
    unknown = _policy_env("PHOENIX_GATE_STRICT_UNKNOWN", "deny").strip().lower()
    if unknown in ("require_approval", "ask_human", "approve", "approval"):
        warns.append(
            "PHOENIX_GATE_STRICT_UNKNOWN softens unknown tools to require_approval "
            "(not hard deny)"
        )
    tip = _policy_env("PHOENIX_GATE_RECEIPT_TIP", "1").strip().lower()
    if tip in ("0", "false", "no", "off", ""):
        warns.append(
            "PHOENIX_GATE_RECEIPT_TIP is off — truncation forks may go undetected"
        )
    return warns


def normalize_tool_name(tool_name: str | None) -> str:
    """NFKC + strip ZW/bidi/NUL/combining marks + collapse whitespace + lower.

    Frustrates unicode rename tricks, null-byte truncation, and prompt-
    injection-ish spaced / RTL / accent-glued names.
    """
    raw = tool_name if isinstance(tool_name, str) else ""
    text = unicodedata.normalize("NFKC", raw)
    text = text.replace("\x00", "")
    text = _ZW_RE.sub("", text)
    # Strip combining marks (Mn) so publish + U+0301 → publish
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    text = _WS_RE.sub("", text)
    return text.strip().lower()


def _bytes_to_scan_text(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        # Drop NULs from codec noise (gzip headers etc.) so scan haystack
        # stays clean; raw-arg NUL smuggling is checked separately.
        text = text.replace(chr(0), "")
        if any(ch.isprintable() or ch in "\n\r\t" for ch in text):
            return text
    return None


def _try_decompress(raw: bytes) -> Optional[bytes]:
    """Best-effort gzip / zlib / raw-deflate inflate (Pass 6)."""
    if not raw or len(raw) > 1_000_000:
        return None
    decoders = (
        gzip.decompress,
        zlib.decompress,
        lambda b: zlib.decompress(b, -zlib.MAX_WBITS),
    )
    for dec in decoders:
        try:
            out = dec(raw)
        except Exception:  # noqa: BLE001
            continue
        if out:
            return out
    return None


def _try_b64_raw(token: str) -> Optional[bytes]:
    s = token.strip()
    if len(s) < 8 or len(s) > 8192:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+=*", s):
        return None
    pad = (-len(s)) % 4
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            try:
                raw = decoder(s + ("=" * pad), validate=False)
            except TypeError:
                raw = decoder(s + ("=" * pad))
        except (binascii.Error, ValueError):
            continue
        if raw:
            return raw
    return None


def _try_b64_decode(token: str) -> Optional[str]:
    raw = _try_b64_raw(token)
    if raw is None:
        return None
    inflated = _try_decompress(raw)
    if inflated is not None:
        inf_text = _bytes_to_scan_text(inflated)
        if inf_text:
            return inf_text
    text = _bytes_to_scan_text(raw)
    if text is None:
        return None
    # Reject mostly-binary latin-1 noise (gzip headers, random pads).
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    if printable / max(len(text), 1) < 0.85:
        return None
    return text


def _try_hex_decode(token: str) -> Optional[str]:
    s = token.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) < 8 or len(s) > 8192 or len(s) % 2:
        return None
    if not re.fullmatch(r"[0-9a-f]+", s):
        return None
    try:
        raw = bytes.fromhex(s)
    except Exception:  # noqa: BLE001
        return None
    inflated = _try_decompress(raw)
    if inflated is not None:
        inf_text = _bytes_to_scan_text(inflated)
        if inf_text:
            return inf_text
    text = _bytes_to_scan_text(raw)
    if text is None:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    if printable / max(len(text), 1) < 0.85:
        return None
    return text


def _one_layer_decoded_fragments(text: str) -> list[str]:
    """Best-effort one-layer b64/hex/(gzip) decode of tokens + whole string."""
    out: list[str] = []
    if not text:
        return out
    compact = re.sub(r"\s+", "", text)
    for attempt in (_try_b64_decode(compact), _try_hex_decode(compact)):
        if attempt:
            out.append(attempt)
    # Bound token walk — avoid ReDoS-ish blowups on huge inputs
    span = text if len(text) <= _MAX_SCAN_CHARS else (text[:4096] + text[-4096:])
    for token in re.findall(r"[A-Za-z0-9+_=-]{8,8192}", span):  # no slash — avoid /path/tokens
        for attempt in (_try_b64_decode(token), _try_hex_decode(token)):
            if attempt:
                out.append(attempt)
    return out


def _multi_layer_decoded_fragments(text: str, max_depth: int = _MAX_DECODE_DEPTH) -> list[str]:
    """BFS multi-layer decode up to max_depth (Pass 6 — closes double/triple b64)."""
    if not text or max_depth < 1:
        return []
    out: list[str] = []
    seen: set[str] = set()
    frontier = [text]
    for _depth in range(max_depth):
        nxt: list[str] = []
        for cur in frontier:
            for frag in _one_layer_decoded_fragments(cur):
                if frag in seen or frag == cur:
                    continue
                seen.add(frag)
                out.append(frag)
                nxt.append(frag)
        frontier = nxt
        if not frontier:
            break
    return out


def _unescape_unicode_escapes(text: str) -> str:
    """Decode literal \\uXXXX / \\xXX / \\UXXXXXXXX sequences in scan haystack."""
    if not text or "\\" not in text:
        return text

    def _repl(m: re.Match[str]) -> str:
        hexpart = m.group(1) or m.group(2) or m.group(3)
        try:
            return chr(int(hexpart, 16))
        except ValueError:
            return m.group(0)

    try:
        return _UNICODE_ESC_RE.sub(_repl, text)
    except Exception:  # noqa: BLE001
        return text


def _scrub_invisible_for_scan(text: str) -> str:
    """Strip ZW/bidi/BOM + Mn + Cf from args scan haystack (Pass 10).

    ``normalize_tool_name`` already scrubbed tool names; args values did not —
    zero-width / tag / variation-selector glue between ``r`` and ``m`` defeated
    wipe regex while looking like ``rm -rf`` to a human/terminal.
    """
    if not text:
        return ""
    cleaned = unicodedata.normalize("NFKC", text)
    cleaned = cleaned.replace("\x00", "")
    cleaned = _ZW_RE.sub("", cleaned)
    cleaned = "".join(
        ch for ch in cleaned if unicodedata.category(ch) not in ("Mn", "Cf")
    )
    return cleaned


def _try_percent_decode(text: str) -> Optional[str]:
    """One-layer URL percent-decode into scan seeds (Pass 10)."""
    if not text or "%" not in text:
        return None
    try:
        out = urllib.parse.unquote(text, errors="replace")
    except Exception:  # noqa: BLE001
        return None
    if out and out != text:
        return out
    try:
        out2 = urllib.parse.unquote_plus(text, errors="replace")
    except Exception:  # noqa: BLE001
        return None
    if out2 and out2 != text:
        return out2
    return None


def _try_html_unescape(text: str) -> Optional[str]:
    """One-layer HTML entity unescape (&#NNN; / &#xHH; / &nbsp;) — Pass 10."""
    if not text or "&" not in text:
        return None
    try:
        out = html.unescape(text)
    except Exception:  # noqa: BLE001
        return None
    if out and out != text:
        return out
    return None


def _scan_window(text: str, limit: int = _MAX_SCAN_CHARS) -> str:
    """Head+tail window so wipe-at-end of huge pads still hits (Pass 6 DoS)."""
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + "\n" + text[-half:]


def _flatten_args(args: Mapping[str, Any] | None) -> str:
    """Flatten args to a searchable string (joins list argv so rm/-rf smuggle hits)."""
    if not args:
        return ""
    parts: list[str] = []
    for key, value in args.items():
        parts.append(str(key).replace("\x00", ""))
        if isinstance(value, (list, tuple)):
            joined = " ".join(str(v) for v in value)
            parts.append(joined.replace("\x00", " "))
            parts.extend(str(v).replace("\x00", "") for v in value)
        elif isinstance(value, Mapping):
            parts.append(_flatten_args(value))
        else:
            parts.append(str(value).replace("\x00", ""))
    return " ".join(parts)


def _concat_arg_values(args: Mapping[str, Any] | None) -> str:
    """Concatenate scalar + list values (no keys) for chunked-payload reassembly."""
    if not args:
        return ""
    parts: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, Mapping):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)
        else:
            parts.append(str(obj).replace("\x00", ""))

    walk(args)
    return "".join(parts)



def _args_contain_nul(args: Mapping[str, Any] | None) -> bool:
    """True if any raw arg key/value contains a NUL byte (pre-strip)."""
    if not args:
        return False

    def walk(obj: Any) -> bool:
        if isinstance(obj, Mapping):
            return any(chr(0) in str(k) or walk(v) for k, v in obj.items())
        if isinstance(obj, (list, tuple)):
            return any(walk(v) for v in obj)
        return chr(0) in str(obj)

    return walk(args)


def flatten_args_for_scan(args: Mapping[str, Any] | None) -> str:
    """Flatten + multi-layer decode + chunk concat + unicode-escape + polyglot (Pass 6/8)."""
    flat = _flatten_args(args)
    chunk = _concat_arg_values(args)
    # Always seed individual values + concat (not only when absent from flat),
    # so gzip+b64 payloads containing "/" still whole-string-decode.
    seeds: list[str] = []
    if flat:
        seeds.append(flat)
    if chunk:
        seeds.append(chunk)
    if args:
        for v in args.values():
            if isinstance(v, str) and v:
                seeds.append(v)
            elif isinstance(v, (list, tuple)):
                joined = "".join(str(x) for x in v)
                if joined:
                    seeds.append(joined)
                    seeds.append(" ".join(str(x) for x in v))
    # Pass 8: comment/fence-stripped + value-space-joined seeds (polyglot / split wipe)
    seeds.extend(_polyglot_scan_seeds(args))
    # de-dupe preserve order
    seen: set[str] = set()
    uniq_seeds: list[str] = []
    for s in seeds:
        if s not in seen:
            seen.add(s)
            uniq_seeds.append(s)

    # Pass 10: expand seeds with percent-decode + HTML-unescape (one layer each).
    expanded: list[str] = []
    for seed in uniq_seeds:
        expanded.append(seed)
        pct = _try_percent_decode(seed)
        if pct:
            expanded.append(pct)
        html_u = _try_html_unescape(seed)
        if html_u:
            expanded.append(html_u)
            # percent after html or html after percent (shallow chain)
            pct2 = _try_percent_decode(html_u)
            if pct2:
                expanded.append(pct2)
            html2 = _try_html_unescape(pct) if pct else None
            if html2:
                expanded.append(html2)
    # de-dupe again
    seen2: set[str] = set()
    uniq_expanded: list[str] = []
    for s in expanded:
        if s not in seen2:
            seen2.add(s)
            uniq_expanded.append(s)

    decoded: list[str] = []
    for seed in uniq_expanded:
        # Include expanded plaintext seeds (percent/html) themselves — not only
        # further b64/hex layers — so ``rm%20-rf`` / ``&#114;&#109;`` hit wipe.
        if seed and seed != flat:
            decoded.append(seed)
        decoded.extend(_multi_layer_decoded_fragments(seed))
        unescaped = _unescape_unicode_escapes(seed)
        if unescaped != seed:
            decoded.append(unescaped)
            decoded.extend(_multi_layer_decoded_fragments(unescaped))
    merged = flat
    if decoded:
        # Prefer text-y fragments; still include all for scan coverage
        merged = flat + " " + " ".join(decoded)
    if chunk and chunk not in merged:
        merged = merged + " " + chunk
    spaced = _values_space_joined(args)
    if spaced and spaced not in merged:
        merged = merged + " " + spaced
    # Pass 10: scrub invisible/format chars so ZW-glued wipe cannot evade regex.
    return _scan_window(_scrub_invisible_for_scan(merged))


def _name_matches(normalized_name: str, candidate: str) -> bool:
    """Token-aware tool match — avoids bare substring hits like pay∈payload.

    Short tokens (len<=4: run/exec/pay/eval/…) and F60 high-FP tokens
    (shell/charge/spend/tweet/…) match exact only so ``shell`` does not claim
    ``shell_history_read`` and ``charge`` does not claim ``charge_report``.
    Explicit aliases remain in each lock's tool_name_any list.
    """
    cand = normalize_tool_name(candidate)
    if not cand or not normalized_name:
        return False
    if normalized_name == cand:
        return True
    # Exact-only: short tokens + high-FP livelihood-adjacent verbs (F60).
    if len(cand) <= 4 or cand in _EXACT_ONLY_NAME_TOKENS:
        return False
    # Separator-aware: publish_message, message_publish, foo-publish-bar
    seps = "._-/"
    padded = f"/{normalized_name}/"
    for s in seps:
        padded = padded.replace(s, "/")
    return f"/{cand}/" in padded



# ---------------------------------------------------------------------------
# Pass 8 (outside Fable / jailbreak / social): sanitize echoes, persuasion
# non-authority, polyglot/comment scan seeds. Persuasion never grants allow.
# ---------------------------------------------------------------------------

_THREAT_ECHO_MAX = 160

# Phrases that try to confuse classifiers / approve UI (Fable / DAN / roleplay).
_PERSUASION_RES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\b",
        r"(?i)\bignore\s+(all\s+)?(policy|policies|instructions|rules)\b",
        r"(?i)\b(authorized|authorised)\s+by\s+(founder|jesse|osmantic|admin|ape)\b",
        r"(?i)\b(founder|jesse)\s+(pre[-_]?authorized|override|approved)\b",
        r"(?i)\b(roleplay|role[- ]?play|pretend|act)\s+as\b",
        r"(?i)\byou\s+are\s+(now\s+)?(an?\s+)?(osmantic|ape|admin|founder|dan)\b",
        r"(?i)\b(do\s+anything\s+now|\bDAN\b|jailbreak\s+mode|developer\s+mode)\b",
        r"(?i)\b(system\s*:?\s*grant\s+consumed|grant\s+consumed\s+by\s+founder)\b",
        r"(?i)\bthreat\s*=\s*(none|safe|benign|cleared)\b",
        r"(?i)\block_id\s*=\s*(none|benign|safe|cleared)\b",
        r"(?i)\b(ape_decision|decision)\s*[:=]\s*allow\b",
        r"(?i)\b(bypass|skip|disable)\s+(policy|gate|phoenix|ape)\b",
    )
)

# Arg keys that look like authority / policy injection — values are scanned for
# wipe/exfil but NEVER treated as kit decisions (non-authority).
_AUTHORITY_CLAIM_KEYS = frozenset(
    {
        "authorized",
        "authorised",
        "authorized_by",
        "authorised_by",
        "founder_override",
        "founder_authorized",
        "ape_decision",
        "phoenix_decision",
        "grant_consumed",
        "lock_id",
        "threat_summary",
        "threat",
        "approval",
        "approved",
        "approver",
        "bypass_policy",
        "ignore_policy",
        "policy_override",
        "admin_override",
        "system_prompt",
        "jailbreak",
    }
)


def _tool_fp(normalized_name: str) -> str:
    return hashlib.sha256((normalized_name or "").encode("utf-8")).hexdigest()[:12]


def sanitize_echo_field(text: str | None, *, max_len: int = _THREAT_ECHO_MAX) -> str:
    """Redact persuasion / jailbreak phrases from UI-facing echo strings.

    Kit-owned lock_ids and fixed threat phrases pass through; attacker-shaped
    'authorized by Founder' / 'threat=none' fragments become [redacted].
    """
    raw = text if isinstance(text, str) else ""
    if not raw:
        return ""
    out = raw
    for pat in _PERSUASION_RES:
        out = pat.sub("[redacted]", out)
    # Collapse whitespace after redaction
    out = re.sub(r"\s+", " ", out).strip()
    if len(out) > max_len:
        out = out[: max_len - 1] + "…"
    return out


def sanitize_threat_summary(
    text: str | None,
    *,
    persuasion: bool = False,
    max_len: int = _THREAT_ECHO_MAX,
) -> str:
    """Sanitize threat_summary for pending / approve / receipt echoes (Pass 8)."""
    cleaned = sanitize_echo_field(text, max_len=max_len)
    if persuasion:
        tag = "persuasion markers present (non-authority — ignored)"
        if tag.lower() not in cleaned.lower():
            if cleaned:
                cleaned = f"{cleaned}; {tag}"
            else:
                cleaned = tag
            if len(cleaned) > max_len:
                cleaned = cleaned[: max_len - 1] + "…"
    return cleaned


def detect_persuasion(
    tool_name: str | None = None,
    args: Mapping[str, Any] | None = None,
) -> bool:
    """True if tool_name / args carry Fable-style jailbreak or authority claims.

    Detection only — never grants allow / never overrides a hard deny.
    """
    blobs: list[str] = []
    if isinstance(tool_name, str) and tool_name:
        blobs.append(tool_name)
    if args:
        for k, v in args.items():
            ks = str(k)
            if ks.lower().replace("-", "_") in _AUTHORITY_CLAIM_KEYS:
                return True
            blobs.append(ks)
            if isinstance(v, (list, tuple)):
                blobs.extend(str(x) for x in v)
            elif isinstance(v, Mapping):
                blobs.append(_flatten_args(v))
            else:
                blobs.append(str(v))
    hay = " ".join(blobs)
    if not hay:
        return False
    return any(pat.search(hay) for pat in _PERSUASION_RES)


def _strip_polyglot_wrappers(text: str) -> str:
    """Expose content inside markdown fences / HTML / C / hash comments for scan."""
    if not text:
        return ""
    s = text
    # Fenced code blocks — keep inner body
    s = re.sub(r"```[\w+-]*\s*([\s\S]*?)```", r"\1", s)
    # HTML / XML comments
    s = re.sub(r"<!--([\s\S]*?)-->", r"\1", s)
    # C-style block comments
    s = re.sub(r"/\*([\s\S]*?)\*/", r"\1", s)
    # Line comments // and #
    s = re.sub(r"(?m)//.*?$", " ", s)
    s = re.sub(r"(?m)#.*?$", " ", s)
    return s


def _values_space_joined(args: Mapping[str, Any] | None) -> str:
    """Join all scalar/list values with spaces (Pass 8 split-key wipe)."""
    if not args:
        return ""
    parts: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, Mapping):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)
        else:
            parts.append(str(obj).replace("\x00", ""))

    walk(args)
    return " ".join(parts)


def _polyglot_scan_seeds(args: Mapping[str, Any] | None) -> list[str]:
    """Extra haystack seeds: comment-stripped + value-joined polyglot bodies."""
    seeds: list[str] = []
    if not args:
        return seeds
    spaced = _values_space_joined(args)
    if spaced:
        seeds.append(spaced)
        stripped = _strip_polyglot_wrappers(spaced)
        if stripped and stripped != spaced:
            seeds.append(stripped)
    flat = _flatten_args(args)
    if flat:
        stripped_flat = _strip_polyglot_wrappers(flat)
        if stripped_flat and stripped_flat != flat:
            seeds.append(stripped_flat)
    for v in args.values():
        if isinstance(v, str) and v:
            stripped = _strip_polyglot_wrappers(v)
            if stripped and stripped != v:
                seeds.append(stripped)
    return seeds


def _hint(
    *,
    lock_id: str,
    force_decision: str,
    note: str = "",
    threat_summary: str = "",
    persuasion_non_authority: bool = False,
) -> LockHint:
    raw_threat = threat_summary or note or lock_id
    return LockHint(
        matched=True,
        lock_id=lock_id,
        force_decision=force_decision,
        phoenix_verdict=APE_TO_PHOENIX.get(force_decision),
        reason=f"phoenix lock matched: {lock_id}",
        note=note,
        threat_summary=sanitize_threat_summary(
            raw_threat, persuasion=persuasion_non_authority
        ),
        persuasion_non_authority=persuasion_non_authority,
    )



def _annotate_persuasion(hint: LockHint, persuasion: bool) -> LockHint:
    """Attach non-authority persuasion flag without changing force_decision."""
    if not persuasion or hint.persuasion_non_authority:
        return hint
    return LockHint(
        matched=hint.matched,
        lock_id=hint.lock_id,
        force_decision=hint.force_decision,
        phoenix_verdict=hint.phoenix_verdict,
        reason=hint.reason,
        note=hint.note,
        threat_summary=sanitize_threat_summary(
            hint.threat_summary, persuasion=True
        ),
        persuasion_non_authority=True,
    )


def _arg_key_norm(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_")


def _partition_benign_wipe_args(
    tool_name: str, args: Mapping[str, Any] | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """F59: split benign args into high-risk (full CMD) vs content (rm -rf only).

    Returns (high_risk_args, content_args). Search needles + prose keys omitted
    from both. Documentary `text` on echo/summarize/think omitted. Draft `body`
    lands in content (rm -rf still denies; curl|bash prose does not).
    """
    high: dict[str, Any] = {}
    content: dict[str, Any] = {}
    if not args:
        return high, content
    name = normalize_tool_name(tool_name)
    doc_text = name in _DOC_TEXT_TOOLS
    for k, v in args.items():
        lk = _arg_key_norm(k)
        if lk in _SEARCH_NEEDLE_KEYS or lk in _PROSE_ARG_KEYS:
            continue
        if doc_text and lk == "text":
            continue
        if lk in _WIPE_HIGH_RISK_KEYS:
            high[k] = v
        else:
            content[k] = v
    return high, content


def _haystack_for(name: str, subset: Mapping[str, Any]) -> str:
    if not subset:
        return name
    return f"{name} {flatten_args_for_scan(subset)}".lower()


def _scan_args_always(
    haystack: str,
    *,
    tool_name: str = "",
    args: Mapping[str, Any] | None = None,
) -> Optional[LockHint]:
    """Args always scanned — even when tool_name looks safe.

    F59 enablement: on doctrine-benign tools, wipe scanning is key-aware —
    high-risk keys get full CMD/pipe-shell patterns; remaining content keys
    (e.g. draft body) only match ``rm -rf``; search needles + prose notes are
    omitted; wipe vocabulary does not fire. Exfil still uses full haystack.
    """
    name = normalize_tool_name(tool_name) if tool_name else ""
    benign = bool(name) and name in STRICT_BENIGN_ALLOWLIST

    wipe_deny = _hint(
        lock_id="destructive_wipe",
        force_decision=DECISION_DENY,
        note="Hard deny — wipe/pipe-shell in args (tool_name ignored)",
        threat_summary="args contain destructive wipe / pipe-to-shell pattern",
    )

    if benign and args is not None:
        high, content = _partition_benign_wipe_args(name, args)
        high_hs = _haystack_for(name, high)
        for pat in _WIPE_CMD_ARGS_RES:
            if pat.search(high_hs):
                return wipe_deny
        # Content tier: only rm -rf (drafting "don't curl|bash" is livelihood)
        content_hs = _haystack_for(name, content)
        if _WIPE_CMD_ARGS_RES[0].search(content_hs):  # rm\s*-rf
            return wipe_deny
    else:
        for pat in _WIPE_CMD_ARGS_RES:
            if pat.search(haystack):
                return wipe_deny
        for pat in _WIPE_VOCAB_ARGS_RES:
            if pat.search(haystack):
                return wipe_deny

    for pat in _EXFIL_ARGS_RES:
        if pat.search(haystack):
            return _hint(
                lock_id="exfil_args_pattern",
                force_decision=DECISION_DENY,
                note="Hard deny — exfil / secret-leak pattern in args",
                threat_summary="args match exfil sink or secret-material pattern",
            )
    return None


def _outbound_exfil_escalation(
    name: str, haystack: str, base: LockHint
) -> LockHint:
    """If outbound HTTP lock matched and body/url looks like exfil → deny."""
    if base.lock_id != "outbound_http":
        return base
    for pat in _EXFIL_ARGS_RES:
        if pat.search(haystack):
            return _hint(
                lock_id="outbound_http_exfil",
                force_decision=DECISION_DENY,
                note="Hard deny — outbound HTTP with exfil-looking URL/body",
                threat_summary="outbound tool args look like exfil sink",
            )
    # Still require_approval for plain http_post (no longer soft-allow).
    return LockHint(
        matched=True,
        lock_id=base.lock_id,
        force_decision=base.force_decision,
        phoenix_verdict=base.phoenix_verdict,
        reason=base.reason,
        note=base.note,
        threat_summary="outbound HTTP tool requires Founder last-yes",
    )


def classify_lock(
    tool_name: str,
    args: Mapping[str, Any] | None = None,
    locks: Sequence[LockRule] = DEFAULT_LOCKS,
    *,
    strict: Optional[bool] = None,
    session_id: Optional[str] = None,
) -> LockHint:
    """Return the first matching Phoenix named-lock hint (or unmatched).

    Empty / whitespace-only tool names hard-deny (fail closed) — no anonymous
    execute path through an unmatched default-allow APE.

    Pass 3: args always scanned (incl. one-layer decode); strict unknown deny;
    outbound HTTP gated; multi-hop subagent class locked.

    Pass 4 (inside-as-Hermes): optional session_id enables compose-wipe and
    secret→exfil taint across tool calls; bypass_gate args denied.

    Pass 6 (ultra-demon): multi-layer decode, chunk concat, unicode-escape
    unescape, glued-wipe, NUL/Mn strip, scan window, help lock, env seal.

    Pass 8 (Fable / jailbreak / social): threat echoes sanitized (no raw
    jailbreak tool_name); persuasion / authority-claim strings are non-authority;
    polyglot + comment scan seeds; split-value wipe.
    """
    # Pass 6: NUL in raw tool_name is always a smuggle — deny before normalize.
    if isinstance(tool_name, str) and chr(0) in tool_name:
        return _hint(
            lock_id="null_byte_in_tool_name",
            force_decision=DECISION_DENY,
            note="Hard deny — NUL byte in tool_name (truncation / smuggle class)",
            threat_summary="NUL byte present in raw tool_name",
        )

    name = normalize_tool_name(tool_name)
    persuasion = detect_persuasion(tool_name, args)

    if not name:
        return _hint(
            lock_id="empty_tool_name",
            force_decision=DECISION_DENY,
            note="Hard deny — missing/blank tool_name",
            threat_summary="empty or whitespace-only tool_name",
            persuasion_non_authority=persuasion,
        )

    # Homoglyph / non-ASCII letter tool names after NFKC → hard deny.
    if any(ord(c) > 127 and c.isalpha() for c in name):
        return _hint(
            lock_id="suspicious_unicode_tool_name",
            force_decision=DECISION_DENY,
            note="Hard deny — non-ASCII letters in tool_name after normalize",
            threat_summary="non-ASCII letters remain in tool_name after NFKC/ZW strip",
        )

    # Pass 6: NUL in *raw* args values (before strip/decode) — smuggle class.
    if _args_contain_nul(args):
        return _hint(
            lock_id="null_byte_in_args",
            force_decision=DECISION_DENY,
            note="Hard deny — NUL byte in args (path truncation / smuggle class)",
            threat_summary="NUL byte present in raw tool args",
        )

    haystack = f"{name} {flatten_args_for_scan(args)}".lower()

    # Pass 4: session compose / taint / bypass BEFORE observe (prior window).
    sess_hit = _scan_session_compose_and_taint(session_id, name, haystack)
    if sess_hit is not None:
        _observe_session(session_id, tool_name, args)
        return _annotate_persuasion(sess_hit, persuasion)

    # Args-always scan first (safe tool_name + evil payload).
    args_hit = _scan_args_always(haystack, tool_name=tool_name, args=args)
    if args_hit is not None:
        _observe_session(session_id, tool_name, args)
        return _annotate_persuasion(args_hit, persuasion)

    use_strict = strict_mode_enabled() if strict is None else strict

    # Record this call into session memory for subsequent compose/taint checks.
    _observe_session(session_id, tool_name, args)

    for rule in locks:
        name_hit = any(_name_matches(name, t) for t in rule.tool_name_any)
        # Pass 10/11 enablement / anti-paralysis:
        # Soft *and* hard lock args-regex must NOT fire on doctrine-benign
        # tools — "do not publish yet" / "wipe is DENY" in notes is prose,
        # not an act. Tool_name matches still apply (publish, wipe, …).
        # Real wipe/exfil in high-risk keys remain covered by args-always (F59).
        if name in STRICT_BENIGN_ALLOWLIST:
            regex_hit = False
        else:
            regex_hit = any(
                re.search(pat, haystack) for pat in rule.args_regex_any
            )
        if name_hit or regex_hit:
            hint = _hint(
                lock_id=rule.lock_id,
                force_decision=rule.ape_decision,
                note=rule.note,
                threat_summary=f"{rule.lock_id}: {rule.note}" if rule.note else rule.lock_id,
            )
            # Multi-hop under strict → escalate to deny when configured.
            if (
                rule.lock_id == "multi_hop_subagent"
                and use_strict
                and strict_unknown_decision() == DECISION_DENY
            ):
                return _hint(
                    lock_id="multi_hop_subagent",
                    force_decision=DECISION_DENY,
                    note="Hard deny under strict — multi-hop / subagent spawn",
                    threat_summary="strict mode denies SpawnAgent / run_subagent class",
                    persuasion_non_authority=persuasion,
                )
            # Pass 6: help/docs under strict → deny (eval-able surface).
            if (
                rule.lock_id == "help_or_docs_eval_surface"
                and use_strict
                and strict_unknown_decision() == DECISION_DENY
            ):
                return _hint(
                    lock_id="help_or_docs_eval_surface",
                    force_decision=DECISION_DENY,
                    note="Hard deny under strict — help/docs eval-able surface",
                    threat_summary="strict mode denies help/docs tools that can return eval-able content",
                    persuasion_non_authority=persuasion,
                )
            return _annotate_persuasion(
                _outbound_exfil_escalation(name, haystack, hint), persuasion
            )

    # Strict: unknown tools fail closed (benign allowlist may still soft-pass).
    if use_strict and name not in STRICT_BENIGN_ALLOWLIST:
        decision = strict_unknown_decision()
        return _hint(
            lock_id="unknown_tool_strict",
            force_decision=decision,
            note=(
                "Strict mode — unknown tool denied"
                if decision == DECISION_DENY
                else "Strict mode — unknown tool needs Founder last-yes"
            ),
            threat_summary=(
                f"unknown tool under PHOENIX_GATE_STRICT (tool_fp={_tool_fp(name)})"
            ),
            persuasion_non_authority=persuasion,
        )

    if persuasion:
        return LockHint(
            matched=False,
            reason="no phoenix named lock matched",
            threat_summary=sanitize_threat_summary(
                "", persuasion=True
            ),
            persuasion_non_authority=True,
        )
    return LockHint(matched=False, reason="no phoenix named lock matched")

# ---------------------------------------------------------------------------
# Pass 4 (inside-as-Hermes): session-scoped compose / taint memory
# ---------------------------------------------------------------------------
# Hermes-class agents can split a wipe across two "innocent" calls, or read
# secrets then http_post. Per-call locks miss that. Session memory is in-pack
# gold: join recent fragments, mark secret reads, deny compose/taint.

_SESSION_LOCK = threading.Lock()
# session_id → deque of recent flattened arg/tool fragments (strings)
_SESSION_FRAGMENTS: dict[str, deque[str]] = {}
# session_id → True if a secret-looking read was observed
_SESSION_SECRET_TAINT: dict[str, bool] = {}
_SESSION_FRAGMENT_LIMIT = 12  # rolling window

_SECRET_PATH_RE = re.compile(
    r"(?i)(\.env\b|\.ssh/id_|\.aws/credentials|/etc/passwd|"
    r"secrets?\.ya?ml|api[_-]?keys?\.json|private[_-]?key|"
    r"wallet\.dat|mnemonic|seed[_-]?phrase)"
)

_READISH_TOOLS = frozenset(
    {
        "read_file",
        "cat",
        "head",
        "safe_ls",
        "ls",
        "list_dir",
        "list_directory",
        "file_stat",
        "stat",
        "get_secret",
        "read_secret",
        "load_env",
        "dotenv_load",
    }
)

_BYPASS_GATE_ARGS_RE = re.compile(
    r"(?i)\b("
    r"bypass[_-]?gate|skip[_-]?gate|no[_-]?gate|ungated|without[_-]?gate|"
    r"inherit[_-]?gate\s*[:=]?\s*(false|0|no|off)"
    r")\b"
)


def reset_session_memory() -> None:
    """Test helper — clear session compose / taint state."""
    with _SESSION_LOCK:
        _SESSION_FRAGMENTS.clear()
        _SESSION_SECRET_TAINT.clear()


def session_is_secret_tainted(session_id: Optional[str]) -> bool:
    if not session_id:
        return False
    with _SESSION_LOCK:
        return bool(_SESSION_SECRET_TAINT.get(session_id))


def _observe_session(session_id: Optional[str], tool_name: str, args: Mapping[str, Any] | None) -> None:
    """Record fragment + secret-read taint for a session (best-effort)."""
    if not session_id:
        return
    name = normalize_tool_name(tool_name)
    flat = flatten_args_for_scan(args)
    frag = f"{name} {flat}".strip().lower()
    with _SESSION_LOCK:
        dq = _SESSION_FRAGMENTS.get(session_id)
        if dq is None:
            dq = deque(maxlen=_SESSION_FRAGMENT_LIMIT)
            _SESSION_FRAGMENTS[session_id] = dq
        if frag:
            dq.append(frag)
        # Secret-path read → taint session
        if name in _READISH_TOOLS or name.startswith("read"):
            if _SECRET_PATH_RE.search(flat) or _SECRET_PATH_RE.search(name):
                _SESSION_SECRET_TAINT[session_id] = True
        # Explicit secret tools
        if name in ("get_secret", "read_secret", "load_env", "dotenv_load"):
            _SESSION_SECRET_TAINT[session_id] = True


def _session_joined_haystack(session_id: Optional[str], current: str) -> str:
    if not session_id:
        return current
    with _SESSION_LOCK:
        dq = _SESSION_FRAGMENTS.get(session_id)
        if not dq:
            return current
        prior = " ".join(dq)
    return f"{prior} {current}".strip()


def _scan_session_compose_and_taint(
    session_id: Optional[str],
    name: str,
    haystack: str,
) -> Optional[LockHint]:
    """After per-call scan: check composed wipe + secret→outbound taint."""
    if not session_id:
        return None

    # Bypass-gate / ungoverned child markers in args → deny (spawn without inherit).
    if _BYPASS_GATE_ARGS_RE.search(haystack):
        return _hint(
            lock_id="ungated_child_or_bypass",
            force_decision=DECISION_DENY,
            note="Hard deny — bypass_gate / inherit_gate=false / skip_gate in args",
            threat_summary="args request ungated / non-inheriting child or gate skip",
        )

    joined = _session_joined_haystack(session_id, haystack)
    # Compose wipe: split "rm" + "-rf" (or wipe+all) across calls — looser
    # window than per-call regex so innocent halves still compose to deny.
    current_wipe = any(p.search(haystack) for p in _WIPE_ARGS_RES)
    if not current_wipe:
        compose_pats = (
            re.compile(r"(?i)\brm\b.{0,160}?-rf\b"),
            re.compile(r"(?i)\b-rf\b.{0,160}?\brm\b"),
            re.compile(r"(?i)\b(delete|wipe|shred|truncate|drop)\b.{0,100}?\b(all|table|db|disk|factory)\b"),
            re.compile(r"(?i)(curl|wget)\b.{0,120}?\|\s*(ba)?sh\b"),
        )
        for pat in compose_pats:
            if pat.search(joined):
                return _hint(
                    lock_id="session_compose_wipe",
                    force_decision=DECISION_DENY,
                    note="Hard deny — wipe pattern composed across session tool calls",
                    threat_summary=(
                        "session rolling args compose to destructive wipe / pipe-shell"
                    ),
                )

    # Secret taint → outbound HTTP class = exfil deny
    tainted = session_is_secret_tainted(session_id)
    outbound_names = {
        "http_post",
        "http_put",
        "http_patch",
        "http_request",
        "http_fetch",
        "fetch_url",
        "web_post",
        "webhook",
        "webhook_send",
        "requests_post",
        "axios_post",
        "curl_post",
    }
    if tainted and (name in outbound_names or "http" in name or "webhook" in name):
        return _hint(
            lock_id="session_secret_exfil",
            force_decision=DECISION_DENY,
            note="Hard deny — session read secrets then outbound HTTP (exfil class)",
            threat_summary="session tainted by secret-path read; outbound blocked",
        )
    return None
