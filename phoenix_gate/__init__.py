"""Phoenix Gate Kit — thin policy gate (offline APE-shaped demo loop).

Named locks · allow / deny / ask_human · receipts. Not a full Hermes integration.
"""

__version__ = "0.1.9"

from .gateway import (
    GateResult,
    GrantMismatchError,
    ReceiptIntegrityError,
    approve_gate_token,
    assert_grant_matches,
    call_fingerprint,
    gate_tool_call,
    load_receipts_verified,
    require_agent_id_enabled,
    peek_pending_approval,
    reset_local_approvals,
    supply_env_warnings,
    verify_receipt_chain,
)
from .phoenix_locks import (
    LockHint,
    classify_lock,
    flatten_args_for_scan,
    insecure_policy_env_warnings,
    normalize_tool_name,
    reset_policy_env_seal,
    reset_session_memory,
    sanitize_echo_field,
    sanitize_threat_summary,
    detect_persuasion,
    session_is_secret_tainted,
    strict_mode_enabled,
)

__all__ = [
    "GateResult",
    "GrantMismatchError",
    "LockHint",
    "ReceiptIntegrityError",
    "approve_gate_token",
    "assert_grant_matches",
    "call_fingerprint",
    "classify_lock",
    "require_agent_id_enabled",
    "flatten_args_for_scan",
    "gate_tool_call",
    "insecure_policy_env_warnings",
    "load_receipts_verified",
    "normalize_tool_name",
    "peek_pending_approval",
    "reset_local_approvals",
    "reset_policy_env_seal",
    "reset_session_memory",
    "sanitize_echo_field",
    "sanitize_threat_summary",
    "detect_persuasion",
    "session_is_secret_tainted",
    "strict_mode_enabled",
    "supply_env_warnings",
    "verify_receipt_chain",
    "__version__",
]
