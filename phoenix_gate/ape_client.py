"""Minimal HTTP client for Osmantic APE (stdlib urllib).

Contract (ODS ape service):
  POST /verify  {tool_name, args, session_id?} →
      {allowed, reason, intent, decision_id, decision?, approval_token?, grant_consumed?}
  POST /approve {approval_token, approver?} →
      {granted, reason, tool_name?, intent?}
  GET  /health  → {status, ...}
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional


class ApeError(Exception):
    """Base APE client error."""


class ApeTimeoutError(ApeError):
    """Request exceeded timeout."""


class ApeConnectionError(ApeError):
    """Could not reach APE."""


class ApeHTTPError(ApeError):
    """APE returned a non-2xx status."""

    def __init__(self, status: int, body: str, message: str | None = None):
        self.status = status
        self.body = body
        super().__init__(message or f"APE HTTP {status}: {body[:200]}")


@dataclass(frozen=True)
class VerifyResult:
    allowed: bool
    reason: str
    intent: str
    decision_id: str
    decision: str  # allow | deny | require_approval
    approval_token: Optional[str] = None
    grant_consumed: bool = False
    raw: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class ApproveResult:
    granted: bool
    reason: str
    tool_name: Optional[str] = None
    intent: Optional[str] = None
    raw: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    status: str
    raw: Optional[Mapping[str, Any]] = None


def _normalize_decision(payload: Mapping[str, Any]) -> str:
    """Derive APE decision tier from response (legacy clients may omit it).

    Pass 10: strip + casefold so ``deny `` / ``DENY`` / ``Allow`` parse;
    non-empty garbage decision → **deny** fail-closed (do not fall through to
    ``allowed`` bool, which a confused wire may set true alongside ``deny ``).
    """
    decision = payload.get("decision")
    if isinstance(decision, str):
        d = decision.strip().lower()
        if d in ("allow", "deny", "require_approval"):
            return d
        if d:
            return "deny"
    elif decision is not None:
        # Non-string decision present → fail closed
        return "deny"
    if payload.get("approval_token"):
        return "require_approval"
    return "allow" if payload.get("allowed") else "deny"


def _normalize_grant_consumed(payload: Mapping[str, Any]) -> bool:
    """Structured grant flag only — never sniff reason text (injection-safe).

    Pass 10: do **not** use bare ``bool(v)`` — ``bool("false")`` is True in
    Python and would skip phoenix allow→ask_human escalate (Founder bypass).
    Only JSON bool true, int 1, or explicit truthy strings count as consumed.
    """
    if "grant_consumed" not in payload:
        return False
    v = payload.get("grant_consumed")
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v == 1
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return False


class ApeClient:
    """Thin urllib client for APE /health, /verify, /approve."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:7890",
        *,
        timeout: float = 5.0,
        api_key: Optional[str] = None,
        user_agent: str = "phoenix-hermes-ape-adapter/0.1",
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_key = api_key
        self.user_agent = user_agent

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers=self._headers(), method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8") or "{}"
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 — best-effort body
                err_body = str(exc)
            raise ApeHTTPError(exc.code, err_body) from exc
        except socket.timeout as exc:
            raise ApeTimeoutError(f"APE timeout after {self.timeout}s: {url}") from exc
        except TimeoutError as exc:
            raise ApeTimeoutError(f"APE timeout after {self.timeout}s: {url}") from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, socket.timeout):
                raise ApeTimeoutError(
                    f"APE timeout after {self.timeout}s: {url}"
                ) from exc
            raise ApeConnectionError(f"APE unreachable at {url}: {reason}") from exc
        except json.JSONDecodeError as exc:
            raise ApeError(f"APE returned non-JSON from {url}") from exc

    def health(self) -> HealthResult:
        payload = self._request("GET", "/health")
        status = str(payload.get("status", "unknown"))
        return HealthResult(ok=status.lower() in ("ok", "healthy", "up"), status=status, raw=payload)

    def verify(
        self,
        tool_name: str,
        args: Optional[Mapping[str, Any]] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> VerifyResult:
        body: dict[str, Any] = {
            "tool_name": tool_name,
            "args": dict(args or {}),
        }
        if session_id is not None:
            body["session_id"] = session_id
        if agent_id is not None:
            body["agent_id"] = agent_id
        payload = self._request("POST", "/verify", body)
        decision = _normalize_decision(payload)
        return VerifyResult(
            allowed=bool(payload.get("allowed")),
            reason=str(payload.get("reason", "")),
            intent=str(payload.get("intent", "unknown")),
            decision_id=str(payload.get("decision_id", "")),
            decision=decision,
            approval_token=payload.get("approval_token"),
            grant_consumed=_normalize_grant_consumed(payload),
            raw=payload,
        )

    def approve(
        self,
        approval_token: str,
        approver: Optional[str] = None,
    ) -> ApproveResult:
        body: dict[str, Any] = {"approval_token": approval_token}
        if approver is not None:
            body["approver"] = approver
        payload = self._request("POST", "/approve", body)
        return ApproveResult(
            granted=bool(payload.get("granted")),
            reason=str(payload.get("reason", "")),
            tool_name=payload.get("tool_name"),
            intent=payload.get("intent"),
            raw=payload,
        )
