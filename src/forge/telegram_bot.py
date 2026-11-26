"""Hardened Telegram ChatOps Controller for FORGE.

Security guarantees:
- Independent default-deny authorization (explicit user_id and optional chat_id allowlists).
- Strict command allowlist — zero arbitrary shell execution, zero shell=True.
- Sliding-window per-user rate limiting.
- Non-blocking background job execution via asyncio.to_thread with explicit job states.
- Two-step cryptographic approval nonce required before /deploy or /rollback.
- Automatic credential redaction on all log outputs.
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from forge.models import ChatOpsAuditEvent
from forge.scanners import execute_security_pipeline
from forge.storage import ForgeStore

ALLOWED_COMMANDS = {
    "/help",
    "/status",
    "/scan",
    "/policy",
    "/sbom",
    "/verify",
    "/deploy",
    "/approve",
    "/rollback",
    "/logs",
}

REDACT_REGEX = re.compile(
    r"(ghp_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{15,}|\d{8,10}:[A-Za-z0-9_-]{25,}|"
    r"(?i:(?:token|password|secret|api_key)\s*[=:]\s*\S+))"
)


def redact_sensitive(text: str) -> str:
    return REDACT_REGEX.sub("[REDACTED]", text)


@dataclass
class PendingApproval:
    token: str
    action: str
    release_tag: str
    requested_by: int
    expires_at: float


class ChatOpsGuard:
    """Enforces identity allowlisting, command allowlisting, rate limits, and two-step approvals."""

    def __init__(
        self,
        allowed_user_ids: set[int],
        allowed_chat_ids: set[int] | None = None,
        max_requests_per_minute: int = 12,
        store: ForgeStore | None = None,
    ) -> None:
        self.allowed_user_ids = allowed_user_ids
        self.allowed_chat_ids = allowed_chat_ids or set()
        self.max_requests_per_minute = max_requests_per_minute
        self.store = store
        self._buckets: dict[int, deque[float]] = defaultdict(deque)
        self._pending_approvals: dict[str, PendingApproval] = {}

    def authorize(self, user_id: int, chat_id: int, command: str) -> tuple[bool, str]:
        cmd_root = command.strip().split()[0].lower() if command.strip() else ""
        if cmd_root not in ALLOWED_COMMANDS:
            self._audit(user_id, chat_id, cmd_root or "<empty>", False, "REJECTED_COMMAND", "Command not in allowlist.")
            return False, "Command rejected: not in allowed command list."

        # Default-deny when allowlist is empty
        if not self.allowed_user_ids or user_id not in self.allowed_user_ids:
            self._audit(user_id, chat_id, cmd_root, False, "UNAUTHORIZED_USER", "User ID not in FORGE_ALLOWED_TELEGRAM_USER_IDS.")
            return False, "Unauthorized: your Telegram user ID is not permitted to operate FORGE."

        if self.allowed_chat_ids and chat_id not in self.allowed_chat_ids:
            self._audit(user_id, chat_id, cmd_root, False, "UNAUTHORIZED_CHAT", "Chat ID not in FORGE_ALLOWED_TELEGRAM_CHAT_IDS.")
            return False, "Unauthorized chat context."

        now = time.monotonic()
        q = self._buckets[user_id]
        while q and now - q[0] > 60.0:
            q.popleft()
        if len(q) >= self.max_requests_per_minute:
            self._audit(user_id, chat_id, cmd_root, False, "RATE_LIMITED", "Exceeded per-minute command quota.")
            return False, "Rate limit exceeded. Please wait before issuing another command."
        q.append(now)

        self._audit(user_id, chat_id, cmd_root, True, "AUTHORIZED", "Access granted.")
        return True, "OK"

    def request_approval(self, user_id: int, action: str, release_tag: str, ttl_seconds: int = 180) -> PendingApproval:
        if action not in {"deploy", "rollback"}:
            raise ValueError("Approval only supports deploy or rollback actions.")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", release_tag):
            raise ValueError("Invalid release tag format.")
        tok = secrets.token_hex(6).upper()
        approval = PendingApproval(
            token=tok,
            action=action,
            release_tag=release_tag,
            requested_by=user_id,
            expires_at=time.time() + ttl_seconds,
        )
        self._pending_approvals[tok] = approval
        return approval

    def consume_approval(self, user_id: int, token: str) -> tuple[bool, PendingApproval | None, str]:
        ap = self._pending_approvals.pop(token.strip().upper(), None)
        if ap is None:
            return False, None, "Invalid or already consumed approval token."
        if time.time() > ap.expires_at:
            return False, None, "Approval token expired."
        if ap.requested_by != user_id:
            return False, None, "Approval token belongs to a different operator."
        return True, ap, "Approval verified."

    def _audit(self, user_id: int, chat_id: int, command: str, authorized: bool, outcome: str, detail: str) -> None:
        if self.store:
            self.store.log_chatops(
                ChatOpsAuditEvent(
                    event_id=f"EVT-{uuid.uuid4().hex[:10].upper()}",
                    user_id=user_id,
                    chat_id=chat_id,
                    command=command,
                    authorized=authorized,
                    outcome=outcome,
                    detail=redact_sensitive(detail),
                )
            )


class ForgeChatOpsService:
    """Asynchronous command dispatcher suitable for both Telegram runtime and automated tests."""

    def __init__(self, guard: ChatOpsGuard, store: ForgeStore, target_path: str | Path = ".") -> None:
        self.guard = guard
        self.store = store
        self.target_path = Path(target_path).resolve()
        self.jobs: dict[str, dict[str, Any]] = {}

    async def handle_command(self, user_id: int, chat_id: int, raw_text: str) -> str:
        ok, msg = self.guard.authorize(user_id, chat_id, raw_text)
        if not ok:
            return msg

        parts = raw_text.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "/help":
            return (
                "FORGE DevSecOps ChatOps Commands:\n"
                "/status — Show latest scan, policy, and active release\n"
                "/scan — Queue real Bandit + Secret + Dockerfile scan\n"
                "/policy — Show latest OPA Rego policy decision\n"
                "/sbom — Show latest CycloneDX SBOM summary\n"
                "/verify — Show latest Ed25519 provenance attestation\n"
                "/deploy <tag> — Request two-step deployment approval\n"
                "/approve <token> — Confirm approved deploy/rollback\n"
                "/rollback — Request controlled rollback approval\n"
                "/logs — Show redacted recent audit events"
            )

        if cmd == "/status":
            runs = self.store.list_scan_runs(limit=1)
            deps = self.store.list_deployments(limit=1)
            run_info = f"{runs[0]['run_id']} ({runs[0]['overall_status']})" if runs else "none"
            dep_info = f"{deps[0]['release_tag']} ({deps[0]['status']})" if deps else "none"
            return f"FORGE Status | Latest Scan: {run_info} | Latest Deployment: {dep_info} | Jobs tracked: {len(self.jobs)}"

        if cmd == "/scan":
            job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
            self.jobs[job_id] = {"status": "RUNNING", "command": "/scan"}
            run, findings = await asyncio.to_thread(
                execute_security_pipeline, self.target_path, self.store, self.target_path / "evidence" / "scans", False
            )
            self.jobs[job_id] = {"status": "SUCCEEDED", "run_id": run.run_id, "findings": len(findings)}
            return f"Scan {run.run_id} completed ({run.overall_status}). Total findings: {len(findings)}."

        if cmd == "/policy":
            decs = self.store.list_policy_decisions(limit=1)
            if not decs:
                return "No policy evaluations recorded yet."
            d = decs[0]
            return f"Policy {d['decision_id']} ({d['engine']}): {'ALLOWED' if d['allowed'] else 'DENIED'} | Violations: {len(d['violations'])}"

        if cmd == "/sbom":
            sboms = self.store.list_sboms(limit=1)
            if not sboms:
                return "No SBOM generated yet."
            s = sboms[0]
            return f"SBOM {s['sbom_id']} (CycloneDX {s['spec_version']}): {s['component_count']} components | Valid: {s['schema_valid']}"

        if cmd == "/verify":
            atts = self.store.list_attestations(limit=1)
            if not atts:
                return "No attestations recorded yet."
            a = atts[0]
            return f"Attestation {a['attestation_id']} ({a['algorithm']}): Verified={a['verified']} | {a['verification_detail']}"

        if cmd == "/deploy":
            tag = args[0] if args else "v2.0.0"
            try:
                ap = self.guard.request_approval(user_id, "deploy", tag)
            except ValueError as exc:
                return f"Invalid deploy request: {exc}"
            return f"Approval required to deploy '{tag}'. Confirm within 180s using: /approve {ap.token}"

        if cmd == "/rollback":
            ap = self.guard.request_approval(user_id, "rollback", "previous")
            return f"Approval required to rollback active release. Confirm within 180s using: /approve {ap.token}"

        if cmd == "/approve":
            if not args:
                return "Usage: /approve <TOKEN>"
            valid, ap, reason = self.guard.consume_approval(user_id, args[0])
            if not valid or ap is None:
                return f"Approval rejected: {reason}"
            return f"Confirmed {ap.action} for '{ap.release_tag}'. Gate enforcement applies via ControlledDeployer."

        if cmd == "/logs":
            events = self.store.list_chatops(limit=5)
            lines = [f"{e['timestamp'][:19]} user={e['user_id']} {e['command']} -> {e['outcome']}" for e in events]
            return redact_sensitive("\n".join(lines) or "No audit events recorded.")

        return "Unhandled command."


def _parse_int_set(raw: str | None) -> set[int]:
    if not raw:
        return set()
    return {int(x.strip()) for x in raw.split(",") if x.strip().lstrip("-").isdigit()}


def run_telegram_bot() -> None:
    """Start live Telegram bot polling using environment variables (never hardcoded secrets)."""
    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set. Configure .env securely before starting.")
    allowed_users = _parse_int_set(os.getenv("FORGE_ALLOWED_TELEGRAM_USER_IDS"))
    if not allowed_users:
        raise RuntimeError("FORGE_ALLOWED_TELEGRAM_USER_IDS must be configured (default-deny policy).")
    allowed_chats = _parse_int_set(os.getenv("FORGE_ALLOWED_TELEGRAM_CHAT_IDS"))

    from telegram import Update
    from telegram.ext import Application, CommandHandler, ContextTypes

    store = ForgeStore(os.getenv("FORGE_DB_PATH", "data/forge.db"))
    guard = ChatOpsGuard(allowed_user_ids=allowed_users, allowed_chat_ids=allowed_chats, store=store)
    service = ForgeChatOpsService(guard=guard, store=store, target_path=".")

    async def _dispatch(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not update.effective_user or not update.effective_chat or not update.message:
            return
        reply = await service.handle_command(
            user_id=update.effective_user.id,
            chat_id=update.effective_chat.id,
            raw_text=update.message.text or "",
        )
        await update.message.reply_text(reply)

    app = Application.builder().token(token).build()
    for cmd_name in [c.lstrip("/") for c in sorted(ALLOWED_COMMANDS)]:
        app.add_handler(CommandHandler(cmd_name, _dispatch))
    app.run_polling()
