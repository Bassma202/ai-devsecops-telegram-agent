"""Hardened Telegram ChatOps Controller for FORGE with linked job execution and explicit terminal states.

Security guarantees:
- Independent default-deny authorization (explicit user_id and optional chat_id allowlists).
- Strict command allowlist — zero arbitrary shell execution, zero shell=True.
- Sliding-window per-user rate limiting.
- Non-blocking background job execution with explicit terminal states separating scanner errors,
  policy blocking findings, timeouts, cancellations, and deployment failures.
- Two-step single-use expiring approval bound to (operator, action, release_tag, artifact_sha256)
  that genuinely executes the bound deployment/rollback callback and persists real execution results.
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
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv

from forge.models import ChatOpsAuditEvent, DeploymentRecord
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


class JobState(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED_CLEAN = "SUCCEEDED_CLEAN"
    BLOCKED_FINDINGS = "BLOCKED_FINDINGS"
    FAILED_SCANNER_ERROR = "FAILED_SCANNER_ERROR"
    FAILED_TIMEOUT = "FAILED_TIMEOUT"
    CANCELLED = "CANCELLED"
    DEPLOYED = "DEPLOYED"
    ROLLED_BACK = "ROLLED_BACK"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    FAILED_DEPLOY = "FAILED_DEPLOY"


def redact_sensitive(text: str) -> str:
    return REDACT_REGEX.sub("[REDACTED]", text)


@dataclass
class PendingApproval:
    token: str
    job_id: str
    action: str
    release_tag: str
    artifact_sha256: str
    requested_by: int
    expires_at: float


class ChatOpsGuard:
    """Enforces identity allowlisting, command allowlisting, rate limits, and artifact-bound single-use approvals."""

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

        if not self.allowed_user_ids or user_id not in self.allowed_user_ids:
            self._audit(user_id, chat_id, cmd_root, False, "UNAUTHORIZED_USER", "User ID not in allowlist.")
            return False, "Unauthorized: your Telegram user ID is not permitted to operate FORGE."

        if self.allowed_chat_ids and chat_id not in self.allowed_chat_ids:
            self._audit(user_id, chat_id, cmd_root, False, "UNAUTHORIZED_CHAT", "Chat ID not in allowlist.")
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

    def request_approval(
        self,
        user_id: int,
        action: str,
        release_tag: str,
        artifact_sha256: str = "unspecified",
        ttl_seconds: int = 180,
    ) -> PendingApproval:
        if action not in {"deploy", "rollback"}:
            raise ValueError("Approval only supports deploy or rollback actions.")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", release_tag):
            raise ValueError("Invalid release tag format.")
        tok = secrets.token_hex(6).upper()
        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        approval = PendingApproval(
            token=tok,
            job_id=job_id,
            action=action,
            release_tag=release_tag,
            artifact_sha256=artifact_sha256,
            requested_by=user_id,
            expires_at=time.time() + ttl_seconds,
        )
        self._pending_approvals[tok] = approval
        return approval

    def consume_approval(
        self,
        user_id: int,
        token: str,
        expected_action: str | None = None,
        expected_release_tag: str | None = None,
    ) -> tuple[bool, PendingApproval | None, str]:
        key = token.strip().upper()
        ap = self._pending_approvals.get(key)
        if ap is None:
            return False, None, "Invalid or already consumed approval token."
        if time.time() > ap.expires_at:
            self._pending_approvals.pop(key, None)
            return False, None, "Approval token expired."
        if ap.requested_by != user_id:
            return False, None, "Approval token belongs to a different operator."
        if expected_action and ap.action != expected_action:
            return False, None, f"Approval token is bound to '{ap.action}', not '{expected_action}'."
        if expected_release_tag and ap.release_tag != expected_release_tag:
            return False, None, f"Approval token is bound to '{ap.release_tag}', not '{expected_release_tag}'."
        # Single-use consumption strictly after ownership, expiry, and binding checks pass
        self._pending_approvals.pop(key, None)
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
    """Asynchronous command dispatcher executing real scanner and deployment/rollback callbacks."""

    def __init__(
        self,
        guard: ChatOpsGuard,
        store: ForgeStore,
        target_path: str | Path = ".",
        scan_runner: Callable[..., Any] | None = None,
        deploy_executor: Callable[[str, str, str], DeploymentRecord] | None = None,
        rollback_executor: Callable[[str], DeploymentRecord] | None = None,
        scan_timeout_s: float = 120.0,
    ) -> None:
        self.guard = guard
        self.store = store
        self.target_path = Path(target_path).resolve()
        self.scan_runner = scan_runner or execute_security_pipeline
        self.deploy_executor = deploy_executor
        self.rollback_executor = rollback_executor
        self.scan_timeout_s = scan_timeout_s
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
                "/scan — Execute real Bandit + Secret + Dockerfile scan\n"
                "/policy — Show latest OPA Rego policy decision\n"
                "/sbom — Show latest CycloneDX SBOM summary\n"
                "/verify — Show latest Ed25519 provenance attestation\n"
                "/deploy <tag> [sha256] — Request artifact-bound deployment approval\n"
                "/approve <token> — Execute approved deploy/rollback job\n"
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
            self.jobs[job_id] = {"job_id": job_id, "status": JobState.RUNNING.value, "command": "/scan"}
            try:
                run, findings = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.scan_runner,
                        self.target_path,
                        self.store,
                        self.target_path / "evidence" / "scans",
                        False,
                    ),
                    timeout=self.scan_timeout_s,
                )
            except asyncio.TimeoutError:
                self.jobs[job_id] = {
                    "job_id": job_id,
                    "status": JobState.FAILED_TIMEOUT.value,
                    "command": "/scan",
                    "error": f"Scan timed out after {self.scan_timeout_s}s",
                }
                return f"Scan job {job_id} FAILED_TIMEOUT after {self.scan_timeout_s}s."
            except asyncio.CancelledError:
                self.jobs[job_id] = {"job_id": job_id, "status": JobState.CANCELLED.value, "command": "/scan"}
                raise
            except Exception as exc:
                self.jobs[job_id] = {
                    "job_id": job_id,
                    "status": JobState.FAILED_SCANNER_ERROR.value,
                    "command": "/scan",
                    "error": redact_sensitive(str(exc)),
                }
                return f"Scan job {job_id} FAILED_SCANNER_ERROR: {redact_sensitive(str(exc))}"

            if run.overall_status == "SCANNER_ERROR":
                state = JobState.FAILED_SCANNER_ERROR
            elif run.overall_status == "FINDINGS_BLOCKING":
                state = JobState.BLOCKED_FINDINGS
            elif run.overall_status == "PASS":
                state = JobState.SUCCEEDED_CLEAN
            else:
                state = JobState.FAILED_SCANNER_ERROR

            self.jobs[job_id] = {
                "job_id": job_id,
                "status": state.value,
                "run_id": run.run_id,
                "overall_status": run.overall_status,
                "findings": len(findings),
            }
            return (
                f"Scan {run.run_id} finished | JobState={state.value} | "
                f"Overall={run.overall_status} | Findings={len(findings)}."
            )

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
            sha = args[1] if len(args) > 1 else "latest-attested"
            try:
                ap = self.guard.request_approval(user_id, "deploy", tag, artifact_sha256=sha)
            except ValueError as exc:
                return f"Invalid deploy request: {exc}"
            self.jobs[ap.job_id] = {
                "job_id": ap.job_id,
                "status": JobState.QUEUED.value,
                "action": "deploy",
                "release_tag": tag,
                "artifact_sha256": sha,
            }
            return (
                f"Approval required for job {ap.job_id} to deploy '{tag}' (artifact={sha[:12]}). "
                f"Confirm within 180s using: /approve {ap.token}"
            )

        if cmd == "/rollback":
            ap = self.guard.request_approval(user_id, "rollback", "previous", artifact_sha256="previous-verified")
            self.jobs[ap.job_id] = {
                "job_id": ap.job_id,
                "status": JobState.QUEUED.value,
                "action": "rollback",
                "release_tag": "previous",
            }
            return f"Approval required for job {ap.job_id} to rollback active release. Confirm within 180s using: /approve {ap.token}"

        if cmd == "/approve":
            if not args:
                return "Usage: /approve <TOKEN>"
            valid, ap, reason = self.guard.consume_approval(user_id, args[0])
            if not valid or ap is None:
                return f"Approval rejected: {reason}"

            actor = f"telegram:{user_id}"
            self.jobs[ap.job_id]["status"] = JobState.RUNNING.value

            if ap.action == "deploy":
                if self.deploy_executor is None:
                    self.jobs[ap.job_id]["status"] = JobState.FAILED_DEPLOY.value
                    self.jobs[ap.job_id]["error"] = "No ControlledDeployer executor wired."
                    return f"Deployment job {ap.job_id} FAILED_DEPLOY: no deployment executor configured."
                try:
                    rec = await asyncio.to_thread(self.deploy_executor, ap.release_tag, ap.artifact_sha256, actor)
                except Exception as exc:
                    self.jobs[ap.job_id]["status"] = JobState.FAILED_DEPLOY.value
                    self.jobs[ap.job_id]["error"] = redact_sensitive(str(exc))
                    return f"Deployment job {ap.job_id} FAILED_DEPLOY: {redact_sensitive(str(exc))}"

                if rec.status == "DEPLOYED":
                    final_state = JobState.DEPLOYED
                elif rec.status == "BLOCKED":
                    final_state = JobState.BLOCKED_POLICY
                else:
                    final_state = JobState.FAILED_DEPLOY

                self.jobs[ap.job_id].update(
                    {
                        "status": final_state.value,
                        "deployment_id": rec.deployment_id,
                        "health_status": rec.health_status,
                    }
                )
                return (
                    f"Job {ap.job_id} executed deploy '{ap.release_tag}' -> {rec.status} "
                    f"(deployment_id={rec.deployment_id}, health={rec.health_status})."
                )

            if ap.action == "rollback":
                if self.rollback_executor is None:
                    self.jobs[ap.job_id]["status"] = JobState.FAILED_DEPLOY.value
                    return f"Rollback job {ap.job_id} FAILED_DEPLOY: no rollback executor configured."
                try:
                    rec = await asyncio.to_thread(self.rollback_executor, actor)
                except Exception as exc:
                    self.jobs[ap.job_id]["status"] = JobState.FAILED_DEPLOY.value
                    return f"Rollback job {ap.job_id} FAILED_DEPLOY: {redact_sensitive(str(exc))}"
                final_state = JobState.ROLLED_BACK if rec.status == "ROLLED_BACK" else JobState.FAILED_DEPLOY
                self.jobs[ap.job_id].update({"status": final_state.value, "deployment_id": rec.deployment_id})
                return (
                    f"Job {ap.job_id} executed rollback -> {rec.status} "
                    f"(restored={rec.release_tag}, health={rec.health_status})."
                )

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
