"""SQLite persistence layer for FORGE scan runs, findings, policies, SBOMs, attestations, and deployments."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.models import (
    AttestationRecord,
    ChatOpsAuditEvent,
    DeploymentRecord,
    Finding,
    FindingStatus,
    PolicyDecision,
    SBOMRecord,
    ScanRun,
)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    git_commit TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    overall_status TEXT NOT NULL,
    scanners_json TEXT NOT NULL,
    summary_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    component TEXT NOT NULL,
    location TEXT NOT NULL,
    message TEXT NOT NULL,
    remediation TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    status TEXT NOT NULL,
    exception_reason TEXT,
    reassessment_note TEXT
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id TEXT PRIMARY KEY,
    run_id TEXT,
    evaluated_at TEXT NOT NULL,
    engine TEXT NOT NULL,
    policy_path TEXT NOT NULL,
    allowed INTEGER NOT NULL,
    violations_json TEXT NOT NULL,
    exceptions_json TEXT NOT NULL,
    input_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sbom_records (
    sbom_id TEXT PRIMARY KEY,
    spec_version TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    artifact_name TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    component_count INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    schema_valid INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attestations (
    attestation_id TEXT PRIMARY KEY,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    git_commit TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    signed_at TEXT NOT NULL,
    verified INTEGER NOT NULL,
    verification_detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deployments (
    deployment_id TEXT PRIMARY KEY,
    release_tag TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    policy_decision_id TEXT NOT NULL,
    sbom_id TEXT NOT NULL,
    attestation_id TEXT NOT NULL,
    status TEXT NOT NULL,
    health_status TEXT NOT NULL,
    deployed_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    notes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chatops_audit (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    chat_id INTEGER NOT NULL,
    command TEXT NOT NULL,
    authorized INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


class ForgeStore:
    def __init__(self, db_path: str | Path = "data/forge.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def save_scan_run(self, run: ScanRun) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_runs
                (run_id, target_path, git_commit, started_at, completed_at, overall_status, scanners_json, summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run.run_id,
                    run.target_path,
                    run.git_commit,
                    run.started_at,
                    run.completed_at,
                    run.overall_status,
                    json.dumps([s.model_dump() for s in run.scanners]),
                    json.dumps(run.summary_counts),
                ),
            )

    def list_scan_runs(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["scanners"] = json.loads(d.pop("scanners_json"))
            d["summary_counts"] = json.loads(d.pop("summary_json"))
            out.append(d)
        return out

    def save_findings(self, findings: list[Finding]) -> None:
        with self._connect() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO findings
                (finding_id, run_id, scanner, rule_id, severity, component, location, message, remediation,
                 evidence_ref, detected_at, status, exception_reason, reassessment_note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        f.finding_id,
                        f.run_id,
                        f.scanner,
                        f.rule_id,
                        f.severity.value,
                        f.component,
                        f.location,
                        f.message,
                        f.remediation,
                        f.evidence_ref,
                        f.detected_at,
                        f.status.value,
                        f.exception_reason,
                        f.reassessment_note,
                    )
                    for f in findings
                ],
            )

    def list_findings(self, run_id: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        query += " ORDER BY detected_at DESC"
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def update_finding_status(
        self,
        finding_id: str,
        status: FindingStatus,
        note: str | None = None,
        exception_reason: str | None = None,
    ) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE findings
                SET status = ?, reassessment_note = COALESCE(?, reassessment_note),
                    exception_reason = COALESCE(?, exception_reason)
                WHERE finding_id = ?""",
                (status.value, note, exception_reason, finding_id),
            )
            return cur.rowcount > 0

    def save_policy_decision(self, decision: PolicyDecision) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO policy_decisions
                (decision_id, run_id, evaluated_at, engine, policy_path, allowed, violations_json, exceptions_json, input_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision.decision_id,
                    decision.run_id,
                    decision.evaluated_at,
                    decision.engine,
                    decision.policy_path,
                    1 if decision.allowed else 0,
                    json.dumps(decision.violations),
                    json.dumps(decision.approved_exceptions),
                    json.dumps(decision.input_snapshot),
                ),
            )

    def list_policy_decisions(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM policy_decisions ORDER BY evaluated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["allowed"] = bool(d["allowed"])
            d["violations"] = json.loads(d.pop("violations_json"))
            d["approved_exceptions"] = json.loads(d.pop("exceptions_json"))
            d["input_snapshot"] = json.loads(d.pop("input_json"))
            out.append(d)
        return out

    def save_sbom(self, sbom: SBOMRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO sbom_records
                (sbom_id, spec_version, tool_name, tool_version, generated_at, artifact_name,
                 artifact_sha256, component_count, file_path, schema_valid)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sbom.sbom_id,
                    sbom.spec_version,
                    sbom.tool_name,
                    sbom.tool_version,
                    sbom.generated_at,
                    sbom.artifact_name,
                    sbom.artifact_sha256,
                    sbom.component_count,
                    sbom.file_path,
                    1 if sbom.schema_valid else 0,
                ),
            )

    def list_sboms(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sbom_records ORDER BY generated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{**dict(r), "schema_valid": bool(r["schema_valid"])} for r in rows]

    def save_attestation(self, att: AttestationRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO attestations
                (attestation_id, artifact_path, artifact_sha256, git_commit, algorithm,
                 public_key_fingerprint, signature_b64, signed_at, verified, verification_detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    att.attestation_id,
                    att.artifact_path,
                    att.artifact_sha256,
                    att.git_commit,
                    att.algorithm,
                    att.public_key_fingerprint,
                    att.signature_b64,
                    att.signed_at,
                    1 if att.verified else 0,
                    att.verification_detail,
                ),
            )

    def list_attestations(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM attestations ORDER BY signed_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{**dict(r), "verified": bool(r["verified"])} for r in rows]

    def save_deployment(self, dep: DeploymentRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO deployments
                (deployment_id, release_tag, artifact_sha256, policy_decision_id, sbom_id,
                 attestation_id, status, health_status, deployed_at, actor, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    dep.deployment_id,
                    dep.release_tag,
                    dep.artifact_sha256,
                    dep.policy_decision_id,
                    dep.sbom_id,
                    dep.attestation_id,
                    dep.status,
                    dep.health_status,
                    dep.deployed_at,
                    dep.actor,
                    dep.notes,
                ),
            )

    def list_deployments(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM deployments ORDER BY deployed_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def log_chatops(self, event: ChatOpsAuditEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO chatops_audit
                (event_id, timestamp, user_id, chat_id, command, authorized, outcome, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.timestamp,
                    event.user_id,
                    event.chat_id,
                    event.command,
                    1 if event.authorized else 0,
                    event.outcome,
                    event.detail,
                ),
            )

    def list_chatops(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM chatops_audit ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{**dict(r), "authorized": bool(r["authorized"])} for r in rows]
