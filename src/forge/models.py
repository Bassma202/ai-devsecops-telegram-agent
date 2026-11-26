"""Unified domain models for FORGE supply-chain security & DevSecOps platform."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerStatus(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


class FindingStatus(str, Enum):
    DETECTED = "DETECTED"
    REVIEWED = "REVIEWED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    REMEDIATED = "REMEDIATED"
    VERIFIED = "VERIFIED"
    EXEMPTED = "EXEMPTED"


class Finding(BaseModel):
    finding_id: str
    run_id: str
    scanner: str
    rule_id: str
    severity: Severity
    component: str
    location: str
    message: str
    remediation: str
    evidence_ref: str = ""
    detected_at: str = Field(default_factory=utc_now_iso)
    status: FindingStatus = FindingStatus.DETECTED
    exception_reason: str | None = None
    reassessment_note: str | None = None


class ScannerExecution(BaseModel):
    scanner: str
    version: str
    status: ScannerStatus
    exit_code: int | None
    duration_ms: float
    finding_count: int
    raw_evidence_path: str | None = None
    error_detail: str | None = None


class ScanRun(BaseModel):
    run_id: str
    target_path: str
    git_commit: str
    started_at: str = Field(default_factory=utc_now_iso)
    completed_at: str | None = None
    overall_status: str = "RUNNING"
    scanners: list[ScannerExecution] = Field(default_factory=list)
    summary_counts: dict[str, int] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    decision_id: str
    run_id: str | None = None
    evaluated_at: str = Field(default_factory=utc_now_iso)
    engine: str
    policy_path: str
    allowed: bool
    violations: list[str] = Field(default_factory=list)
    approved_exceptions: list[str] = Field(default_factory=list)
    input_snapshot: dict[str, Any] = Field(default_factory=dict)


class SBOMRecord(BaseModel):
    sbom_id: str
    spec_version: str
    tool_name: str
    tool_version: str
    generated_at: str = Field(default_factory=utc_now_iso)
    artifact_name: str
    artifact_sha256: str
    component_count: int
    file_path: str
    schema_valid: bool


class AttestationRecord(BaseModel):
    attestation_id: str
    artifact_path: str
    artifact_sha256: str
    git_commit: str
    algorithm: str = "Ed25519"
    public_key_fingerprint: str
    signature_b64: str
    signed_at: str = Field(default_factory=utc_now_iso)
    verified: bool = False
    verification_detail: str = ""


class DeploymentRecord(BaseModel):
    deployment_id: str
    release_tag: str
    artifact_sha256: str
    policy_decision_id: str
    sbom_id: str
    attestation_id: str
    status: str  # DEPLOYED | BLOCKED | ROLLED_BACK | FAILED
    health_status: str
    deployed_at: str = Field(default_factory=utc_now_iso)
    actor: str
    notes: str = ""


class ChatOpsAuditEvent(BaseModel):
    event_id: str
    timestamp: str = Field(default_factory=utc_now_iso)
    user_id: int
    chat_id: int
    command: str
    authorized: bool
    outcome: str
    detail: str = ""
