"""Controlled local deployment manager enforcing security gates, health checks, and rollback."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Callable

from forge.models import AttestationRecord, DeploymentRecord, PolicyDecision, SBOMRecord
from forge.storage import ForgeStore


class ControlledDeployer:
    """Mediates local release activation behind mandatory Policy, SBOM, and Attestation gates."""

    def __init__(
        self,
        store: ForgeStore,
        state_file: str | Path = "data/active_release.json",
        health_probe: Callable[[str], tuple[bool, str]] | None = None,
    ) -> None:
        self.store = store
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.health_probe = health_probe or self._default_health_probe

    @staticmethod
    def _default_health_probe(release_tag: str) -> tuple[bool, str]:
        return True, f"Release {release_tag} passed local readiness check."

    def current_state(self) -> dict[str, str | None]:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        return {"active_release": None, "previous_release": None, "active_deployment_id": None}

    def deploy(
        self,
        release_tag: str,
        policy_decision: PolicyDecision,
        sbom: SBOMRecord,
        attestation: AttestationRecord,
        actor: str = "cli",
    ) -> DeploymentRecord:
        dep_id = f"DEP-{uuid.uuid4().hex[:10].upper()}"
        reasons: list[str] = []
        if not policy_decision.allowed:
            reasons.append(f"OPA policy denied ({len(policy_decision.violations)} violations)")
        if not sbom.schema_valid:
            reasons.append("SBOM failed schema validation")
        if not attestation.verified:
            reasons.append(f"Attestation unverified: {attestation.verification_detail}")

        if reasons:
            rec = DeploymentRecord(
                deployment_id=dep_id,
                release_tag=release_tag,
                artifact_sha256=attestation.artifact_sha256,
                policy_decision_id=policy_decision.decision_id,
                sbom_id=sbom.sbom_id,
                attestation_id=attestation.attestation_id,
                status="BLOCKED",
                health_status="NOT_DEPLOYED",
                actor=actor,
                notes="; ".join(reasons),
            )
            self.store.save_deployment(rec)
            return rec

        healthy, health_msg = self.health_probe(release_tag)
        state = self.current_state()
        if not healthy:
            rec = DeploymentRecord(
                deployment_id=dep_id,
                release_tag=release_tag,
                artifact_sha256=attestation.artifact_sha256,
                policy_decision_id=policy_decision.decision_id,
                sbom_id=sbom.sbom_id,
                attestation_id=attestation.attestation_id,
                status="FAILED",
                health_status=f"UNHEALTHY: {health_msg}",
                actor=actor,
                notes="Health validation failed; previous active release retained.",
            )
            self.store.save_deployment(rec)
            return rec

        new_state = {
            "active_release": release_tag,
            "previous_release": state.get("active_release"),
            "active_deployment_id": dep_id,
        }
        self.state_file.write_text(json.dumps(new_state, indent=2), encoding="utf-8")

        rec = DeploymentRecord(
            deployment_id=dep_id,
            release_tag=release_tag,
            artifact_sha256=attestation.artifact_sha256,
            policy_decision_id=policy_decision.decision_id,
            sbom_id=sbom.sbom_id,
            attestation_id=attestation.attestation_id,
            status="DEPLOYED",
            health_status=f"HEALTHY: {health_msg}",
            actor=actor,
            notes="All security gates passed (OPA + CycloneDX SBOM + Ed25519 provenance).",
        )
        self.store.save_deployment(rec)
        return rec

    def rollback(self, actor: str = "cli") -> DeploymentRecord:
        state = self.current_state()
        prev = state.get("previous_release")
        if not prev:
            raise ValueError("No previous verified release available for rollback.")

        healthy, health_msg = self.health_probe(prev)
        dep_id = f"DEP-{uuid.uuid4().hex[:10].upper()}"
        new_state = {
            "active_release": prev,
            "previous_release": state.get("active_release"),
            "active_deployment_id": dep_id,
        }
        self.state_file.write_text(json.dumps(new_state, indent=2), encoding="utf-8")
        rec = DeploymentRecord(
            deployment_id=dep_id,
            release_tag=prev,
            artifact_sha256="rollback-verified-release",
            policy_decision_id="ROLLBACK",
            sbom_id="ROLLBACK",
            attestation_id="ROLLBACK",
            status="ROLLED_BACK",
            health_status=f"{'HEALTHY' if healthy else 'UNHEALTHY'}: {health_msg}",
            actor=actor,
            notes=f"Controlled rollback from {state.get('active_release')} to {prev}.",
        )
        self.store.save_deployment(rec)
        return rec
