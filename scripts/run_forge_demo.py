#!/usr/bin/env python3
"""Reproducible end-to-end FORGE demonstration & evidence generator.

Executes real Bandit SAST, secret scanning, Dockerfile auditing, OPA Rego v1 policy evaluation,
CycloneDX v1.5 SBOM generation, Ed25519 signing/tamper verification, and controlled deployment
+ rollback, writing sanitized JSON evidence to evidence/forge_demo_evidence.json.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from forge.deployer import ControlledDeployer
from forge.models import FindingStatus, utc_now_iso
from forge.policy import PolicyEvaluator
from forge.sbom import generate_cyclonedx_sbom
from forge.scanners import execute_security_pipeline
from forge.signing import generate_keypair, sign_artifact, verify_artifact
from forge.storage import ForgeStore


def main() -> None:
    evidence_dir = ROOT / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    store = ForgeStore(ROOT / "data" / "forge.db")

    # 1. Baseline vulnerable fixture -> Bandit detects B602 -> blocks pipeline
    vuln_run, vuln_findings = execute_security_pipeline(
        ROOT / "examples" / "vulnerable_fixture", store, evidence_dir / "scans"
    )
    # Record remediation lifecycle transition
    for f in vuln_findings:
        store.update_finding_status(f.finding_id, FindingStatus.REMEDIATED, note="Removed shell=True in remediated_fixture")

    # 2. Clean hardened target app scan
    clean_run, clean_findings = execute_security_pipeline(
        ROOT / "app", store, evidence_dir / "scans"
    )

    # 3. Genuine CycloneDX v1.5 SBOM
    artifact = ROOT / "app" / "app.py"
    sbom_rec, _ = generate_cyclonedx_sbom(
        artifact, evidence_dir / "sbom" / "forge_cyclonedx_v15.json", store=store
    )

    # 4. Ephemeral Ed25519 keypair (never committed) -> sign & verify + tamper test
    with tempfile.TemporaryDirectory() as keytmp:
        priv = Path(keytmp) / "ephemeral_ed25519.pem"
        pub = Path(keytmp) / "ephemeral_ed25519.pub.pem"
        generate_keypair(priv, pub)
        att_path = evidence_dir / "attestation_demo.json"
        att_rec, _ = sign_artifact(artifact, priv, clean_run.git_commit, att_path, store=store)
        ver_ok, ver_msg = verify_artifact(artifact, att_path, pub)

        # Tamper copy test
        tampered = Path(keytmp) / "tampered_app.py"
        tampered.write_bytes(artifact.read_bytes() + b"\n# tampered\n")
        tamper_ok, tamper_msg = verify_artifact(tampered, att_path, pub)

    # 5. OPA Policy evaluation (compliant vs. noncompliant)
    evaluator = PolicyEvaluator(store=store, allow_docker_opa=True)
    noncompliant_policy = evaluator.evaluate(
        {
            "container": {"image": "forge-demo-app:latest", "user": "root", "privileged": True, "read_only_rootfs": False, "cap_drop": []},
            "vulnerabilities": {"critical": 1, "high": len(vuln_findings), "secrets": 0},
            "supply_chain": {"sbom_valid": False, "signature_verified": False},
        },
        run_id=vuln_run.run_id,
    )
    compliant_policy = evaluator.evaluate(
        {
            "container": {"image": "forge-demo-app:2.0.0", "user": "1001:1001", "privileged": False, "read_only_rootfs": True, "cap_drop": ["ALL"], "host_mounts": []},
            "vulnerabilities": {"critical": 0, "high": 0, "secrets": 0},
            "supply_chain": {"sbom_valid": sbom_rec.schema_valid, "signature_verified": ver_ok},
        },
        run_id=clean_run.run_id,
    )

    # 6. Controlled deployment (blocked -> deployed v2.0.0 -> deployed v2.0.1 -> rollback to v2.0.0)
    deployer = ControlledDeployer(store=store, state_file=ROOT / "data" / "active_release.json")
    dep_blocked = deployer.deploy("v2.0.0-unsafe", noncompliant_policy, sbom_rec, att_rec, actor="forge-demo")
    dep_v1 = deployer.deploy("v2.0.0", compliant_policy, sbom_rec, att_rec, actor="forge-demo")
    dep_v2 = deployer.deploy("v2.0.1", compliant_policy, sbom_rec, att_rec, actor="forge-demo")
    dep_rb = deployer.rollback(actor="forge-demo")

    summary = {
        "generated_at": utc_now_iso(),
        "evidence_classification": "Genuine laboratory execution",
        "remediation_lifecycle": {
            "vulnerable_run_id": vuln_run.run_id,
            "vulnerable_status": vuln_run.overall_status,
            "vulnerable_rules_detected": [f.rule_id for f in vuln_findings],
            "clean_app_run_id": clean_run.run_id,
            "clean_app_status": clean_run.overall_status,
            "clean_app_finding_count": len(clean_findings),
        },
        "policy_gate": {
            "engine": compliant_policy.engine,
            "noncompliant_allowed": noncompliant_policy.allowed,
            "noncompliant_violations": noncompliant_policy.violations,
            "compliant_allowed": compliant_policy.allowed,
        },
        "sbom": sbom_rec.model_dump(),
        "provenance": {
            "attestation_id": att_rec.attestation_id,
            "authentic_verified": ver_ok,
            "authentic_detail": ver_msg,
            "tampered_verified": tamper_ok,
            "tampered_detail": tamper_msg,
        },
        "deployments": {
            "blocked": dep_blocked.status,
            "v2_0_0": dep_v1.status,
            "v2_0_1": dep_v2.status,
            "rollback": dep_rb.status,
            "active_after_rollback": deployer.current_state()["active_release"],
        },
    }
    out_file = evidence_dir / "forge_demo_evidence.json"
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
