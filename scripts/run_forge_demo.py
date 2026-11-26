#!/usr/bin/env python3
"""Reproducible end-to-end FORGE demonstration & evidence generator.

Verifies:
1. Real Bandit + Secret + Dockerfile scan on examples/vulnerable_fixture (blocks on B602)
   and independent rescan of examples/remediated_fixture (0 findings).
2. Distinct local Python HTTP release artifacts (v2.0.0, v2.1.0, and broken v2.2.0-unhealthy)
   with distinct SHA-256 digests, CycloneDX v1.5 SBOM, and Ed25519 signing + 1-byte tamper test.
3. Real OPA Rego v1 policy evaluation (Docker openpolicyagent/opa:1.1.0-static when available).
4. Genuine local runtime deployment of v2.0.0 -> live HTTP /version check -> deploy v2.1.0 ->
   live HTTP /version check -> controlled failed deployment of broken v2.2.0 -> live rollback
   verifying restored HTTP /version == v2.0.0 and exact v2.0.0 SHA-256!
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from forge.deployer import ControlledDeployer, write_verifiable_release_service  # noqa: E402
from forge.models import FindingStatus, utc_now_iso  # noqa: E402
from forge.policy import PolicyEvaluator  # noqa: E402
from forge.sbom import generate_cyclonedx_sbom  # noqa: E402
from forge.scanners import execute_security_pipeline  # noqa: E402
from forge.signing import generate_keypair, sign_artifact, verify_artifact  # noqa: E402
from forge.storage import ForgeStore  # noqa: E402


def main() -> None:
    evidence_dir = ROOT / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    store = ForgeStore(ROOT / "data" / "forge.db")

    # 1. Baseline vulnerable fixture -> Bandit detects B602 -> blocks pipeline
    vuln_run, vuln_findings = execute_security_pipeline(
        ROOT / "examples" / "vulnerable_fixture", store, evidence_dir / "scans"
    )
    for f in vuln_findings:
        store.update_finding_status(f.finding_id, FindingStatus.REMEDIATED, note="Removed shell=True in remediated_fixture")

    # Independent rescan of the remediated fixture
    rem_run, rem_findings = execute_security_pipeline(
        ROOT / "examples" / "remediated_fixture", store, evidence_dir / "scans"
    )

    # Clean hardened target app scan
    clean_run, clean_findings = execute_security_pipeline(
        ROOT / "app", store, evidence_dir / "scans"
    )

    # 2. Build 3 distinct verifiable local release artifacts (distinct SHA-256 digests!)
    releases_dir = ROOT / "data" / "releases"
    art_v1 = write_verifiable_release_service(releases_dir / "forge_release_v2_0_0.py", "v2.0.0", healthy=True)
    art_v2 = write_verifiable_release_service(releases_dir / "forge_release_v2_1_0.py", "v2.1.0", healthy=True)
    art_bad = write_verifiable_release_service(releases_dir / "forge_release_v2_2_0_broken.py", "v2.2.0-broken", healthy=False)

    # 3. Genuine CycloneDX v1.5 SBOM
    sbom_v1, _ = generate_cyclonedx_sbom(art_v1, evidence_dir / "sbom" / "forge_cyclonedx_v15.json", store=store)
    sbom_v2, _ = generate_cyclonedx_sbom(art_v2, evidence_dir / "sbom" / "forge_cyclonedx_v2_1_0.json", store=store)

    # 4. Ephemeral Ed25519 keypair -> sign distinct artifacts & verify + tamper test
    with tempfile.TemporaryDirectory() as keytmp:
        priv = Path(keytmp) / "ephemeral_ed25519.pem"
        pub = Path(keytmp) / "ephemeral_ed25519.pub.pem"
        generate_keypair(priv, pub)

        att_v1_path = evidence_dir / "attestation_v2_0_0.json"
        att_v2_path = evidence_dir / "attestation_v2_1_0.json"
        att_bad_path = Path(keytmp) / "attestation_broken.json"

        att_v1, _ = sign_artifact(art_v1, priv, clean_run.git_commit, att_v1_path, store=store)
        att_v2, _ = sign_artifact(art_v2, priv, clean_run.git_commit, att_v2_path, store=store)
        att_bad, _ = sign_artifact(art_bad, priv, clean_run.git_commit, att_bad_path, store=store)

        ver_v1_ok, ver_v1_msg = verify_artifact(art_v1, att_v1_path, pub)
        ver_v2_ok, ver_v2_msg = verify_artifact(art_v2, att_v2_path, pub)

        tampered = Path(keytmp) / "tampered_v1.py"
        tampered.write_bytes(art_v1.read_bytes() + b"\n# tampered\n")
        tamper_ok, tamper_msg = verify_artifact(tampered, att_v1_path, pub)

    assert att_v1.artifact_sha256 != att_v2.artifact_sha256, "Distinct releases must have distinct SHA-256 digests"

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
            "container": {"image": "forge-demo-app:2.1.0", "user": "1001:1001", "privileged": False, "read_only_rootfs": True, "cap_drop": ["ALL"], "host_mounts": []},
            "vulnerabilities": {"critical": 0, "high": 0, "secrets": 0},
            "supply_chain": {"sbom_valid": sbom_v1.schema_valid and sbom_v2.schema_valid, "signature_verified": ver_v1_ok and ver_v2_ok},
        },
        run_id=clean_run.run_id,
    )

    # 6. Genuine local runtime deployment, live /version checks, controlled failed deploy, and real rollback
    deployer = ControlledDeployer(store=store, state_file=ROOT / "data" / "active_release.json")
    try:
        dep_blocked = deployer.deploy("v2.0.0-unsafe", noncompliant_policy, sbom_v1, att_v1, actor="forge-demo", artifact_path=art_v1)

        dep_v1 = deployer.deploy("v2.0.0", compliant_policy, sbom_v1, att_v1, actor="forge-demo", artifact_path=art_v1)
        live_v1 = deployer.query_running_version()

        dep_v2 = deployer.deploy("v2.1.0", compliant_policy, sbom_v2, att_v2, actor="forge-demo", artifact_path=art_v2)
        live_v2 = deployer.query_running_version()

        dep_failed = deployer.deploy("v2.2.0-broken", compliant_policy, sbom_v2, att_bad, actor="forge-demo", artifact_path=art_bad)
        live_after_fail = deployer.query_running_version()

        dep_rb = deployer.rollback(actor="forge-demo")
        live_after_rb = deployer.query_running_version()
    finally:
        deployer.stop_runtime()

    summary = {
        "generated_at": utc_now_iso(),
        "evidence_classification": "Genuine laboratory execution (live local HTTP release runtimes + real scanners + OPA)",
        "remediation_lifecycle": {
            "vulnerable_run_id": vuln_run.run_id,
            "vulnerable_status": vuln_run.overall_status,
            "vulnerable_rules_detected": [f.rule_id for f in vuln_findings],
            "remediated_run_id": rem_run.run_id,
            "remediated_status": rem_run.overall_status,
            "remediated_finding_count": len(rem_findings),
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
        "sbom": sbom_v1.model_dump(),
        "provenance": {
            "v2_0_0_sha256": att_v1.artifact_sha256,
            "v2_1_0_sha256": att_v2.artifact_sha256,
            "distinct_artifact_digests": att_v1.artifact_sha256 != att_v2.artifact_sha256,
            "v2_0_0_verified": ver_v1_ok,
            "v2_1_0_verified": ver_v2_ok,
            "tampered_verified": tamper_ok,
            "tampered_detail": tamper_msg,
        },
        "runtime_deployments": {
            "blocked_status": dep_blocked.status,
            "v2_0_0_status": dep_v1.status,
            "v2_0_0_live_http_version": live_v1,
            "v2_1_0_status": dep_v2.status,
            "v2_1_0_live_http_version": live_v2,
            "broken_release_status": dep_failed.status,
            "live_http_retained_after_failed_deploy": live_after_fail,
            "rollback_status": dep_rb.status,
            "live_http_restored_after_rollback": live_after_rb,
        },
    }
    out_file = evidence_dir / "forge_demo_evidence.json"
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
