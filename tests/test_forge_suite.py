"""Comprehensive FORGE test suite: real scanners, remediation lifecycle, OPA policy, SBOM, Ed25519 signing, ChatOps guard, deployment/rollback, and FastAPI web UI."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forge.deployer import ControlledDeployer
from forge.models import FindingStatus
from forge.policy import PolicyEvaluator
from forge.sbom import generate_cyclonedx_sbom, validate_sbom_document
from forge.scanners import execute_security_pipeline, run_bandit, run_dockerfile_audit, run_secret_scan
from forge.signing import generate_keypair, sign_artifact, verify_artifact
from forge.storage import ForgeStore
from forge.telegram_bot import ChatOpsGuard, ForgeChatOpsService, redact_sensitive
from forge.web import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_real_bandit_remediation_lifecycle(tmp_path: Path) -> None:
    """Verify real Bandit catches B602 in vulnerable fixture and clears on remediated fixture."""
    ev_dir = tmp_path / "evidence"
    exec_bad, findings_bad = run_bandit(REPO_ROOT / "examples" / "vulnerable_fixture", "RUN-BAD", ev_dir)
    assert exec_bad.status.value == "COMPLETED"
    assert exec_bad.exit_code == 1
    assert any(f.rule_id == "B602" for f in findings_bad)

    exec_ok, findings_ok = run_bandit(REPO_ROOT / "examples" / "remediated_fixture", "RUN-OK", ev_dir)
    assert exec_ok.status.value == "COMPLETED"
    assert exec_ok.exit_code == 0
    assert len(findings_ok) == 0


def test_secret_scanner_detects_and_redacts(tmp_path: Path) -> None:
    sample = tmp_path / "leaked.py"
    # Synthetic non-working token fixture matching AWS key format
    sample.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    exec_rec, findings = run_secret_scan(tmp_path, "RUN-SEC", tmp_path / "ev")
    assert exec_rec.status.value == "COMPLETED"
    assert any(f.rule_id == "SEC-AWS-KEY" for f in findings)
    raw = (tmp_path / "ev" / "RUN-SEC_secrets.json").read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in raw
    assert "<REDACTED" in raw


def test_dockerfile_audit_passes_hardened_app_and_catches_root(tmp_path: Path) -> None:
    exec_ok, findings_ok = run_dockerfile_audit(REPO_ROOT / "app", "RUN-DF-OK", tmp_path / "ev")
    assert exec_ok.status.value == "COMPLETED"
    assert len(findings_ok) == 0

    bad_dir = tmp_path / "bad_docker"
    bad_dir.mkdir()
    (bad_dir / "Dockerfile").write_text("FROM python:latest\nCMD ['python']\n", encoding="utf-8")
    _, findings_bad = run_dockerfile_audit(bad_dir, "RUN-DF-BAD", tmp_path / "ev")
    rules = {f.rule_id for f in findings_bad}
    assert "DF-001" in rules and "DF-002" in rules


def test_policy_evaluator_enforces_hardening_and_exceptions(tmp_path: Path) -> None:
    store = ForgeStore(tmp_path / "forge.db")
    evaluator = PolicyEvaluator(store=store)
    compliant = {
        "container": {
            "image": "forge-demo-app:2.0.0",
            "user": "1001:1001",
            "privileged": False,
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "host_mounts": [],
        },
        "vulnerabilities": {"critical": 0, "high": 0, "secrets": 0},
        "supply_chain": {"sbom_valid": True, "signature_verified": True},
        "approved_exceptions": [],
    }
    dec_ok = evaluator.evaluate(compliant)
    assert dec_ok.allowed is True
    assert dec_ok.violations == []

    bad = {
        **compliant,
        "container": {**compliant["container"], "user": "root", "host_mounts": ["/var/run/docker.sock"]},
        "vulnerabilities": {"critical": 2, "high": 0, "secrets": 1},
    }
    dec_bad = evaluator.evaluate(bad)
    assert dec_bad.allowed is False
    assert len(dec_bad.violations) >= 4


def test_cyclonedx_sbom_real_generation_and_validation(tmp_path: Path) -> None:
    store = ForgeStore(tmp_path / "forge.db")
    artifact = REPO_ROOT / "app" / "app.py"
    rec, doc = generate_cyclonedx_sbom(artifact, tmp_path / "sbom.json", store=store)
    assert rec.schema_valid is True
    assert rec.component_count >= 10
    assert validate_sbom_document(doc) is True
    assert doc["bomFormat"] == "CycloneDX"


def test_ed25519_signing_verification_and_tamper_rejection(tmp_path: Path) -> None:
    store = ForgeStore(tmp_path / "forge.db")
    artifact = tmp_path / "release.tar"
    artifact.write_bytes(b"forge-verified-release-payload-v2.0.0")
    priv = tmp_path / "keys" / "forge_ed25519.pem"
    pub = tmp_path / "keys" / "forge_ed25519.pub.pem"
    generate_keypair(priv, pub)

    env_path = tmp_path / "release.att.json"
    att, _ = sign_artifact(artifact, priv, "abc1234", env_path, store=store)
    assert att.verified is True

    ok, msg = verify_artifact(artifact, env_path, pub)
    assert ok is True and "VERIFIED" in msg

    # Tamper 1 byte -> verification must fail
    artifact.write_bytes(b"forge-verified-release-payload-v2.0.1")
    ok_tampered, msg_tampered = verify_artifact(artifact, env_path, pub)
    assert ok_tampered is False and "DIGEST_MISMATCH" in msg_tampered

    # Untrusted public key -> verification must fail
    other_priv = tmp_path / "keys" / "other.pem"
    other_pub = tmp_path / "keys" / "other.pub.pem"
    generate_keypair(other_priv, other_pub)
    artifact.write_bytes(b"forge-verified-release-payload-v2.0.0")
    ok_key, msg_key = verify_artifact(artifact, env_path, other_pub)
    assert ok_key is False and "SIGNATURE_INVALID" in msg_key


def test_controlled_deployment_gate_and_rollback(tmp_path: Path) -> None:
    store = ForgeStore(tmp_path / "forge.db")
    evaluator = PolicyEvaluator(store=store)
    artifact = tmp_path / "app.whl"
    artifact.write_bytes(b"release-v1")
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    sbom, _ = generate_cyclonedx_sbom(artifact, tmp_path / "sbom.json", store=store)
    att, _ = sign_artifact(artifact, priv, "commit1", tmp_path / "att.json", store=store)

    deployer = ControlledDeployer(store=store, state_file=tmp_path / "active.json")

    # 1. Noncompliant build must be blocked
    denied_pol = evaluator.evaluate(
        {
            "container": {"image": "demo:latest", "user": "root", "privileged": True, "read_only_rootfs": False, "cap_drop": []},
            "vulnerabilities": {"critical": 1, "high": 0, "secrets": 0},
            "supply_chain": {"sbom_valid": True, "signature_verified": True},
        }
    )
    dep_blocked = deployer.deploy("v1.0.0-bad", denied_pol, sbom, att, actor="ci")
    assert dep_blocked.status == "BLOCKED"
    assert deployer.current_state()["active_release"] is None

    # 2. Compliant v1 & v2 deploy, then rollback to v1
    ok_pol = evaluator.evaluate(
        {
            "container": {"image": "demo:2.0.0", "user": "1001:1001", "privileged": False, "read_only_rootfs": True, "cap_drop": ["ALL"]},
            "vulnerabilities": {"critical": 0, "high": 0, "secrets": 0},
            "supply_chain": {"sbom_valid": True, "signature_verified": True},
        }
    )
    d1 = deployer.deploy("v2.0.0", ok_pol, sbom, att, actor="operator:101")
    assert d1.status == "DEPLOYED"
    d2 = deployer.deploy("v2.0.1", ok_pol, sbom, att, actor="operator:101")
    assert d2.status == "DEPLOYED"
    assert deployer.current_state()["active_release"] == "v2.0.1"

    rb = deployer.rollback(actor="operator:101")
    assert rb.status == "ROLLED_BACK"
    assert deployer.current_state()["active_release"] == "v2.0.0"


def test_telegram_chatops_authorization_rate_limit_and_two_step_approval(tmp_path: Path) -> None:
    store = ForgeStore(tmp_path / "forge.db")
    guard = ChatOpsGuard(allowed_user_ids={1001}, allowed_chat_ids={9001}, max_requests_per_minute=4, store=store)
    svc = ForgeChatOpsService(guard=guard, store=store, target_path=REPO_ROOT / "app")

    # Unauthorized user blocked
    resp_unauth = asyncio.run(svc.handle_command(user_id=9999, chat_id=9001, raw_text="/status"))
    assert "Unauthorized" in resp_unauth

    # Command injection / non-allowlisted command blocked
    resp_bad_cmd = asyncio.run(svc.handle_command(user_id=1001, chat_id=9001, raw_text="/exec rm -rf /"))
    assert "rejected" in resp_bad_cmd.lower()

    # Two-step approval workflow
    resp_dep = asyncio.run(svc.handle_command(user_id=1001, chat_id=9001, raw_text="/deploy v2.0.0"))
    assert "/approve " in resp_dep
    token = resp_dep.split("/approve ")[1].strip()
    resp_app = asyncio.run(svc.handle_command(user_id=1001, chat_id=9001, raw_text=f"/approve {token}"))
    assert "Confirmed deploy" in resp_app

    # Redaction check
    assert "[REDACTED]" in redact_sensitive("error with password=SuperSecret12345")


def test_fastapi_dashboard_and_remediation_api(tmp_path: Path) -> None:
    db = tmp_path / "forge.db"
    store = ForgeStore(db)
    run, findings = execute_security_pipeline(REPO_ROOT / "examples" / "vulnerable_fixture", store, tmp_path / "ev")
    assert run.overall_status == "FINDINGS_BLOCKING"
    assert len(findings) >= 1

    client = TestClient(create_app(db_path=db, repo_root=REPO_ROOT / "app"))
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "healthy"

    r_html = client.get("/")
    assert r_html.status_code == 200
    assert "FORGE — Secure Software Supply Chain" in r_html.text

    fid = findings[0].finding_id
    r_patch = client.patch(f"/api/findings/{fid}", json={"status": FindingStatus.VERIFIED.value, "note": "Replaced shell=True"})
    assert r_patch.status_code == 200
    assert r_patch.json()["status"] == "VERIFIED"
