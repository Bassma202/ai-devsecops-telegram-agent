"""Comprehensive FORGE test suite & remediation regression tests (FORGE-01 through FORGE-05)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forge.deployer import ControlledDeployer, http_health_probe, write_verifiable_release_service
from forge.models import FindingStatus, ScanRun
from forge.policy import PolicyEvaluator
from forge.sbom import generate_cyclonedx_sbom, validate_sbom_document
from forge.scanners import execute_security_pipeline, run_bandit, run_dockerfile_audit, run_secret_scan
from forge.signing import generate_keypair, sign_artifact, verify_artifact
from forge.storage import ForgeStore
from forge.telegram_bot import ChatOpsGuard, ForgeChatOpsService, JobState, redact_sensitive
from forge.web import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_real_bandit_remediation_lifecycle(tmp_path: Path) -> None:
    """FORGE-03: Verify real Bandit catches B602 in vulnerable fixture and clears on remediated fixture."""
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

    artifact.write_bytes(b"forge-verified-release-payload-v2.0.1")
    ok_tampered, msg_tampered = verify_artifact(artifact, env_path, pub)
    assert ok_tampered is False and "DIGEST_MISMATCH" in msg_tampered

    other_priv = tmp_path / "keys" / "other.pem"
    other_pub = tmp_path / "keys" / "other.pub.pem"
    generate_keypair(other_priv, other_pub)
    artifact.write_bytes(b"forge-verified-release-payload-v2.0.0")
    ok_key, msg_key = verify_artifact(artifact, env_path, other_pub)
    assert ok_key is False and "SIGNATURE_INVALID" in msg_key


def test_forge01_health_probe_fails_closed_on_missing_and_invalid_endpoints() -> None:
    """FORGE-01: Default HTTP readiness probe must never unconditionally succeed."""
    ok_bad_url, msg_bad, _ = http_health_probe("https://untrusted.example/health", retries=1)
    assert ok_bad_url is False and "Invalid loopback" in msg_bad

    # Unreachable closed local port -> must fail closed
    ok_closed, msg_closed, _ = http_health_probe("http://127.0.0.1:19991/health", timeout_s=0.3, retries=2, retry_delay_s=0.05)
    assert ok_closed is False and "Readiness probe failed" in msg_closed


def test_forge02_real_runtime_deployment_failure_and_rollback(tmp_path: Path) -> None:
    """FORGE-02 & FORGE-03: Genuine runtime HTTP deployment of distinct versions, failed deploy retention, and real rollback."""
    store = ForgeStore(tmp_path / "forge.db")
    evaluator = PolicyEvaluator(store=store)

    art_v1 = write_verifiable_release_service(tmp_path / "rel_v1.py", "v2.0.0", healthy=True)
    art_v2 = write_verifiable_release_service(tmp_path / "rel_v2.py", "v2.1.0", healthy=True)
    art_bad = write_verifiable_release_service(tmp_path / "rel_bad.py", "v2.2.0-broken", healthy=False)

    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    sbom_v1, _ = generate_cyclonedx_sbom(art_v1, tmp_path / "sbom_v1.json", store=store)
    sbom_v2, _ = generate_cyclonedx_sbom(art_v2, tmp_path / "sbom_v2.json", store=store)
    att_v1, _ = sign_artifact(art_v1, priv, "commit1", tmp_path / "att_v1.json", store=store)
    att_v2, _ = sign_artifact(art_v2, priv, "commit2", tmp_path / "att_v2.json", store=store)
    att_bad, _ = sign_artifact(art_bad, priv, "commit3", tmp_path / "att_bad.json", store=store)
    assert att_v1.artifact_sha256 != att_v2.artifact_sha256

    denied_pol = evaluator.evaluate(
        {
            "container": {"image": "demo:latest", "user": "root", "privileged": True, "read_only_rootfs": False, "cap_drop": []},
            "vulnerabilities": {"critical": 1, "high": 0, "secrets": 0},
            "supply_chain": {"sbom_valid": True, "signature_verified": True},
        }
    )
    ok_pol = evaluator.evaluate(
        {
            "container": {"image": "demo:2.1.0", "user": "1001:1001", "privileged": False, "read_only_rootfs": True, "cap_drop": ["ALL"]},
            "vulnerabilities": {"critical": 0, "high": 0, "secrets": 0},
            "supply_chain": {"sbom_valid": True, "signature_verified": True},
        }
    )

    deployer = ControlledDeployer(store=store, state_file=tmp_path / "active.json")
    try:
        # 1. Policy violation blocks deployment
        dep_blocked = deployer.deploy("v1.0.0-bad", denied_pol, sbom_v1, att_v1, actor="ci", artifact_path=art_v1)
        assert dep_blocked.status == "BLOCKED"
        assert deployer.query_running_version() is None

        # 2. Deploy v2.0.0 -> verify live running HTTP identity
        d1 = deployer.deploy("v2.0.0", ok_pol, sbom_v1, att_v1, actor="operator:101", artifact_path=art_v1)
        assert d1.status == "DEPLOYED"
        live1 = deployer.query_running_version()
        assert live1 is not None and live1["version"] == "v2.0.0" and live1["artifact_sha256"] == att_v1.artifact_sha256

        # 3. Deploy distinct v2.1.0 -> verify live running HTTP identity changed
        d2 = deployer.deploy("v2.1.0", ok_pol, sbom_v2, att_v2, actor="operator:101", artifact_path=art_v2)
        assert d2.status == "DEPLOYED"
        live2 = deployer.query_running_version()
        assert live2 is not None and live2["version"] == "v2.1.0" and live2["artifact_sha256"] == att_v2.artifact_sha256

        # 4. Controlled failed deployment (HTTP 503) -> must fail and leave v2.1.0 running
        dfail = deployer.deploy("v2.2.0-broken", ok_pol, sbom_v2, att_bad, actor="operator:101", artifact_path=art_bad)
        assert dfail.status == "FAILED"
        live_after_fail = deployer.query_running_version()
        assert live_after_fail is not None and live_after_fail["version"] == "v2.1.0"

        # 5. Real rollback -> must restore running HTTP v2.0.0 and verify exact digest
        rb = deployer.rollback(actor="operator:101")
        assert rb.status == "ROLLED_BACK"
        live_rb = deployer.query_running_version()
        assert live_rb is not None and live_rb["version"] == "v2.0.0" and live_rb["artifact_sha256"] == att_v1.artifact_sha256
    finally:
        deployer.stop_runtime()


def test_forge04_and_forge05_telegram_linked_execution_and_scanner_error_states(tmp_path: Path) -> None:
    """FORGE-04 & FORGE-05: Approvals must bind/expire/execute real jobs; scanner errors must never report SUCCEEDED."""
    store = ForgeStore(tmp_path / "forge.db")
    evaluator = PolicyEvaluator(store=store)
    art_v1 = write_verifiable_release_service(tmp_path / "tg_v1.py", "v2.0.0", healthy=True)
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    sbom, _ = generate_cyclonedx_sbom(art_v1, tmp_path / "sbom.json", store=store)
    att, _ = sign_artifact(art_v1, priv, "c1", tmp_path / "att.json", store=store)
    ok_pol = evaluator.evaluate(
        {
            "container": {"image": "demo:2.0.0", "user": "1001:1001", "privileged": False, "read_only_rootfs": True, "cap_drop": ["ALL"]},
            "vulnerabilities": {"critical": 0, "high": 0, "secrets": 0},
            "supply_chain": {"sbom_valid": True, "signature_verified": True},
        }
    )

    deployer = ControlledDeployer(store=store, state_file=tmp_path / "tg_active.json")
    try:
        guard = ChatOpsGuard(allowed_user_ids={1001, 1002}, allowed_chat_ids={9001}, max_requests_per_minute=20, store=store)
        svc = ForgeChatOpsService(
            guard=guard,
            store=store,
            target_path=REPO_ROOT / "app",
            deploy_executor=lambda tag, sha, actor: deployer.deploy(tag, ok_pol, sbom, att, actor=actor, artifact_path=art_v1),
            rollback_executor=lambda actor: deployer.rollback(actor=actor),
        )

        # Unauthorized user & invalid command blocked
        assert "Unauthorized" in asyncio.run(svc.handle_command(9999, 9001, "/status"))
        assert "rejected" in asyncio.run(svc.handle_command(1001, 9001, "/exec rm -rf /")).lower()

        # Approval ownership & single-use enforcement
        dep_msg = asyncio.run(svc.handle_command(1001, 9001, f"/deploy v2.0.0 {att.artifact_sha256}"))
        token = dep_msg.split("/approve ")[1].strip()
        # Different authorized operator CANNOT steal another operator's approval
        wrong_op = asyncio.run(svc.handle_command(1002, 9001, f"/approve {token}"))
        assert "different operator" in wrong_op.lower()

        # Original operator approves -> actually deploys live local HTTP service!
        app_msg = asyncio.run(svc.handle_command(1001, 9001, f"/approve {token}"))
        assert "DEPLOYED" in app_msg
        live = deployer.query_running_version()
        assert live is not None and live["version"] == "v2.0.0"

        # Reuse of same token rejected
        reuse = asyncio.run(svc.handle_command(1001, 9001, f"/approve {token}"))
        assert "rejected" in reuse.lower()

        # Expired approval rejected
        ap_exp = guard.request_approval(1001, "deploy", "v2.0.1", ttl_seconds=0)
        time.sleep(0.02)
        ok_exp, _, exp_reason = guard.consume_approval(1001, ap_exp.token)
        assert ok_exp is False and "expired" in exp_reason.lower()

        # FORGE-05: Scanner error must report FAILED_SCANNER_ERROR, never SUCCEEDED
        def _failing_scanner(*_args, **_kwargs):
            return ScanRun(run_id="RUN-ERR", target_path=".", git_commit="abc", overall_status="SCANNER_ERROR"), []

        svc_err = ForgeChatOpsService(guard=guard, store=store, target_path=REPO_ROOT / "app", scan_runner=_failing_scanner)
        err_reply = asyncio.run(svc_err.handle_command(1001, 9001, "/scan"))
        assert JobState.FAILED_SCANNER_ERROR.value in err_reply
        assert list(svc_err.jobs.values())[-1]["status"] == JobState.FAILED_SCANNER_ERROR.value

        # Timeout handling
        def _slow_scanner(*_args, **_kwargs):
            time.sleep(0.5)
            return ScanRun(run_id="RUN-SLOW", target_path=".", git_commit="abc", overall_status="PASS"), []

        svc_to = ForgeChatOpsService(
            guard=guard, store=store, target_path=REPO_ROOT / "app", scan_runner=_slow_scanner, scan_timeout_s=0.05
        )
        to_reply = asyncio.run(svc_to.handle_command(1001, 9001, "/scan"))
        assert JobState.FAILED_TIMEOUT.value in to_reply

        # Unexpected exception handling
        def _crash_scanner(*_args, **_kwargs):
            raise RuntimeError("bandit binary crashed with password=SecretValue999")

        svc_crash = ForgeChatOpsService(guard=guard, store=store, target_path=REPO_ROOT / "app", scan_runner=_crash_scanner)
        crash_reply = asyncio.run(svc_crash.handle_command(1001, 9001, "/scan"))
        assert JobState.FAILED_SCANNER_ERROR.value in crash_reply
        assert "SecretValue999" not in crash_reply

        assert "[REDACTED]" in redact_sensitive("error with password=SuperSecret12345")
    finally:
        deployer.stop_runtime()


def test_fastapi_dashboard_and_remediation_api(tmp_path: Path) -> None:
    db = tmp_path / "forge.db"
    store = ForgeStore(db)
    run, findings = execute_security_pipeline(REPO_ROOT / "examples" / "vulnerable_fixture", store, tmp_path / "ev")
    assert run.overall_status == "FINDINGS_BLOCKING"
    assert len(findings) >= 1

    client = TestClient(create_app(db_path=db, repo_root=REPO_ROOT / "app"))
    assert client.get("/api/health").status_code == 200
    assert "FORGE — Secure Software Supply Chain" in client.get("/").text

    fid = findings[0].finding_id
    r_patch = client.patch(f"/api/findings/{fid}", json={"status": FindingStatus.VERIFIED.value, "note": "Replaced shell=True"})
    assert r_patch.status_code == 200
    assert r_patch.json()["status"] == "VERIFIED"


@pytest.mark.parametrize("bad_tag", ["../escape", "v1;rm -rf /", ""])
def test_invalid_release_tags_rejected(bad_tag: str, tmp_path: Path) -> None:
    guard = ChatOpsGuard(allowed_user_ids={1001})
    with pytest.raises(ValueError):
        guard.request_approval(1001, "deploy", bad_tag)
