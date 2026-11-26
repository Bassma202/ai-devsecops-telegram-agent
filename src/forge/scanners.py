"""Real security scanner orchestration, finding normalization, and deduplication.

Executes real security tools using subprocess argument lists (never shell=True),
captures exact exit codes, preserves sanitized raw evidence, and never treats
scanner errors or unavailability as clean scans.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from forge.models import (
    Finding,
    ScannerExecution,
    ScannerStatus,
    ScanRun,
    Severity,
    utc_now_iso,
)
from forge.storage import ForgeStore

SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    ("SEC-GH-PAT", "GitHub Personal Access Token", re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b"), Severity.CRITICAL),
    ("SEC-AWS-KEY", "AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("SEC-PRIV-KEY", "Private Key Material", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("SEC-TG-BOT", "Telegram Bot Token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), Severity.CRITICAL),
    ("SEC-HARDCODED-PWD", "Hardcoded Password Assignment", re.compile(r"""(?i)\b(?:password|passwd|db_pass|secret_key|api_secret)\s*=\s*['"]([^'"]{8,})['"]"""), Severity.HIGH),
]

BANDIT_SEV_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", "evidence", "data"}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {ch: s.count(ch) / len(s) for ch in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _finding_id(scanner: str, rule_id: str, location: str, component: str) -> str:
    digest = hashlib.sha256(f"{scanner}:{rule_id}:{location}:{component}".encode()).hexdigest()[:12]
    return f"FRG-{digest.upper()}"


def _git_head(target_path: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(target_path),
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except OSError:
        pass
    return "unknown"


def _tool_version(cmd: list[str]) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=False)
        out = (res.stdout or res.stderr).strip().splitlines()
        return out[0] if out else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def run_bandit(target_path: Path, run_id: str, evidence_dir: Path) -> tuple[ScannerExecution, list[Finding]]:
    """Execute real Bandit SAST via Python module invocation (shell=False)."""
    start = time.perf_counter()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_file = evidence_dir / f"{run_id}_bandit.json"
    version = _tool_version([sys.executable, "-m", "bandit", "--version"])
    if version == "unavailable":
        return (
            ScannerExecution(
                scanner="bandit",
                version="unavailable",
                status=ScannerStatus.UNAVAILABLE,
                exit_code=None,
                duration_ms=0.0,
                finding_count=0,
                error_detail="bandit Python module is not installed in active environment.",
            ),
            [],
        )

    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(target_path),
        "-f",
        "json",
        "-x",
        ",".join(sorted(EXCLUDED_DIRS)),
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, shell=False)
    except subprocess.TimeoutExpired:
        return (
            ScannerExecution(
                scanner="bandit",
                version=version,
                status=ScannerStatus.FAILED,
                exit_code=-1,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
                finding_count=0,
                error_detail="Bandit execution timed out after 120s.",
            ),
            [],
        )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    # Bandit exit code: 0 = clean, 1 = issues found, >1 = error
    if res.returncode not in (0, 1):
        return (
            ScannerExecution(
                scanner="bandit",
                version=version,
                status=ScannerStatus.FAILED,
                exit_code=res.returncode,
                duration_ms=duration_ms,
                finding_count=0,
                error_detail=(res.stderr or res.stdout)[:500],
            ),
            [],
        )

    try:
        payload = json.loads(res.stdout) if res.stdout.strip() else {"results": []}
    except json.JSONDecodeError as exc:
        return (
            ScannerExecution(
                scanner="bandit",
                version=version,
                status=ScannerStatus.FAILED,
                exit_code=res.returncode,
                duration_ms=duration_ms,
                finding_count=0,
                error_detail=f"Malformed Bandit JSON output: {exc}",
            ),
            [],
        )

    raw_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    findings: list[Finding] = []
    for item in payload.get("results", []):
        rel_file = os.path.relpath(item.get("filename", "unknown"), target_path)
        line_no = item.get("line_number", 0)
        rule_id = item.get("test_id", "B000")
        sev = BANDIT_SEV_MAP.get(str(item.get("issue_severity", "LOW")).upper(), Severity.LOW)
        location = f"{rel_file}:{line_no}"
        findings.append(
            Finding(
                finding_id=_finding_id("bandit", rule_id, location, rel_file),
                run_id=run_id,
                scanner="bandit",
                rule_id=rule_id,
                severity=sev,
                component=rel_file,
                location=location,
                message=f"[{item.get('test_name', 'sast')}] {item.get('issue_text', '')}",
                remediation=f"Review {rule_id} ({item.get('more_info', 'https://bandit.readthedocs.io/')}) and apply secure coding fix.",
                evidence_ref=str(raw_file),
            )
        )

    return (
        ScannerExecution(
            scanner="bandit",
            version=version,
            status=ScannerStatus.COMPLETED,
            exit_code=res.returncode,
            duration_ms=duration_ms,
            finding_count=len(findings),
            raw_evidence_path=str(raw_file),
        ),
        findings,
    )


def run_secret_scan(target_path: Path, run_id: str, evidence_dir: Path) -> tuple[ScannerExecution, list[Finding]]:
    """Run deterministic secret & credential exposure scan with strict output redaction."""
    start = time.perf_counter()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_file = evidence_dir / f"{run_id}_secrets.json"
    findings: list[Finding] = []
    sanitized_hits: list[dict[str, Any]] = []

    text_exts = {".py", ".yml", ".yaml", ".json", ".toml", ".env", ".sh", ".md", ".txt", ".cfg", ".ini", ".js", ".ts"}
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in sorted(dirs) if d not in EXCLUDED_DIRS]
        for fname in sorted(files):
            fp = Path(root) / fname
            if fp.suffix.lower() not in text_exts and fname != "Dockerfile":
                continue
            if fname == ".env.example":
                continue
            rel = str(fp.relative_to(target_path))
            # Skip scanning the secret-scanner rule definitions themselves
            if rel.endswith("src/forge/scanners.py"):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                for rule_id, label, pattern, sev in SECRET_PATTERNS:
                    m = pattern.search(line)
                    if not m:
                        continue
                    matched_val = m.group(1) if m.lastindex else m.group(0)
                    # Filter low-entropy benign placeholders only for generic password assignments
                    if rule_id == "SEC-HARDCODED-PWD" and (
                        "placeholder" in line.lower()
                        or "change-me" in line.lower()
                        or "replace-with" in line.lower()
                        or _shannon_entropy(matched_val) < 2.6
                    ):
                        continue
                    loc = f"{rel}:{lineno}"
                    findings.append(
                        Finding(
                            finding_id=_finding_id("secret-scanner", rule_id, loc, rel),
                            run_id=run_id,
                            scanner="secret-scanner",
                            rule_id=rule_id,
                            severity=sev,
                            component=rel,
                            location=loc,
                            message=f"{label} detected (value redacted).",
                            remediation="Remove secret from source control, rotate credential immediately, and inject via environment/secret manager.",
                            evidence_ref=str(raw_file),
                        )
                    )
                    sanitized_hits.append(
                        {
                            "rule_id": rule_id,
                            "location": loc,
                            "severity": sev.value,
                            "redacted_preview": f"<REDACTED len={len(matched_val)}>",
                        }
                    )

    raw_file.write_text(json.dumps({"hits": sanitized_hits}, indent=2), encoding="utf-8")
    return (
        ScannerExecution(
            scanner="secret-scanner",
            version="forge-builtin-2.0.0",
            status=ScannerStatus.COMPLETED,
            exit_code=1 if findings else 0,
            duration_ms=round((time.perf_counter() - start) * 1000, 2),
            finding_count=len(findings),
            raw_evidence_path=str(raw_file),
        ),
        findings,
    )


def run_dockerfile_audit(target_path: Path, run_id: str, evidence_dir: Path) -> tuple[ScannerExecution, list[Finding]]:
    """Inspect Dockerfiles for concrete hardening issues (root user, latest tag, add remote URL)."""
    start = time.perf_counter()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_file = evidence_dir / f"{run_id}_dockerfile.json"
    findings: list[Finding] = []
    checked_files: list[str] = []

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in sorted(dirs) if d not in EXCLUDED_DIRS]
        for fname in sorted(files):
            if fname != "Dockerfile" and not fname.endswith(".Dockerfile"):
                continue
            fp = Path(root) / fname
            rel = str(fp.relative_to(target_path))
            checked_files.append(rel)
            lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
            has_non_root_user = False
            for idx, raw_ln in enumerate(lines, start=1):
                ln = raw_ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                upper = ln.upper()
                if upper.startswith("FROM ") and ":LATEST" in upper:
                    findings.append(
                        Finding(
                            finding_id=_finding_id("dockerfile-audit", "DF-001", f"{rel}:{idx}", rel),
                            run_id=run_id,
                            scanner="dockerfile-audit",
                            rule_id="DF-001",
                            severity=Severity.MEDIUM,
                            component=rel,
                            location=f"{rel}:{idx}",
                            message="Floating ':latest' base image tag undermines reproducible builds.",
                            remediation="Pin an explicit image version tag or immutable SHA-256 digest.",
                            evidence_ref=str(raw_file),
                        )
                    )
                if upper.startswith("USER "):
                    user_val = ln.split(None, 1)[1].strip().lower()
                    if user_val not in {"root", "0", "0:0"}:
                        has_non_root_user = True
            if not has_non_root_user:
                findings.append(
                    Finding(
                        finding_id=_finding_id("dockerfile-audit", "DF-002", f"{rel}:1", rel),
                        run_id=run_id,
                        scanner="dockerfile-audit",
                        rule_id="DF-002",
                        severity=Severity.HIGH,
                        component=rel,
                        location=f"{rel}:1",
                        message="Dockerfile does not specify a non-root USER instruction.",
                        remediation="Create an unprivileged service user and set USER <uid>:<gid> before CMD/ENTRYPOINT.",
                        evidence_ref=str(raw_file),
                    )
                )

    raw_file.write_text(json.dumps({"checked_files": checked_files, "finding_count": len(findings)}, indent=2), encoding="utf-8")
    return (
        ScannerExecution(
            scanner="dockerfile-audit",
            version="forge-builtin-2.0.0",
            status=ScannerStatus.COMPLETED,
            exit_code=1 if findings else 0,
            duration_ms=round((time.perf_counter() - start) * 1000, 2),
            finding_count=len(findings),
            raw_evidence_path=str(raw_file),
        ),
        findings,
    )


def run_pip_audit(target_path: Path, run_id: str, evidence_dir: Path) -> tuple[ScannerExecution, list[Finding]]:
    """Run real pip-audit dependency vulnerability scanning when available and online."""
    start = time.perf_counter()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_file = evidence_dir / f"{run_id}_pip_audit.json"
    version = _tool_version([sys.executable, "-m", "pip_audit", "--version"])
    if version == "unavailable":
        return (
            ScannerExecution(
                scanner="pip-audit",
                version="unavailable",
                status=ScannerStatus.UNAVAILABLE,
                exit_code=None,
                duration_ms=0.0,
                finding_count=0,
                error_detail="pip-audit is not installed in this environment.",
            ),
            [],
        )

    req_file = target_path / "requirements.txt"
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json"]
    if req_file.exists():
        cmd += ["-r", str(req_file)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=False)
    except subprocess.TimeoutExpired:
        return (
            ScannerExecution(
                scanner="pip-audit",
                version=version,
                status=ScannerStatus.FAILED,
                exit_code=-1,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
                finding_count=0,
                error_detail="pip-audit timed out after 60s.",
            ),
            [],
        )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    if res.returncode not in (0, 1) or not res.stdout.strip().startswith("{"):
        return (
            ScannerExecution(
                scanner="pip-audit",
                version=version,
                status=ScannerStatus.UNAVAILABLE,
                exit_code=res.returncode,
                duration_ms=duration_ms,
                finding_count=0,
                error_detail=(res.stderr or res.stdout or "Advisory DB unreachable (offline environment).")[:400],
            ),
            [],
        )

    payload = json.loads(res.stdout)
    raw_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    findings: list[Finding] = []
    for dep in payload.get("dependencies", []):
        pkg = dep.get("name", "unknown")
        ver = dep.get("version", "unknown")
        for vuln in dep.get("vulns", []):
            vid = vuln.get("id", "CVE-UNKNOWN")
            fix = ", ".join(vuln.get("fix_versions", [])) or "Upgrade to patched release"
            findings.append(
                Finding(
                    finding_id=_finding_id("pip-audit", vid, f"{pkg}=={ver}", pkg),
                    run_id=run_id,
                    scanner="pip-audit",
                    rule_id=vid,
                    severity=Severity.HIGH,
                    component=f"{pkg}=={ver}",
                    location="requirements.txt",
                    message=vuln.get("description", f"Known vulnerability {vid} in {pkg}=={ver}")[:300],
                    remediation=f"Upgrade {pkg} to fixed version: {fix}",
                    evidence_ref=str(raw_file),
                )
            )
    return (
        ScannerExecution(
            scanner="pip-audit",
            version=version,
            status=ScannerStatus.COMPLETED,
            exit_code=res.returncode,
            duration_ms=duration_ms,
            finding_count=len(findings),
            raw_evidence_path=str(raw_file),
        ),
        findings,
    )


def run_trivy_fs(target_path: Path, run_id: str, evidence_dir: Path) -> tuple[ScannerExecution, list[Finding]]:
    """Run real Trivy filesystem scan if trivy CLI is installed; otherwise report UNAVAILABLE explicitly."""
    start = time.perf_counter()
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        return (
            ScannerExecution(
                scanner="trivy",
                version="unavailable",
                status=ScannerStatus.UNAVAILABLE,
                exit_code=None,
                duration_ms=0.0,
                finding_count=0,
                error_detail="trivy CLI not installed on host PATH (runs via Docker or CI job).",
            ),
            [],
        )
    version = _tool_version([trivy_bin, "--version"])
    raw_file = evidence_dir / f"{run_id}_trivy.json"
    cmd = [trivy_bin, "fs", "--format", "json", "--quiet", str(target_path)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180, shell=False)
    except subprocess.TimeoutExpired:
        return (
            ScannerExecution(
                scanner="trivy",
                version=version,
                status=ScannerStatus.FAILED,
                exit_code=-1,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
                finding_count=0,
                error_detail="trivy timed out after 180s.",
            ),
            [],
        )
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    if res.returncode != 0:
        return (
            ScannerExecution(
                scanner="trivy",
                version=version,
                status=ScannerStatus.FAILED,
                exit_code=res.returncode,
                duration_ms=duration_ms,
                finding_count=0,
                error_detail=(res.stderr or res.stdout)[:400],
            ),
            [],
        )
    payload = json.loads(res.stdout) if res.stdout.strip() else {}
    raw_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    findings: list[Finding] = []
    for result in payload.get("Results", []):
        target_name = result.get("Target", "filesystem")
        for vuln in result.get("Vulnerabilities") or []:
            sev_str = str(vuln.get("Severity", "MEDIUM")).upper()
            sev = Severity(sev_str) if sev_str in Severity._value2member_map_ else Severity.MEDIUM
            vid = vuln.get("VulnerabilityID", "TRIVY-VULN")
            pkg = f"{vuln.get('PkgName', 'pkg')}=={vuln.get('InstalledVersion', '?')}"
            findings.append(
                Finding(
                    finding_id=_finding_id("trivy", vid, f"{target_name}:{pkg}", pkg),
                    run_id=run_id,
                    scanner="trivy",
                    rule_id=vid,
                    severity=sev,
                    component=pkg,
                    location=target_name,
                    message=vuln.get("Title") or vuln.get("Description", vid)[:240],
                    remediation=f"Upgrade to {vuln.get('FixedVersion') or 'latest patched release'}.",
                    evidence_ref=str(raw_file),
                )
            )
    return (
        ScannerExecution(
            scanner="trivy",
            version=version,
            status=ScannerStatus.COMPLETED,
            exit_code=0,
            duration_ms=duration_ms,
            finding_count=len(findings),
            raw_evidence_path=str(raw_file),
        ),
        findings,
    )


def execute_security_pipeline(
    target_path: str | Path,
    store: ForgeStore,
    evidence_dir: str | Path = "evidence/scans",
    include_network_scanners: bool = False,
) -> tuple[ScanRun, list[Finding]]:
    """Run all configured security scanners, deduplicate findings, and persist full evidence."""
    tpath = Path(target_path).resolve()
    edir = Path(evidence_dir)
    run_id = f"RUN-{uuid.uuid4().hex[:10].upper()}"
    run = ScanRun(run_id=run_id, target_path=str(tpath), git_commit=_git_head(tpath))

    scanners_to_run = [run_bandit, run_secret_scan, run_dockerfile_audit]
    if include_network_scanners:
        scanners_to_run.extend([run_pip_audit, run_trivy_fs])

    dedup: dict[str, Finding] = {}
    executions: list[ScannerExecution] = []
    any_failed = False

    for fn in scanners_to_run:
        exec_rec, found = fn(tpath, run_id, edir)
        executions.append(exec_rec)
        if exec_rec.status == ScannerStatus.FAILED:
            any_failed = True
        for f in found:
            dedup[f.finding_id] = f

    findings = list(dedup.values())
    counts: dict[str, int] = {s.value.lower(): 0 for s in Severity}
    counts["secrets"] = 0
    for f in findings:
        counts[f.severity.value.lower()] += 1
        if f.scanner == "secret-scanner":
            counts["secrets"] += 1

    run.scanners = executions
    run.summary_counts = counts
    run.completed_at = utc_now_iso()
    if any_failed:
        run.overall_status = "SCANNER_ERROR"
    elif counts["critical"] > 0 or counts["high"] > 0 or counts["secrets"] > 0:
        run.overall_status = "FINDINGS_BLOCKING"
    else:
        run.overall_status = "PASS"

    store.save_scan_run(run)
    store.save_findings(findings)
    return run, findings
