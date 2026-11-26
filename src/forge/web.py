"""FORGE Operations Web Interface & REST API (FastAPI).

Displays live persisted SQLite records: security scan runs, normalized findings & remediation
lifecycle, OPA policy decisions, CycloneDX SBOMs, Ed25519 provenance attestations,
controlled deployments/rollbacks, and ChatOps audit logs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from forge.models import FindingStatus
from forge.scanners import execute_security_pipeline
from forge.storage import ForgeStore


class RemediationUpdate(BaseModel):
    status: FindingStatus
    note: str | None = None
    exception_reason: str | None = None


def create_app(db_path: str | Path | None = None, repo_root: str | Path | None = None) -> FastAPI:
    store = ForgeStore(db_path or os.getenv("FORGE_DB_PATH", "data/forge.db"))
    root = Path(repo_root or ".").resolve()

    app = FastAPI(
        title="FORGE — Secure Software Supply Chain & DevSecOps Engineering",
        version="2.0.0",
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "healthy", "service": "forge-devsecops", "version": "2.0.0"}

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        runs = store.list_scan_runs(limit=10)
        findings = store.list_findings()
        policies = store.list_policy_decisions(limit=10)
        sboms = store.list_sboms(limit=10)
        attestations = store.list_attestations(limit=10)
        deployments = store.list_deployments(limit=10)
        chatops = store.list_chatops(limit=15)
        return {
            "counts": {
                "scan_runs": len(runs),
                "findings": len(findings),
                "policy_decisions": len(policies),
                "sboms": len(sboms),
                "attestations": len(attestations),
                "deployments": len(deployments),
                "chatops_events": len(chatops),
            },
            "latest_run": runs[0] if runs else None,
            "latest_policy": policies[0] if policies else None,
            "latest_sbom": sboms[0] if sboms else None,
            "latest_attestation": attestations[0] if attestations else None,
            "latest_deployment": deployments[0] if deployments else None,
            "findings": findings[:50],
            "deployments": deployments,
            "chatops": chatops,
        }

    @app.post("/api/scans")
    def trigger_scan() -> dict[str, Any]:
        run, findings = execute_security_pipeline(root, store, evidence_dir=root / "evidence" / "scans")
        return {"run": run.model_dump(), "finding_count": len(findings)}

    @app.patch("/api/findings/{finding_id}")
    def update_finding(finding_id: str, body: RemediationUpdate) -> dict[str, Any]:
        updated = store.update_finding_status(
            finding_id=finding_id,
            status=body.status,
            note=body.note,
            exception_reason=body.exception_reason,
        )
        if not updated:
            raise HTTPException(status_code=404, detail="Finding not found.")
        return {"finding_id": finding_id, "status": body.status.value}

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        data = overview()
        c = data["counts"]
        latest_dep = data["latest_deployment"] or {}
        latest_pol = data["latest_policy"] or {}
        latest_sbom = data["latest_sbom"] or {}
        latest_att = data["latest_attestation"] or {}

        finding_rows = "".join(
            f"<tr><td><code>{f['finding_id']}</code></td><td>{f['scanner']}</td><td>{f['rule_id']}</td>"
            f"<td><span class='badge sev-{f['severity'].lower()}'>{f['severity']}</span></td>"
            f"<td>{f['location']}</td><td>{f['status']}</td></tr>"
            for f in data["findings"][:15]
        ) or "<tr><td colspan='6' class='muted'>No security findings currently recorded.</td></tr>"

        dep_rows = "".join(
            f"<tr><td><code>{d['deployment_id']}</code></td><td>{d['release_tag']}</td>"
            f"<td><span class='badge st-{d['status'].lower()}'>{d['status']}</span></td>"
            f"<td>{d['health_status']}</td><td>{d['actor']}</td><td>{d['notes']}</td></tr>"
            for d in data["deployments"][:10]
        ) or "<tr><td colspan='6' class='muted'>No deployments executed yet.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FORGE — Supply Chain &amp; DevSecOps Operations</title>
<style>
  :root {{ --bg:#F5F5F3; --surface:#FFFFFF; --ink:#1E242B; --muted:#5C6773; --steel:#3D5166; --green:#243B35; --border:#DCE1E6; --danger:#7A2E3A; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--ink); line-height:1.5; }}
  header {{ background:#182028; color:#EAE5DA; padding:22px 32px; border-bottom:3px solid var(--green); }}
  header h1 {{ font-size:20px; letter-spacing:1.2px; font-weight:700; }}
  header p {{ font-size:13px; color:#A8B3BE; margin-top:4px; }}
  main {{ max-width:1180px; margin:24px auto; padding:0 24px 40px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin-bottom:24px; }}
  .card {{ background:var(--surface); border:1px solid var(--border); padding:16px; }}
  .card .label {{ font-size:11px; text-transform:uppercase; letter-spacing:0.8px; color:var(--muted); }}
  .card .val {{ font-size:22px; font-weight:700; color:var(--ink); margin-top:6px; }}
  .card .sub {{ font-size:12px; color:var(--steel); margin-top:4px; }}
  section {{ background:var(--surface); border:1px solid var(--border); padding:18px 20px; margin-bottom:20px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:0.8px; color:var(--green); margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:6px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #ECEFF2; }}
  th {{ font-size:11px; text-transform:uppercase; color:var(--muted); background:#FAFBFB; }}
  .badge {{ display:inline-block; padding:2px 7px; font-size:11px; font-weight:600; border-radius:2px; }}
  .sev-critical,.sev-high,.st-blocked,.st-failed {{ background:#F6E6E9; color:var(--danger); }}
  .sev-medium {{ background:#F6EFE2; color:#7A5A20; }}
  .sev-low,.st-deployed {{ background:#E5F0EC; color:var(--green); }}
  .st-rolled_back {{ background:#E9EEF3; color:var(--steel); }}
  .muted {{ color:var(--muted); }}
</style>
</head>
<body>
  <header>
    <h1>FORGE — Secure Software Supply Chain &amp; DevSecOps Engineering</h1>
    <p>Live persisted pipeline state · Real SAST/Secret/Policy/SBOM/Ed25519 Provenance Controls</p>
  </header>
  <main>
    <div class="grid">
      <div class="card"><div class="label">Security Scans</div><div class="val">{c['scan_runs']}</div><div class="sub">Persisted runs</div></div>
      <div class="card"><div class="label">OPA Policy Gate</div><div class="val">{'PASS' if latest_pol.get('allowed') else ('DENY' if latest_pol else 'N/A')}</div><div class="sub">{latest_pol.get('engine', 'Not evaluated')}</div></div>
      <div class="card"><div class="label">CycloneDX SBOM</div><div class="val">{latest_sbom.get('component_count', 0)}</div><div class="sub">Components ({latest_sbom.get('spec_version', 'N/A')})</div></div>
      <div class="card"><div class="label">Provenance Signature</div><div class="val">{'VERIFIED' if latest_att.get('verified') else 'NONE'}</div><div class="sub">{latest_att.get('algorithm', 'Ed25519')}</div></div>
      <div class="card"><div class="label">Active Release</div><div class="val">{latest_dep.get('release_tag', 'None')}</div><div class="sub">{latest_dep.get('status', 'Awaiting gate')}</div></div>
    </div>

    <section>
      <h2>Normalized Security Findings &amp; Remediation Status</h2>
      <table>
        <thead><tr><th>ID</th><th>Scanner</th><th>Rule</th><th>Severity</th><th>Location</th><th>Status</th></tr></thead>
        <tbody>{finding_rows}</tbody>
      </table>
    </section>

    <section>
      <h2>Controlled Deployments &amp; Rollback History</h2>
      <table>
        <thead><tr><th>Deployment</th><th>Release</th><th>Gate Status</th><th>Health</th><th>Actor</th><th>Notes</th></tr></thead>
        <tbody>{dep_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""

    return app


app = create_app()
