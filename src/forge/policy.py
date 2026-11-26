"""Policy-as-Code evaluator backed by Open Policy Agent (OPA) Rego v1."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from forge.models import PolicyDecision
from forge.storage import ForgeStore

DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "policies" / "container_compliance.rego"
OPA_DOCKER_IMAGE = "openpolicyagent/opa:1.1.0-static"
UNSAFE_MOUNTS = {"/var/run/docker.sock", "/etc", "/proc", "/sys", "/"}


class PolicyEvaluator:
    """Evaluates deployment manifests against policies/container_compliance.rego.

    Prefers real OPA execution (native `opa` CLI, then pinned Docker OPA image when enabled)
    and falls back to an exact Python mirror only when OPA is unavailable, transparently
    recording the exact engine used in `PolicyDecision.engine`.
    """

    def __init__(
        self,
        policy_path: str | Path = DEFAULT_POLICY,
        store: ForgeStore | None = None,
        allow_docker_opa: bool = False,
    ) -> None:
        self.policy_path = Path(policy_path).resolve()
        self.store = store
        self.allow_docker_opa = allow_docker_opa

    def _eval_with_opa_cli(self, payload: dict[str, Any]) -> tuple[bool, list[str]] | None:
        opa_bin = shutil.which("opa")
        if not opa_bin:
            return None
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            json.dump(payload, tmp)
            tmp_path = tmp.name
        try:
            res = subprocess.run(
                [
                    opa_bin,
                    "eval",
                    "--format",
                    "json",
                    "--data",
                    str(self.policy_path),
                    "--input",
                    tmp_path,
                    "data.forge.security",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
            if res.returncode != 0:
                return None
            out = json.loads(res.stdout)
            val = out["result"][0]["expressions"][0]["value"]
            return bool(val.get("allow", False)), sorted(val.get("violations", []))
        except (OSError, subprocess.SubprocessError, KeyError, IndexError, json.JSONDecodeError):
            return None
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _eval_with_opa_docker(self, payload: dict[str, Any]) -> tuple[bool, list[str]] | None:
        docker_bin = shutil.which("docker")
        if not self.allow_docker_opa or not docker_bin:
            return None
        with tempfile.TemporaryDirectory() as tmpdir:
            in_file = Path(tmpdir) / "input.json"
            in_file.write_text(json.dumps(payload), encoding="utf-8")
            cmd = [
                docker_bin,
                "run",
                "--rm",
                "-v",
                f"{self.policy_path.parent}:/policies:ro",
                "-v",
                f"{tmpdir}:/work:ro",
                OPA_DOCKER_IMAGE,
                "eval",
                "--format",
                "json",
                "--data",
                f"/policies/{self.policy_path.name}",
                "--input",
                "/work/input.json",
                "data.forge.security",
            ]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30, shell=False)
                if res.returncode != 0:
                    return None
                out = json.loads(res.stdout)
                val = out["result"][0]["expressions"][0]["value"]
                return bool(val.get("allow", False)), sorted(val.get("violations", []))
            except (OSError, subprocess.SubprocessError, KeyError, IndexError, json.JSONDecodeError):
                return None

    def _eval_python_mirror(self, payload: dict[str, Any]) -> tuple[bool, list[str]]:
        """Deterministic Python mirror matching policies/container_compliance.rego 1:1."""
        violations: list[str] = []
        ctr = payload.get("container", {})
        vulns = payload.get("vulnerabilities", {})
        sc = payload.get("supply_chain", {})
        exc = set(payload.get("approved_exceptions", []))

        user = str(ctr.get("user", "")).strip().lower()
        if user in {"", "root", "0", "0:0"}:
            violations.append(
                "POLICY_FAIL [CTR-001]: Container runs as root or unspecified UID. Set non-root USER (e.g., 1001:1001)."
            )
        if ctr.get("privileged", False) is True:
            violations.append("POLICY_FAIL [CTR-002]: Privileged container mode is prohibited.")
        if not ctr.get("read_only_rootfs", False) and "CTR-003" not in exc:
            violations.append("POLICY_FAIL [CTR-003]: Root filesystem must be read-only (read_only_rootfs: true).")
        caps = {str(c).lower() for c in ctr.get("cap_drop", [])}
        if "all" not in caps:
            violations.append("POLICY_FAIL [CTR-004]: Container must drop ALL Linux capabilities (cap_drop: ['ALL']).")
        for mount in ctr.get("host_mounts", []):
            if mount in UNSAFE_MOUNTS:
                violations.append(f"POLICY_FAIL [CTR-005]: Prohibited host mount detected: {mount}")
        image = str(ctr.get("image", ""))
        if image.endswith(":latest"):
            violations.append(
                f"POLICY_FAIL [CTR-006]: Floating ':latest' image tag is prohibited ({image}). Pin version or digest."
            )
        crit = int(vulns.get("critical", 0))
        if crit > 0:
            violations.append(f"POLICY_FAIL [VULN-001]: {crit} CRITICAL vulnerabilities exceed ceiling (0).")
        high = int(vulns.get("high", 0))
        if high > 0 and "VULN-002" not in exc:
            violations.append(f"POLICY_FAIL [VULN-002]: {high} HIGH vulnerabilities require remediation or approved exception.")
        secrets = int(vulns.get("secrets", 0))
        if secrets > 0:
            violations.append(f"POLICY_FAIL [SEC-001]: {secrets} secret exposure(s) detected. Deployment blocked.")
        if not sc.get("sbom_valid", False):
            violations.append("POLICY_FAIL [SC-001]: Valid CycloneDX SBOM artifact is required before release.")
        if not sc.get("signature_verified", False):
            violations.append("POLICY_FAIL [SC-002]: Cryptographic artifact provenance signature must verify before release.")

        return len(violations) == 0, sorted(violations)

    def evaluate(self, payload: dict[str, Any], run_id: str | None = None) -> PolicyDecision:
        engine = "opa-cli"
        result = self._eval_with_opa_cli(payload)
        if result is None:
            result = self._eval_with_opa_docker(payload)
            if result is not None:
                engine = f"opa-docker:{OPA_DOCKER_IMAGE}"
        if result is None:
            result = self._eval_python_mirror(payload)
            engine = "python-rego-parity"

        allowed, violations = result
        decision = PolicyDecision(
            decision_id=f"POL-{uuid.uuid4().hex[:10].upper()}",
            run_id=run_id,
            engine=engine,
            policy_path=str(self.policy_path),
            allowed=allowed,
            violations=violations,
            approved_exceptions=list(payload.get("approved_exceptions", [])),
            input_snapshot=payload,
        )
        if self.store:
            self.store.save_policy_decision(decision)
        return decision
