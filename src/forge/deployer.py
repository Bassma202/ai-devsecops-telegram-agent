"""Controlled local runtime deployment manager enforcing security gates, real HTTP readiness probes, and rollback."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from forge.models import AttestationRecord, DeploymentRecord, PolicyDecision, SBOMRecord
from forge.storage import ForgeStore


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def http_health_probe(
    url: str,
    expected_version: str | None = None,
    expected_sha256: str | None = None,
    timeout_s: float = 1.0,
    retries: int = 12,
    retry_delay_s: float = 0.25,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Perform a genuine bounded HTTP readiness probe. Fail-closed on any connection, timeout, status, or payload mismatch."""
    if not url or not url.startswith(("http://127.0.0.1:", "http://localhost:")):
        return False, f"Invalid loopback health probe URL: '{url}'", None

    last_err = "No attempts made"
    for attempt in range(1, max(1, retries) + 1):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
                code = resp.getcode()
                raw = resp.read().decode("utf-8", errors="replace")
                if code != 200:
                    last_err = f"HTTP {code} from {url}"
                else:
                    try:
                        body = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        last_err = f"Non-JSON health payload: {exc}"
                    else:
                        if body.get("status") != "healthy":
                            last_err = f"Unhealthy status reported: {body.get('status')}"
                        elif expected_version and body.get("version") != expected_version:
                            last_err = f"Version mismatch: expected {expected_version}, got {body.get('version')}"
                        elif expected_sha256 and body.get("artifact_sha256") != expected_sha256:
                            last_err = (
                                f"Artifact digest mismatch: expected {expected_sha256[:12]}, "
                                f"got {str(body.get('artifact_sha256'))[:12]}"
                            )
                        else:
                            return (
                                True,
                                f"HTTP 200 healthy (version={body.get('version')}, attempts={attempt})",
                                body,
                            )
        except urllib.error.HTTPError as exc:
            last_err = f"HTTP {exc.code} from {url}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = f"Connection/timeout error ({type(exc).__name__}): {exc}"

        if attempt < retries:
            time.sleep(retry_delay_s)

    return False, f"Readiness probe failed after {retries} attempts: {last_err}", None


def write_verifiable_release_service(
    target_path: Path,
    version: str,
    healthy: bool = True,
) -> Path:
    """Create a minimal standalone Python HTTP release artifact serving /health and /version for local deployment tests."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    code = f'''"""Standalone FORGE release artifact {version}."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = {version!r}
HEALTHY = {healthy!r}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        sha = os.environ.get("FORGE_ARTIFACT_SHA256", "unset")
        if self.path == "/health":
            code = 200 if HEALTHY else 503
            payload = {{"status": "healthy" if HEALTHY else "unhealthy", "version": VERSION, "artifact_sha256": sha}}
        elif self.path == "/version":
            code = 200
            payload = {{"version": VERSION, "artifact_sha256": sha}}
        else:
            code = 404
            payload = {{"error": "not_found"}}
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("FORGE_PORT", "0"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''
    target_path.write_text(code, encoding="utf-8")
    return target_path


@dataclass
class RunningReleaseProcess:
    release_tag: str
    artifact_path: Path
    artifact_sha256: str
    port: int
    process: subprocess.Popen[str]

    @property
    def health_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/health"

    @property
    def version_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/version"

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2.0)


class ControlledDeployer:
    """Mediates genuine local runtime release activation behind Policy, SBOM, Attestation, and live HTTP health gates."""

    def __init__(
        self,
        store: ForgeStore,
        state_file: str | Path = "data/active_release.json",
        health_probe: Callable[[str, str | None, str | None], tuple[bool, str, dict[str, Any] | None]] | None = None,
    ) -> None:
        self.store = store
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.health_probe = health_probe or self._default_health_probe
        self._active_proc: RunningReleaseProcess | None = None

    @staticmethod
    def _default_health_probe(
        health_url: str,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        """Fail-closed default readiness probe requiring an actual reachable local HTTP endpoint."""
        return http_health_probe(
            url=health_url,
            expected_version=expected_version,
            expected_sha256=expected_sha256,
            timeout_s=1.0,
            retries=10,
            retry_delay_s=0.15,
        )

    def current_state(self) -> dict[str, Any]:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        return {
            "active_release": None,
            "active_artifact_path": None,
            "active_artifact_sha256": None,
            "active_port": None,
            "active_deployment_id": None,
            "previous_release": None,
            "previous_artifact_path": None,
            "previous_artifact_sha256": None,
        }

    def query_running_version(self) -> dict[str, Any] | None:
        """Query the live running local release process over HTTP to independently verify its identity."""
        if self._active_proc is None or self._active_proc.process.poll() is not None:
            return None
        try:
            with urllib.request.urlopen(self._active_proc.version_url, timeout=1.5) as resp:  # nosec B310
                if resp.getcode() == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None
        return None

    def _launch_artifact(self, release_tag: str, artifact_path: Path, expected_sha256: str) -> RunningReleaseProcess:
        resolved = artifact_path.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Release artifact not found: {resolved}")
        actual_sha = _sha256_file(resolved)
        if actual_sha != expected_sha256:
            raise ValueError(
                f"Artifact digest mismatch before launch: expected {expected_sha256}, actual {actual_sha}"
            )
        port = _pick_free_port()
        env = os.environ.copy()
        env["FORGE_PORT"] = str(port)
        env["FORGE_RELEASE_VERSION"] = release_tag
        env["FORGE_ARTIFACT_SHA256"] = actual_sha
        proc = subprocess.Popen(  # nosec B603
            [sys.executable, str(resolved)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            shell=False,
        )
        return RunningReleaseProcess(
            release_tag=release_tag,
            artifact_path=resolved,
            artifact_sha256=actual_sha,
            port=port,
            process=proc,
        )

    def stop_runtime(self) -> None:
        if self._active_proc is not None:
            self._active_proc.stop()
            self._active_proc = None

    def deploy(
        self,
        release_tag: str,
        policy_decision: PolicyDecision,
        sbom: SBOMRecord,
        attestation: AttestationRecord,
        actor: str = "cli",
        artifact_path: str | Path | None = None,
        health_url: str | None = None,
    ) -> DeploymentRecord:
        dep_id = f"DEP-{uuid.uuid4().hex[:10].upper()}"
        reasons: list[str] = []
        if not policy_decision.allowed:
            reasons.append(f"OPA policy denied ({len(policy_decision.violations)} violations)")
        if not sbom.schema_valid:
            reasons.append("SBOM failed schema validation")
        if not attestation.verified:
            reasons.append(f"Attestation unverified: {attestation.verification_detail}")

        resolved_artifact = Path(artifact_path) if artifact_path else Path(attestation.artifact_path)
        if resolved_artifact.is_file():
            actual_digest = _sha256_file(resolved_artifact)
            if actual_digest != attestation.artifact_sha256:
                reasons.append("Artifact SHA-256 on disk does not match verified attestation digest")
        elif health_url is None:
            reasons.append(f"Verified release artifact missing on disk: {resolved_artifact}")

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

        candidate_proc: RunningReleaseProcess | None = None
        probe_target = health_url or ""
        try:
            if health_url is None:
                candidate_proc = self._launch_artifact(release_tag, resolved_artifact, attestation.artifact_sha256)
                probe_target = candidate_proc.health_url
            healthy, health_msg, _ = self.health_probe(probe_target, release_tag, attestation.artifact_sha256)
        except Exception as exc:
            healthy = False
            health_msg = f"Launch or probe error: {exc}"

        state = self.current_state()
        if not healthy:
            if candidate_proc is not None:
                candidate_proc.stop()
            # Verify existing active release remains unaffected if one was running
            prev_note = "Readiness probe failed; no prior release running."
            if self._active_proc is not None:
                prev_ok, prev_msg, _ = self.health_probe(
                    self._active_proc.health_url,
                    self._active_proc.release_tag,
                    self._active_proc.artifact_sha256,
                )
                prev_note = f"Readiness probe failed; prior active release {self._active_proc.release_tag} retained (healthy={prev_ok}: {prev_msg})."
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
                notes=prev_note,
            )
            self.store.save_deployment(rec)
            return rec

        # Promote healthy candidate and stop previous runtime process cleanly
        old_proc = self._active_proc
        self._active_proc = candidate_proc
        if old_proc is not None:
            old_proc.stop()

        new_state = {
            "active_release": release_tag,
            "active_artifact_path": str(resolved_artifact.resolve()) if resolved_artifact.exists() else None,
            "active_artifact_sha256": attestation.artifact_sha256,
            "active_port": candidate_proc.port if candidate_proc else None,
            "active_deployment_id": dep_id,
            "previous_release": state.get("active_release"),
            "previous_artifact_path": state.get("active_artifact_path"),
            "previous_artifact_sha256": state.get("active_artifact_sha256"),
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
            notes="Verified runtime process started and passed live HTTP readiness and version-digest checks.",
        )
        self.store.save_deployment(rec)
        return rec

    def rollback(self, actor: str = "cli") -> DeploymentRecord:
        state = self.current_state()
        prev_tag = state.get("previous_release")
        prev_path_str = state.get("previous_artifact_path")
        prev_sha = state.get("previous_artifact_sha256")
        if not prev_tag or not prev_path_str or not prev_sha:
            raise ValueError("No previous verified release artifact available for rollback.")

        prev_path = Path(prev_path_str)
        dep_id = f"DEP-{uuid.uuid4().hex[:10].upper()}"
        restored_proc: RunningReleaseProcess | None = None
        try:
            restored_proc = self._launch_artifact(prev_tag, prev_path, prev_sha)
            healthy, health_msg, _ = self.health_probe(restored_proc.health_url, prev_tag, prev_sha)
        except Exception as exc:
            healthy = False
            health_msg = f"Rollback launch failed: {exc}"

        if not healthy:
            if restored_proc is not None:
                restored_proc.stop()
            rec = DeploymentRecord(
                deployment_id=dep_id,
                release_tag=prev_tag,
                artifact_sha256=prev_sha,
                policy_decision_id="ROLLBACK",
                sbom_id="ROLLBACK",
                attestation_id="ROLLBACK",
                status="ROLLBACK_FAILED",
                health_status=f"UNHEALTHY: {health_msg}",
                actor=actor,
                notes=f"Attempted rollback to {prev_tag} failed readiness verification.",
            )
            self.store.save_deployment(rec)
            return rec

        old_proc = self._active_proc
        self._active_proc = restored_proc
        if old_proc is not None:
            old_proc.stop()

        new_state = {
            "active_release": prev_tag,
            "active_artifact_path": str(prev_path.resolve()),
            "active_artifact_sha256": prev_sha,
            "active_port": restored_proc.port if restored_proc else None,
            "active_deployment_id": dep_id,
            "previous_release": state.get("active_release"),
            "previous_artifact_path": state.get("active_artifact_path"),
            "previous_artifact_sha256": state.get("active_artifact_sha256"),
        }
        self.state_file.write_text(json.dumps(new_state, indent=2), encoding="utf-8")

        rec = DeploymentRecord(
            deployment_id=dep_id,
            release_tag=prev_tag,
            artifact_sha256=prev_sha,
            policy_decision_id="ROLLBACK",
            sbom_id="ROLLBACK",
            attestation_id="ROLLBACK",
            status="ROLLED_BACK",
            health_status=f"HEALTHY: {health_msg}",
            actor=actor,
            notes=f"Restored verified runtime artifact {prev_tag} (sha256={prev_sha[:12]}) from {state.get('active_release')}.",
        )
        self.store.save_deployment(rec)
        return rec
