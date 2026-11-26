# FORGE — Secure Software Supply Chain & DevSecOps Engineering

**Repository:** `https://github.com/Bassma202/ai-devsecops-telegram-agent`  
**Author:** Bassma Alaoui Sossey — Final-Year Cybersecurity Engineering Student (Université Euromed de Fès — EIDIA)

## 1. Purpose
FORGE is a local DevSecOps, software supply-chain security, and hardened ChatOps engineering platform. It integrates deterministic Bandit SAST execution, OPA Rego v1 policy-as-code gates, genuine CycloneDX v1.5 SBOM generation, Ed25519 provenance signing/verification, genuine local HTTP process release deployment & verified rollback, and state-machine-hardened Telegram ChatOps.

## 2. Implemented Capabilities
- **Real Fail-Closed Security Scanners (`src/forge/scanners.py`):** Executes Bandit SAST via argv-only `subprocess.run(..., shell=False)`, redacted secret scanning, Dockerfile hardening checks, and optional `pip-audit` / `trivy` integration. Both `FAILED` and `UNAVAILABLE` scanner states evaluate fail-closed (`SCANNER_ERROR`) and are never reported as clean passes.
- **OPA Rego v1 Policy-as-Code (`policies/container_compliance.rego`):** Enforces non-root UID, non-privileged mode, read-only rootfs, `cap_drop: [ALL]`, unsafe host-mount blocks, pinned image tags, zero critical/secret findings, SBOM validity, and verified cryptographic provenance, with documented exception support. Verified via `8/8` Rego unit tests on `openpolicyagent/opa:1.1.0-static`.
- **CycloneDX v1.5 SBOM (`src/forge/sbom.py`):** Generates live SBOMs from installed distributions using `cyclonedx-python-lib` (`67` validated components in current environment) bound to artifact SHA-256 digests.
- **Ed25519 Provenance Attestation (`src/forge/signing.py`):** Produces DSSE/in-toto-style signed envelopes bound to artifact digest and Git commit SHA; strictly rejects altered artifacts (`DIGEST_MISMATCH`) and untrusted keys (`SIGNATURE_INVALID`).
- **Genuine Local HTTP Release Deployment, Fail-Closed Health Probing & Rollback (`src/forge/deployer.py`):**
  - Launches real isolated Python HTTP release runtimes bound to loopback (`127.0.0.1`) serving distinct signed release artifacts (`v2.0.0`, `v2.1.0`, `v2.2.0-broken`).
  - `http_health_probe` validates loopback-only URLs, HTTP 200 status, JSON `status == "healthy"`, exact `expected_version`, and exact `expected_artifact_sha256`—failing closed on timeout, connection error, 5xx, or digest/version mismatch.
  - Broken candidate deploys (`HTTP 503`) fail safely without dropping the previous healthy running release; rollback launches and live-verifies the prior signed release over HTTP `/version` and `/health`.
- **Hardened Telegram ChatOps with Explicit Job States & Real Execution Hooks (`src/forge/telegram_bot.py`):** Default-deny operator allowlist (`FORGE_ALLOWED_TELEGRAM_USER_IDS`), strict command allowlist, sliding-window rate limiting, explicit `JobState` enum (`SUCCEEDED_CLEAN`, `BLOCKED_FINDINGS`, `FAILED_SCANNER_ERROR`, `FAILED_TIMEOUT`, `CANCELLED`, `DEPLOYED`, `ROLLED_BACK`, `BLOCKED_POLICY`, `FAILED_DEPLOY`), and operator-bound, expiry-checked, single-use, artifact-digest-bound two-step approval nonces wired directly to `deploy_executor` and `rollback_executor`.
- **Live Operations Dashboard (`src/forge/web.py`):** FastAPI REST API + HTML interface reading directly from SQLite (`data/forge.db`).
- **Reusable GitHub Actions Workflow (`.github/workflows/reusable-security-gate.yml`):** Least-privilege reusable workflow consumed via immutable 40-char commit SHA pins in sibling portfolio repositories (`CONSERVA`, `LIMEN`).

## 3. Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## 4. Quick Start & Reproduction
```bash
make doctor
make setup
make test
make security
make opa-test
make demo
make up   # Opens FastAPI operations UI on http://127.0.0.1:8006
```

## 5. Verified Execution Evidence
Evidence generated on 2026-11-26 (`evidence/forge_demo_evidence.json`, classification: **Genuine laboratory execution**):
- **Independent Remediation Scan:** Bandit `1.9.4` detected `B404` & `B602` (`shell=True`) in `examples/vulnerable_fixture` (`FINDINGS_BLOCKING`) and independently verified `0` findings (`PASS`) on `examples/remediated_fixture`.
- **OPA Rego v1 Gate:** Evaluated with `openpolicyagent/opa:1.1.0-static` (`8/8` Rego unit tests passed; noncompliant manifest blocked with `9` violations; compliant manifest `allowed: true`).
- **SBOM & Provenance:** `CycloneDX 1.5` SBOM (`67` components, `schema_valid: true`); Ed25519 verified authentic artifact, rejected 1-byte tamper (`DIGEST_MISMATCH`), rejected untrusted key (`SIGNATURE_INVALID`).
- **Live HTTP Deploy / Broken Candidate / Rollback:** Deployed distinct signed releases `v2.0.0` -> `v2.1.0` verified on loopback HTTP `/version` + `/health`; rejected unhealthy `v2.2.0-broken` (`HTTP 503`, retaining live `v2.1.0`); executed genuine runtime rollback back to `v2.0.0` confirmed over live HTTP.
- **Test Suite:** `13/13` pytest passed, Ruff clean, Bandit `0` Medium/High findings.

## 6. Known Limitations
- Local Ed25519 keys validate artifact integrity within the lab trust root; production pipelines should adopt keyless Sigstore OIDC or KMS-backed signing.
- Local process runtime deployment demonstrates fail-closed health checks and rollbacks on loopback without requiring an external Kubernetes cluster.
- Despite the historical repository slug (`ai-devsecops-telegram-agent`), FORGE does not fabricate LLM decision-making in security gates; all gating is deterministic.

## 7. License
MIT License.
