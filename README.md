# FORGE — Secure Software Supply Chain & DevSecOps Engineering

**Repository:** `https://github.com/Bassma202/ai-devsecops-telegram-agent`  
**Author:** Bassma Alaoui Sossey — Final-Year Cybersecurity Engineering Student (Université Euromed de Fès — EIDIA)

## 1. Purpose
FORGE is a local DevSecOps, software supply-chain security, and hardened ChatOps engineering platform. It replaces naive regex checks and manual deployments with real SAST execution, OPA Rego v1 policy-as-code gates, genuine CycloneDX v1.5 SBOM generation, Ed25519 provenance signing/verification, controlled release rollbacks, and default-deny Telegram ChatOps.

## 2. Implemented Capabilities
- **Real Security Scanners (`src/forge/scanners.py`)**: Executes Bandit SAST via argv-only `subprocess.run(..., shell=False)`, redacted secret scanning, Dockerfile hardening checks, and optional `pip-audit` / `trivy` integration. Scanner errors or unavailability are reported explicitly (`FAILED` / `UNAVAILABLE`) and never treated as passing scans.
- **OPA Rego v1 Policy-as-Code (`policies/container_compliance.rego`)**: Enforces non-root UID, non-privileged mode, read-only rootfs, `cap_drop: [ALL]`, unsafe host-mount blocks, pinned image tags, zero critical/secret findings, SBOM validity, and verified cryptographic provenance, with documented exception support. Verified via `8/8` Rego unit tests on `openpolicyagent/opa:1.1.0-static`.
- **CycloneDX v1.5 SBOM (`src/forge/sbom.py`)**: Generates live SBOMs from installed distributions using `cyclonedx-python-lib` (67 validated components in current environment) bound to artifact SHA-256 digests.
- **Ed25519 Provenance Attestation (`src/forge/signing.py`)**: Produces DSSE/in-toto-style signed envelopes bound to artifact digest and Git commit SHA; strictly rejects altered artifacts (`DIGEST_MISMATCH`) and untrusted keys (`SIGNATURE_INVALID`).
- **Controlled Local Deployment & Rollback (`src/forge/deployer.py`)**: Blocks noncompliant builds, records health checks on approved releases, and supports controlled rollback to the last verified release.
- **Hardened Telegram ChatOps (`src/forge/telegram_bot.py`)**: Default-deny operator allowlist (`FORGE_ALLOWED_TELEGRAM_USER_IDS`), strict command allowlist, sliding-window rate limiting, non-blocking async scan execution, two-step approval nonces for `/deploy` and `/rollback`, and automatic secret redaction.
- **Live Operations Dashboard (`src/forge/web.py`)**: FastAPI REST API + HTML interface reading directly from SQLite (`data/forge.db`).
- **Reusable GitHub Actions Workflow (`.github/workflows/reusable-security-gate.yml`)**: Pinned-SHA least-privilege workflow reusable across sibling portfolio repositories.

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
- **Remediation Lifecycle**: Bandit `1.9.4` detected `B404` & `B602` (`shell=True`) in `examples/vulnerable_fixture` (`FINDINGS_BLOCKING`) and returned `0` findings (`PASS`) on `examples/remediated_fixture` and hardened `app/`.
- **OPA Rego v1 Gate**: Evaluated with `openpolicyagent/opa:1.1.0-static` (`8/8` Rego unit tests passed; noncompliant manifest blocked with `9` violations; compliant manifest `allowed: true`).
- **SBOM**: Generated `CycloneDX 1.5` SBOM (`67` components, `schema_valid: true`).
- **Provenance**: Authentic artifact `VERIFIED`; 1-byte modified artifact rejected (`DIGEST_MISMATCH`); untrusted key rejected (`SIGNATURE_INVALID`).
- **Deployment & Rollback**: `v2.0.0-unsafe` -> `BLOCKED`; `v2.0.0` -> `DEPLOYED`; `v2.0.1` -> `DEPLOYED`; rollback -> `ROLLED_BACK` (`active_release: v2.0.0`).

## 6. Known Limitations
- Local Ed25519 keys validate artifact integrity within the lab trust root; production pipelines should adopt keyless Sigstore OIDC or KMS-backed signing.
- `pip-audit` and `trivy` require network access for live vulnerability databases; offline runs explicitly classify them `UNAVAILABLE`.
- Despite the historical repository slug (`ai-devsecops-telegram-agent`), FORGE does not fabricate LLM decision-making in security gates; all gating is deterministic.

## 7. License
MIT License.
