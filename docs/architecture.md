# Architecture & Design Decisions — FORGE

## Component Overview
- **`src/forge/scanners.py`**: Executes real security tools (`bandit`, `pip-audit`, `trivy` when installed, plus deterministic secret & Dockerfile auditors) via argv-only `subprocess.run(..., shell=False)`. Distinguishes `COMPLETED`, `FAILED`, and `UNAVAILABLE` explicitly.
- **`src/forge/policy.py` & `policies/container_compliance.rego`**: Open Policy Agent (OPA) Rego v1 policy gate covering root UID, privileged mode, read-only rootfs, Linux capability dropping, unsafe host mounts, `:latest` tags, vulnerability ceilings, secret blocks, SBOM validity, and signature verification. Verified with `opa test policies/ -v` (`8/8` passing on `openpolicyagent/opa:1.1.0-static`).
- **`src/forge/sbom.py`**: Generates genuine CycloneDX v1.5 JSON SBOMs from live installed distributions via `cyclonedx-python-lib` bound to artifact SHA-256 digests.
- **`src/forge/signing.py`**: Ed25519 DSSE/in-toto-style provenance signing and verification rejecting 1-byte tampering and untrusted keys.
- **`src/forge/deployer.py`**: Gate-enforced local release activation with health checks and controlled rollback.
- **`src/forge/telegram_bot.py`**: Default-deny authorized Telegram ChatOps interface with command allowlisting, sliding-window rate limits, non-blocking async execution, and two-step approval tokens.
- **`src/forge/web.py`**: FastAPI operational dashboard reading live persisted SQLite state.

## Key Architectural Decisions (ADRs)
1. **ADR-001 — Eliminate `shell=True` and substring scanning**: Original academic prototype used `shell=True` and naive string matching. Replaced with argv-only subprocess execution of real Bandit SAST and explicit scanner status tracking.
2. **ADR-002 — Rego v1 + pinned static OPA container**: Upgraded `policies/container_compliance.rego` from Rego v0 to Rego v1 (`import rego.v1`) and validated against `openpolicyagent/opa:1.1.0-static` (`arm64` + `amd64`).
3. **ADR-003 — Honest AI scope**: Removed unsupported AI claims; FORGE is positioned accurately as a DevSecOps, supply-chain security, and ChatOps engineering platform.
