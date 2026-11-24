# ==============================================================================
# Open Policy Agent (OPA) / Rego Security Policy for Containers
# Author: Bassma Alaoui Sossey
# Enforces production quality gates before deployment in CI/CD pipelines
# ==============================================================================

package container.security

default allow = false

# Allow deployment only if there are zero policy violations
allow {
    count(violations) == 0
}

# Rule 1: Disallow running containers as root (UID 0)
violations[msg] {
    input.config.User == "root"
    msg := "POLICY_FAIL: Container runs as root user. Must specify non-root USER in Dockerfile."
}

violations[msg] {
    input.config.User == "0"
    msg := "POLICY_FAIL: Container runs with UID 0. Must specify non-root USER."
}

# Rule 2: Disallow privileged mode execution
violations[msg] {
    input.host_config.Privileged == true
    msg := "POLICY_FAIL: Container configured in Privileged mode. Violates least-privilege boundary."
}

# Rule 3: Enforce presence of Trivy security scan report
violations[msg] {
    not input.trivy_scan_completed
    msg := "POLICY_FAIL: Missing mandatory Trivy container image security scan."
}

# Rule 4: Zero CRITICAL CVE tolerance
violations[msg] {
    input.vulnerabilities.critical > 0
    msg := sprintf("POLICY_FAIL: Found %d CRITICAL CVEs in image. Zero tolerance threshold exceeded.", [input.vulnerabilities.critical])
}
