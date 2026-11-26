# FORGE — Open Policy Agent (OPA) Rego v1 Container & Supply-Chain Policy
# Enforces container hardening, vulnerability ceilings, SBOM presence, and cryptographic attestation.

package forge.security

import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

# 1. Disallow root or empty user
violations contains msg if {
	user := lower(trim_space(object.get(input.container, "user", "")))
	user in {"", "root", "0", "0:0"}
	msg := "POLICY_FAIL [CTR-001]: Container runs as root or unspecified UID. Set non-root USER (e.g., 1001:1001)."
}

# 2. Disallow privileged containers
violations contains msg if {
	object.get(input.container, "privileged", false) == true
	msg := "POLICY_FAIL [CTR-002]: Privileged container mode is prohibited."
}

# 3. Require read-only root filesystem (unless explicitly exempted)
violations contains msg if {
	not object.get(input.container, "read_only_rootfs", false)
	not "CTR-003" in object.get(input, "approved_exceptions", [])
	msg := "POLICY_FAIL [CTR-003]: Root filesystem must be read-only (read_only_rootfs: true)."
}

# 4. Require dropping ALL Linux capabilities
violations contains msg if {
	caps := [lower(c) | some c in object.get(input.container, "cap_drop", [])]
	not "all" in caps
	msg := "POLICY_FAIL [CTR-004]: Container must drop ALL Linux capabilities (cap_drop: ['ALL'])."
}

# 5. Prohibit unsafe host mounts (Docker socket, /etc, /proc, root /)
unsafe_mounts := {"/var/run/docker.sock", "/etc", "/proc", "/sys", "/"}

violations contains msg if {
	some m in object.get(input.container, "host_mounts", [])
	m in unsafe_mounts
	msg := sprintf("POLICY_FAIL [CTR-005]: Prohibited host mount detected: %s", [m])
}

# 6. Disallow floating latest image tags
violations contains msg if {
	image := object.get(input.container, "image", "")
	endswith(image, ":latest")
	msg := sprintf("POLICY_FAIL [CTR-006]: Floating ':latest' image tag is prohibited (%s). Pin version or digest.", [image])
}

# 7. Require zero Critical vulnerabilities
violations contains msg if {
	crit := object.get(object.get(input, "vulnerabilities", {}), "critical", 0)
	crit > 0
	msg := sprintf("POLICY_FAIL [VULN-001]: %d CRITICAL vulnerabilities exceed ceiling (0).", [crit])
}

# 8. Require zero High unexempted vulnerabilities (unless documented exception)
violations contains msg if {
	high := object.get(object.get(input, "vulnerabilities", {}), "high", 0)
	high > 0
	not "VULN-002" in object.get(input, "approved_exceptions", [])
	msg := sprintf("POLICY_FAIL [VULN-002]: %d HIGH vulnerabilities require remediation or approved exception.", [high])
}

# 9. Require zero leaked secrets
violations contains msg if {
	secrets := object.get(object.get(input, "vulnerabilities", {}), "secrets", 0)
	secrets > 0
	msg := sprintf("POLICY_FAIL [SEC-001]: %d secret exposure(s) detected. Deployment blocked.", [secrets])
}

# 10. Require valid SBOM & verified artifact attestation for release
violations contains msg if {
	not object.get(object.get(input, "supply_chain", {}), "sbom_valid", false)
	msg := "POLICY_FAIL [SC-001]: Valid CycloneDX SBOM artifact is required before release."
}

violations contains msg if {
	not object.get(object.get(input, "supply_chain", {}), "signature_verified", false)
	msg := "POLICY_FAIL [SC-002]: Cryptographic artifact provenance signature must verify before release."
}
