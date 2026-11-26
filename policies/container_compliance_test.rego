package forge.security_test

import data.forge.security
import rego.v1

compliant_input := {
	"container": {
		"image": "forge-demo-app:2.0.0@sha256:abc123",
		"user": "1001:1001",
		"privileged": false,
		"read_only_rootfs": true,
		"cap_drop": ["ALL"],
		"host_mounts": [],
	},
	"vulnerabilities": {
		"critical": 0,
		"high": 0,
		"secrets": 0,
	},
	"supply_chain": {
		"sbom_valid": true,
		"signature_verified": true,
	},
	"approved_exceptions": [],
}

test_compliant_artifact_allowed if {
	security.allow with input as compliant_input
	count(security.violations) == 0 with input as compliant_input
}

test_root_user_denied if {
	bad := object.union(compliant_input, {"container": object.union(compliant_input.container, {"user": "root"})})
	not security.allow with input as bad
}

test_privileged_container_denied if {
	bad := object.union(compliant_input, {"container": object.union(compliant_input.container, {"privileged": true})})
	not security.allow with input as bad
}

test_docker_sock_mount_denied if {
	bad := object.union(compliant_input, {"container": object.union(compliant_input.container, {"host_mounts": ["/var/run/docker.sock"]})})
	not security.allow with input as bad
}

test_floating_latest_tag_denied if {
	bad := object.union(compliant_input, {"container": object.union(compliant_input.container, {"image": "python:latest"})})
	not security.allow with input as bad
}

test_critical_cve_denied if {
	bad := object.union(compliant_input, {"vulnerabilities": {"critical": 1, "high": 0, "secrets": 0}})
	not security.allow with input as bad
}

test_missing_signature_denied if {
	bad := object.union(compliant_input, {"supply_chain": {"sbom_valid": true, "signature_verified": false}})
	not security.allow with input as bad
}

test_documented_high_exception_allowed if {
	exc := object.union(compliant_input, {
		"vulnerabilities": {"critical": 0, "high": 1, "secrets": 0},
		"approved_exceptions": ["VULN-002"],
	})
	security.allow with input as exc
}
