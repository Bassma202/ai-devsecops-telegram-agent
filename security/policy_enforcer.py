"""
Policy-as-Code Quality Gate Evaluator
Author: Bassma Alaoui Sossey
Evaluates container deployment metadata against security policies (OPA / Rego model).
"""

from typing import Dict, Any, List

class PolicyEnforcer:
    def evaluate(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        violations = []

        # 1. Root User Check
        user = str(manifest.get("user", "")).lower()
        if user in ["root", "0", ""]:
            violations.append("NON-ROOT VIOLATION: Container must not run as root. Specify explicit UID (e.g., USER 1001).")

        # 2. Privileged Mode Check
        if manifest.get("privileged", False):
            violations.append("PRIVILEGED MODE VIOLATION: Privileged flag enabled. Violates container isolation boundary.")

        # 3. Read-only Root Filesystem Check
        if not manifest.get("read_only_rootfs", False):
            violations.append("FILESYSTEM INTEGRITY WARNING: Root filesystem is writable. Consider enabling read-only rootfs.")

        # 4. Critical CVE Check (Trivy Scan Results)
        vulns = manifest.get("vulnerabilities", {})
        critical_cves = vulns.get("critical", 0)
        high_cves = vulns.get("high", 0)

        if critical_cves > 0:
            violations.append(f"QUALITY GATE FAILED: Found {critical_cves} CRITICAL CVEs. Zero-tolerance policy enforced.")

        is_allowed = len([v for v in violations if "WARNING" not in v]) == 0

        return {
            "deployment_allowed": is_allowed,
            "policy_status": "PASSED" if is_allowed else "BLOCKED_BY_POLICY",
            "violations_count": len(violations),
            "violations": violations
        }

if __name__ == "__main__":
    enforcer = PolicyEnforcer()
    bad_manifest = {
        "image": "app:latest",
        "user": "root",
        "privileged": True,
        "vulnerabilities": {"critical": 2, "high": 5}
    }
    good_manifest = {
        "image": "app:v1.2",
        "user": "appuser_1001",
        "privileged": False,
        "read_only_rootfs": True,
        "vulnerabilities": {"critical": 0, "high": 1}
    }
    print("Bad Container Evaluation:", enforcer.evaluate(bad_manifest))
    print("Hardened Container Evaluation:", enforcer.evaluate(good_manifest))
