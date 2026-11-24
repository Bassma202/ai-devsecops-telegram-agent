"""
Unit Tests for DevSecOps Policy-as-Code Quality Gate
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from security.policy_enforcer import PolicyEnforcer

class TestPolicyEnforcer(unittest.TestCase):
    def setUp(self):
        self.enforcer = PolicyEnforcer()

    def test_root_user_blocked(self):
        manifest = {"user": "root", "privileged": False, "vulnerabilities": {"critical": 0}}
        res = self.enforcer.evaluate(manifest)
        self.assertFalse(res["deployment_allowed"])
        self.assertTrue(any("NON-ROOT" in v for v in res["violations"]))

    def test_critical_cve_blocked(self):
        manifest = {"user": "appuser_1001", "privileged": False, "vulnerabilities": {"critical": 3}}
        res = self.enforcer.evaluate(manifest)
        self.assertFalse(res["deployment_allowed"])
        self.assertTrue(any("QUALITY GATE FAILED" in v for v in res["violations"]))

    def test_hardened_manifest_allowed(self):
        manifest = {
            "user": "appuser_1001",
            "privileged": False,
            "read_only_rootfs": True,
            "vulnerabilities": {"critical": 0, "high": 0}
        }
        res = self.enforcer.evaluate(manifest)
        self.assertTrue(res["deployment_allowed"])
        self.assertEqual(res["policy_status"], "PASSED")

if __name__ == "__main__":
    unittest.main()
