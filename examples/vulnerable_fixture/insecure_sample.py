"""Harmless laboratory fixture containing intentional insecure patterns for FORGE remediation testing.

NOT USED IN PRODUCTION. Used solely to verify that Bandit and FORGE secret/SAST gates detect
real defects and block deployment until remediated.
"""

import subprocess


def run_diagnostic_insecure(hostname: str) -> str:
    # Intentional Bandit B602 finding (shell=True command injection risk)
    res = subprocess.run(f"echo {hostname}", shell=True, capture_output=True, text=True)
    return res.stdout
