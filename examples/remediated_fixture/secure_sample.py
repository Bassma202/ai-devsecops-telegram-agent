"""Remediated laboratory fixture eliminating subprocess shell invocation completely."""

import re

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,64}$")


def run_diagnostic_secure(hostname: str) -> str:
    if not HOST_RE.fullmatch(hostname):
        raise ValueError("Invalid hostname format.")
    return f"validated:{hostname}\n"
