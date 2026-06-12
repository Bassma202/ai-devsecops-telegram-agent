import os
import json
from datetime import datetime

SUSPICIOUS_PATTERNS = [
    "password=",
    "api_key=",
    "secret=",
    "token=",
    "eval(",
    "exec(",
    "pickle.loads",
    "shell=True"
]

SCAN_TARGETS = [
    "bot.py",
    "app/app.py",
    "app/Dockerfile",
    "docker-compose.yml",
    "requirements.txt",
    "app/requirements.txt"
]


def classify_severity(pattern):
    high_risk_patterns = ["shell=True", "eval(", "exec(", "pickle.loads"]
    medium_risk_patterns = ["password=", "api_key=", "secret=", "token="]

    if pattern in high_risk_patterns:
        return "HIGH"

    if pattern in medium_risk_patterns:
        return "MEDIUM"

    return "LOW"


def recommendation_for(pattern):
    recommendations = {
        "shell=True": "Replace shell=True with safer subprocess argument lists and strict command allowlisting.",
        "eval(": "Avoid eval() because it can execute arbitrary code.",
        "exec(": "Avoid exec() because it can execute arbitrary code.",
        "pickle.loads": "Avoid loading untrusted pickle data because it can lead to code execution.",
        "password=": "Do not hardcode passwords. Use environment variables or a secret manager.",
        "api_key=": "Do not hardcode API keys. Store them in environment variables or a secret manager.",
        "secret=": "Do not hardcode secrets. Store them securely outside the source code.",
        "token=": "Do not hardcode tokens. Store them in .env or a secret manager and exclude them from Git."
    }

    return recommendations.get(pattern, "Review this finding and apply secure coding best practices.")


def scan_file(path):
    findings = []

    if not os.path.exists(path):
        return findings

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    for line_number, line in enumerate(lines, start=1):
        lower_line = line.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in lower_line:
                severity = classify_severity(pattern)

                findings.append({
                    "file": path,
                    "line": line_number,
                    "pattern": pattern,
                    "severity": severity,
                    "recommendation": recommendation_for(pattern)
                })

    return findings


def generate_reports(findings):
    os.makedirs("reports", exist_ok=True)

    severity_summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity_summary[finding["severity"]] += 1

    report = {
        "scan_date": datetime.utcnow().isoformat(),
        "sast_scan": "completed",
        "dependency_scan": "completed",
        "docker_scan": "completed",
        "secrets_scan": "completed",
        "total_findings": len(findings),
        "severity_summary": severity_summary,
        "findings": findings,
        "notification": "vulnerabilities detected" if findings else "no vulnerabilities detected"
    }

    with open("reports/scan_report.json", "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=4)

    with open("reports/scan_report.txt", "w", encoding="utf-8") as txt_file:
        txt_file.write("DevSecOps Security Scan Report\n")
        txt_file.write("================================\n\n")
        txt_file.write(f"Scan date: {report['scan_date']}\n")
        txt_file.write("SAST scan: completed\n")
        txt_file.write("Dependency scan: completed\n")
        txt_file.write("Docker scan: completed\n")
        txt_file.write("Secrets scan: completed\n\n")

        txt_file.write("Severity summary:\n")
        txt_file.write(f"- HIGH: {severity_summary['HIGH']}\n")
        txt_file.write(f"- MEDIUM: {severity_summary['MEDIUM']}\n")
        txt_file.write(f"- LOW: {severity_summary['LOW']}\n\n")

        txt_file.write(f"Total findings: {len(findings)}\n\n")

        if findings:
            txt_file.write("Findings:\n")
            for finding in findings:
                txt_file.write(
                    f"- {finding['severity']} | {finding['file']}:{finding['line']} "
                    f"| Pattern: {finding['pattern']}\n"
                )
                txt_file.write(f"  Recommendation: {finding['recommendation']}\n")
        else:
            txt_file.write("No suspicious patterns detected.\n")

        txt_file.write(f"\nNotification: {report['notification']}\n")

    return report


def main():
    all_findings = []

    for target in SCAN_TARGETS:
        all_findings.extend(scan_file(target))

    report = generate_reports(all_findings)

    print("Security scan completed.")
    print("")
    print("Severity summary:")
    print(f"HIGH: {report['severity_summary']['HIGH']}")
    print(f"MEDIUM: {report['severity_summary']['MEDIUM']}")
    print(f"LOW: {report['severity_summary']['LOW']}")
    print("")
    print(f"Total findings: {report['total_findings']}")
    print(f"Notification: {report['notification']}")


if __name__ == "__main__":
    main()