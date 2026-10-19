SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}


def calculate_risk_score(findings):
    total_score = 0

    for finding in findings:
        severity = finding["severity"]
        total_score += SEVERITY_SCORES.get(severity, 0)

    return total_score


def prioritize_findings(findings):
    return sorted(
        findings,
        key=lambda finding: SEVERITY_SCORES.get(
            finding["severity"], 0
        ),
        reverse=True
    )


def generate_risk_summary(findings):
    return {
        "total_findings": len(findings),
        "critical": sum(
            f["severity"] == "CRITICAL" for f in findings
        ),
        "high": sum(
            f["severity"] == "HIGH" for f in findings
        ),
        "medium": sum(
            f["severity"] == "MEDIUM" for f in findings
        ),
        "low": sum(
            f["severity"] == "LOW" for f in findings
        ),
        "risk_score": calculate_risk_score(findings)
    }
