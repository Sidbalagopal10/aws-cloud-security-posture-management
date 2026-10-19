from scanner.validator import validate_bucket
import json
from pathlib import Path

from scanner.risk_engine import (
    generate_risk_summary,
    prioritize_findings
)
from scanner.report_generator import generate_json_report


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "s3_buckets.json"
)

REQUIRED_PUBLIC_ACCESS_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets"
)


def load_buckets():
    with FIXTURE_PATH.open(encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Fixture root must be a JSON object")

    buckets = data.get("buckets")

    if not isinstance(buckets, list):
        raise ValueError("Fixture must contain a buckets list")

    seen_names = set()

    for bucket in buckets:
        validate_bucket(bucket)

        name = bucket["name"]

        if name in seen_names:
            raise ValueError(
                f"Duplicate bucket name: {name}"
            )

        seen_names.add(name)

    return buckets


def audit_bucket(bucket):
    findings = []
    name = bucket["name"]

    # Rule 1: Explicit S3 Block Public Access checks
    public_access = bucket.get("public_access_block") or {}

    incomplete_settings = [
        setting
        for setting in REQUIRED_PUBLIC_ACCESS_SETTINGS
        if public_access.get(setting) is not True
    ]

    if incomplete_settings:
        findings.append({
            "bucket": name,
            "severity": "HIGH",
            "issue": "S3 Block Public Access incomplete",
            "recommendation": (
                "Review these settings: "
                + ", ".join(incomplete_settings)
                + ". Enable all four controls where appropriate. "
                "This finding does not prove public exposure."
            )
        })

    # Rule 2: Organization-specific KMS policy
    encryption = bucket.get("encryption")

    if encryption != "aws:kms":
        findings.append({
            "bucket": name,
            "severity": "MEDIUM",
            "issue": "Bucket does not meet KMS encryption policy",
            "recommendation": (
                "Review encryption requirements and "
                "configure SSE-KMS if mandated by policy. "
                "SSE-S3 is also encryption at rest."
            )
        })

    # Rule 3: Bucket versioning
    if bucket.get("versioning") != "Enabled":
        findings.append({
            "bucket": name,
            "severity": "MEDIUM",
            "issue": "S3 versioning not enabled",
            "recommendation": (
                "Consider enabling versioning where recovery "
                "and retention requirements justify it."
            )
        })

    # Rule 4: Server access logging
    if bucket.get("logging") is not True:
        findings.append({
            "bucket": name,
            "severity": "LOW",
            "issue": "S3 server access logging disabled",
            "recommendation": (
                "Review access logging requirements and "
                "enable suitable monitoring where needed."
            )
        })

    return findings


def main():
    buckets = load_buckets()
    all_findings = []

    for bucket in buckets:
        all_findings.extend(audit_bucket(bucket))

    print("\nAWS CSPM - S3 Security Audit")
    print("=" * 40)

    for finding in all_findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['bucket']}: {finding['issue']}"
        )

    print(f"\nAssets scanned: {len(buckets)}")
    print(f"Total findings: {len(all_findings)}")

    summary = generate_risk_summary(all_findings)

    print("\nRisk Assessment Summary")
    print("=" * 40)
    print(f"Critical Findings: {summary['critical']}")
    print(f"High Findings: {summary['high']}")
    print(f"Medium Findings: {summary['medium']}")
    print(f"Low Findings: {summary['low']}")
    print(f"Total Risk Score: {summary['risk_score']}")

    print("\nPrioritized Findings")
    print("=" * 40)

    for finding in prioritize_findings(all_findings):
        print(
            f"[{finding['severity']}] "
            f"{finding['bucket']} - {finding['issue']}"
        )

    report_path = generate_json_report(
        all_findings,
        buckets=buckets
    )

    print("\nSecurity report generated successfully!")
    print(f"Report location: {report_path}")


if __name__ == "__main__":
    main()
