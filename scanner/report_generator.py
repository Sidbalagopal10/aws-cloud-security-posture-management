import json
from datetime import datetime, timezone
from pathlib import Path

from scanner.risk_engine import (
    generate_risk_summary,
    prioritize_findings
)


def generate_json_report(
    findings,
    output_path=None,
    buckets=None
):
    if output_path is None:
        output_path = (
            Path(__file__).resolve().parents[1]
            / "reports"
            / "s3_security_report.json"
        )

    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    inventory = []

    if buckets is not None:
        for bucket in buckets:
            bucket_name = bucket["name"]

            bucket_findings = [
                finding for finding in findings
                if finding["bucket"] == bucket_name
            ]

            bucket_summary = generate_risk_summary(
                bucket_findings
            )

            inventory.append({
                "bucket": bucket_name,
                "status": (
                    "FINDINGS"
                    if bucket_findings
                    else "NO_FINDINGS"
                ),
                "total_findings": len(bucket_findings),
                "risk_score": bucket_summary["risk_score"]
            })

    report = {
        "report_type": "AWS S3 Security Audit",
        "scan_mode": "offline_simulation",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "assets_scanned": len(inventory),
        "asset_inventory": inventory,
        "summary": generate_risk_summary(findings),
        "findings": prioritize_findings(findings)
    }

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_path
