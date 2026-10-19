import json
from pathlib import Path

import pandas as pd
import streamlit as st


REPORT_PATH = (
    Path(__file__).resolve().parents[1]
    / "reports"
    / "s3_security_report.json"
)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

st.set_page_config(
    page_title="AWS Cloud Security Posture Management",
    page_icon="🛡️",
    layout="wide"
)


def load_report():
    if not REPORT_PATH.exists():
        return None

    with REPORT_PATH.open(encoding="utf-8") as file:
        return json.load(file)


report = load_report()

st.title("AWS Cloud Security Posture Management")
st.caption(
    "Enterprise-style S3 Security Auditing | "
    "Offline Simulation"
)

if report is None:
    st.error(
        "Security report not found. "
        "Run: python -m scanner.s3_audit"
    )
    st.stop()

summary = report["summary"]
findings = report["findings"]
inventory = report.get("asset_inventory", [])

st.info(
    "Demo mode: Findings are generated from simulated "
    "S3 configurations, not live AWS resources."
)


# --------------------------------------------------
# Security Overview
# --------------------------------------------------

st.subheader("Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric(
    "Assets Scanned",
    report.get("assets_scanned", len(inventory))
)
col2.metric("Total Findings", summary["total_findings"])
col3.metric("High Severity", summary["high"])
col4.metric("Medium Severity", summary["medium"])
col5.metric("Aggregate Risk Score", summary["risk_score"])

st.caption(
    "Risk score is a custom weighted sum of findings, "
    "not a standardized risk rating."
)

st.divider()


# --------------------------------------------------
# Severity Distribution
# --------------------------------------------------

st.subheader("Findings by Severity")

severity_data = pd.DataFrame({
    "Severity": SEVERITIES,
    "Count": [
        summary["critical"],
        summary["high"],
        summary["medium"],
        summary["low"]
    ]
})

st.bar_chart(severity_data.set_index("Severity"))

st.divider()


# --------------------------------------------------
# Complete Asset Inventory
# --------------------------------------------------

st.subheader("S3 Asset Inventory")

if inventory:
    inventory_df = pd.DataFrame(inventory)

    inventory_df = inventory_df.rename(columns={
        "bucket": "Bucket",
        "status": "Status",
        "total_findings": "Total Findings",
        "risk_score": "Risk Score"
    })

    inventory_df = inventory_df.sort_values(
        ["Risk Score", "Bucket"],
        ascending=[False, True]
    )

    st.dataframe(
        inventory_df,
        use_container_width=True,
        hide_index=True
    )

    assets_with_findings = sum(
        asset["status"] == "FINDINGS"
        for asset in inventory
    )

    assets_without_findings = sum(
        asset["status"] == "NO_FINDINGS"
        for asset in inventory
    )

    inv_col1, inv_col2 = st.columns(2)

    inv_col1.metric(
        "Buckets With Findings",
        assets_with_findings
    )

    inv_col2.metric(
        "Buckets Without Findings",
        assets_without_findings
    )

    st.caption(
        "NO_FINDINGS means no violations of the "
        "implemented audit rules were detected. "
        "It does not guarantee that a bucket is secure."
    )
else:
    st.warning(
        "Asset inventory unavailable. "
        "Regenerate the security report."
    )

st.divider()


# --------------------------------------------------
# Interactive Security Findings
# --------------------------------------------------

st.subheader("Security Findings")

if findings:
    findings_df = pd.DataFrame(findings)

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        selected_severities = st.multiselect(
            "Filter by Severity",
            options=SEVERITIES,
            default=SEVERITIES
        )

    with filter_col2:
        bucket_options = sorted(
            asset["bucket"] for asset in inventory
        ) if inventory else sorted(
            findings_df["bucket"].unique()
        )

        selected_buckets = st.multiselect(
            "Filter by S3 Bucket",
            options=bucket_options,
            default=bucket_options
        )

    filtered_findings = findings_df[
        findings_df["severity"].isin(selected_severities)
        & findings_df["bucket"].isin(selected_buckets)
    ]

    st.write(
        f"Showing {len(filtered_findings)} "
        f"of {len(findings_df)} findings"
    )

    st.dataframe(
        filtered_findings,
        use_container_width=True,
        hide_index=True
    )

else:
    filtered_findings = pd.DataFrame(
        columns=[
            "bucket", "severity",
            "issue", "recommendation"
        ]
    )

    st.success("No security findings detected.")

st.divider()


# --------------------------------------------------
# Filtered Remediation Recommendations
# --------------------------------------------------

st.subheader("Remediation Recommendations")

if not filtered_findings.empty:
    for finding in filtered_findings.to_dict("records"):
        with st.expander(
            f"[{finding['severity']}] "
            f"{finding['bucket']} — {finding['issue']}"
        ):
            st.write(
                "**Affected Bucket:**",
                finding["bucket"]
            )
            st.write(
                "**Severity:**",
                finding["severity"]
            )
            st.write(
                "**Issue:**",
                finding["issue"]
            )
            st.write(
                "**Recommendation:**",
                finding["recommendation"]
            )
else:
    st.info(
        "No remediation recommendations match "
        "the selected filters."
    )

st.divider()


# --------------------------------------------------
# Download Security Reports
# --------------------------------------------------

st.subheader("Download Security Reports")

download_col1, download_col2, download_col3 = st.columns(3)

with download_col1:
    st.download_button(
        "Download Full JSON Report",
        data=json.dumps(report, indent=4),
        file_name="aws_cspm_security_report.json",
        mime="application/json",
        use_container_width=True
    )

with download_col2:
    st.download_button(
        "Download Filtered CSV Findings",
        data=filtered_findings.to_csv(index=False),
        file_name="aws_cspm_filtered_findings.csv",
        mime="text/csv",
        use_container_width=True
    )

with download_col3:
    inventory_csv = (
        inventory_df.to_csv(index=False)
        if inventory
        else pd.DataFrame().to_csv(index=False)
    )

    st.download_button(
        "Download Asset Inventory CSV",
        data=inventory_csv,
        file_name="aws_cspm_asset_inventory.csv",
        mime="text/csv",
        use_container_width=True
    )

st.divider()


# --------------------------------------------------
# Report Metadata
# --------------------------------------------------

st.caption(
    f"Report generated: {report['generated_at']} | "
    f"Scan mode: {report['scan_mode']}"
)
