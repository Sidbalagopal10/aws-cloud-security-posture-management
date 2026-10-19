import json

from scanner.report_generator import generate_json_report


def sample_findings():
    return [
        {
            "bucket": "test-bucket",
            "severity": "LOW",
            "issue": "Logging disabled",
            "recommendation": "Enable logging"
        },
        {
            "bucket": "test-bucket",
            "severity": "HIGH",
            "issue": "Public access protection incomplete",
            "recommendation": "Review public access settings"
        }
    ]


def test_report_file_creation(tmp_path):
    output = tmp_path / "security_report.json"

    result = generate_json_report(
        sample_findings(),
        output_path=output
    )

    assert result == output
    assert output.exists()


def test_report_metadata(tmp_path):
    output = tmp_path / "security_report.json"

    generate_json_report(
        sample_findings(),
        output_path=output
    )

    with output.open(encoding="utf-8") as file:
        report = json.load(file)

    assert report["report_type"] == "AWS S3 Security Audit"
    assert report["scan_mode"] == "offline_simulation"
    assert "generated_at" in report


def test_report_risk_summary(tmp_path):
    output = tmp_path / "security_report.json"

    generate_json_report(
        sample_findings(),
        output_path=output
    )

    with output.open(encoding="utf-8") as file:
        report = json.load(file)

    summary = report["summary"]

    assert summary["total_findings"] == 2
    assert summary["high"] == 1
    assert summary["low"] == 1
    assert summary["risk_score"] == 8


def test_report_prioritization(tmp_path):
    output = tmp_path / "security_report.json"

    generate_json_report(
        sample_findings(),
        output_path=output
    )

    with output.open(encoding="utf-8") as file:
        report = json.load(file)

    severities = [
        finding["severity"]
        for finding in report["findings"]
    ]

    assert severities == ["HIGH", "LOW"]
