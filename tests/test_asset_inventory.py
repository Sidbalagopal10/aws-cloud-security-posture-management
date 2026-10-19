import json

from scanner.report_generator import generate_json_report


def sample_buckets():
    return [
        {"name": "insecure-bucket"},
        {"name": "secure-bucket"}
    ]


def sample_findings():
    return [
        {
            "bucket": "insecure-bucket",
            "severity": "HIGH",
            "issue": "Public access protection incomplete",
            "recommendation": "Review public access settings"
        }
    ]


def test_inventory_includes_all_buckets(tmp_path):
    output = tmp_path / "inventory_report.json"

    generate_json_report(
        sample_findings(),
        output_path=output,
        buckets=sample_buckets()
    )

    with output.open(encoding="utf-8") as file:
        report = json.load(file)

    assert report["assets_scanned"] == 2
    assert len(report["asset_inventory"]) == 2


def test_secure_bucket_in_inventory(tmp_path):
    output = tmp_path / "inventory_report.json"

    generate_json_report(
        sample_findings(),
        output_path=output,
        buckets=sample_buckets()
    )

    with output.open(encoding="utf-8") as file:
        report = json.load(file)

    secure = next(
        asset for asset in report["asset_inventory"]
        if asset["bucket"] == "secure-bucket"
    )

    assert secure["status"] == "NO_FINDINGS"
    assert secure["total_findings"] == 0
    assert secure["risk_score"] == 0


def test_insecure_bucket_risk_score(tmp_path):
    output = tmp_path / "inventory_report.json"

    generate_json_report(
        sample_findings(),
        output_path=output,
        buckets=sample_buckets()
    )

    with output.open(encoding="utf-8") as file:
        report = json.load(file)

    insecure = next(
        asset for asset in report["asset_inventory"]
        if asset["bucket"] == "insecure-bucket"
    )

    assert insecure["status"] == "FINDINGS"
    assert insecure["total_findings"] == 1
    assert insecure["risk_score"] == 7


def test_empty_inventory(tmp_path):
    output = tmp_path / "empty_report.json"

    generate_json_report(
        [],
        output_path=output,
        buckets=[]
    )

    with output.open(encoding="utf-8") as file:
        report = json.load(file)

    assert report["assets_scanned"] == 0
    assert report["asset_inventory"] == []
    assert report["summary"]["total_findings"] == 0
