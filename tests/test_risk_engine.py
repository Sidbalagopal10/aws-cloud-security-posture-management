from scanner.risk_engine import (
    calculate_risk_score,
    prioritize_findings,
    generate_risk_summary
)


def sample_findings():
    return [
        {"severity": "LOW", "issue": "Logging disabled"},
        {"severity": "HIGH", "issue": "Public access protection"},
        {"severity": "MEDIUM", "issue": "Versioning disabled"},
        {"severity": "MEDIUM", "issue": "Encryption policy"}
    ]


def test_risk_score():
    assert calculate_risk_score(sample_findings()) == 16


def test_prioritization():
    prioritized = prioritize_findings(sample_findings())

    assert [f["severity"] for f in prioritized] == [
        "HIGH", "MEDIUM", "MEDIUM", "LOW"
    ]


def test_risk_summary():
    summary = generate_risk_summary(sample_findings())

    assert summary["total_findings"] == 4
    assert summary["critical"] == 0
    assert summary["high"] == 1
    assert summary["medium"] == 2
    assert summary["low"] == 1
    assert summary["risk_score"] == 16


def test_empty_findings():
    summary = generate_risk_summary([])

    assert summary["total_findings"] == 0
    assert summary["risk_score"] == 0
