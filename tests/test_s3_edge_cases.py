from scanner.s3_audit import audit_bucket


def secure_bucket():
    return {
        "name": "test-secure-bucket",
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        },
        "encryption": "aws:kms",
        "versioning": "Enabled",
        "logging": True
    }


def test_missing_public_access_setting():
    bucket = secure_bucket()
    del bucket["public_access_block"]["BlockPublicPolicy"]

    findings = audit_bucket(bucket)

    assert any(
        finding["issue"] == "S3 Block Public Access incomplete"
        for finding in findings
    )


def test_empty_public_access_configuration():
    bucket = secure_bucket()
    bucket["public_access_block"] = {}

    findings = audit_bucket(bucket)

    assert any(
        finding["severity"] == "HIGH"
        for finding in findings
    )


def test_sse_s3_is_policy_finding():
    bucket = secure_bucket()
    bucket["encryption"] = "AES256"

    findings = audit_bucket(bucket)

    assert len(findings) == 1
    assert findings[0]["issue"] == (
        "Bucket does not meet KMS encryption policy"
    )
    assert "SSE-S3" in findings[0]["recommendation"]
