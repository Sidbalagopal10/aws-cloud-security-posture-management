from scanner.s3_audit import audit_bucket


def secure_bucket():
    return {
        "name": "company-secure-data",
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


def test_secure_bucket():
    bucket = secure_bucket()
    findings = audit_bucket(bucket)

    assert len(findings) == 0


def test_insecure_bucket():
    bucket = secure_bucket()

    bucket["public_access_block"] = {
        key: False
        for key in bucket["public_access_block"]
    }

    bucket["versioning"] = "Disabled"
    bucket["logging"] = False

    findings = audit_bucket(bucket)

    assert len(findings) == 3


def test_public_access_detection():
    bucket = secure_bucket()
    bucket["public_access_block"]["BlockPublicPolicy"] = False

    findings = audit_bucket(bucket)

    assert any(
        finding["severity"] == "HIGH"
        and finding["issue"] == "S3 Block Public Access incomplete"
        for finding in findings
    )


def test_versioning_detection():
    bucket = secure_bucket()
    bucket["versioning"] = "Disabled"

    findings = audit_bucket(bucket)

    assert any(
        finding["severity"] == "MEDIUM"
        and finding["issue"] == "S3 versioning not enabled"
        for finding in findings
    )


def test_sse_s3_encryption_policy():
    bucket = secure_bucket()
    bucket["encryption"] = "AES256"

    findings = audit_bucket(bucket)

    assert any(
        finding["issue"] ==
        "Bucket does not meet KMS encryption policy"
        for finding in findings
    )


def test_missing_encryption_configuration():
    bucket = secure_bucket()
    bucket["encryption"] = None

    findings = audit_bucket(bucket)

    assert any(
        finding["issue"] ==
        "Bucket does not meet KMS encryption policy"
        for finding in findings
    )
