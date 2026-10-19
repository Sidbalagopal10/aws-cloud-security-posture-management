import pytest

from scanner.validator import validate_bucket


def valid_bucket():
    return {
        "name": "company-test-bucket",
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


def test_valid_bucket():
    assert validate_bucket(valid_bucket()) is True


def test_missing_bucket_name():
    bucket = valid_bucket()
    del bucket["name"]

    with pytest.raises(ValueError):
        validate_bucket(bucket)


def test_invalid_public_access_type():
    bucket = valid_bucket()
    bucket["public_access_block"]["BlockPublicAcls"] = "false"

    with pytest.raises(ValueError):
        validate_bucket(bucket)


def test_missing_public_access_setting():
    bucket = valid_bucket()
    del bucket["public_access_block"]["BlockPublicPolicy"]

    with pytest.raises(ValueError):
        validate_bucket(bucket)


def test_invalid_encryption():
    bucket = valid_bucket()
    bucket["encryption"] = "unknown"

    with pytest.raises(ValueError):
        validate_bucket(bucket)


def test_invalid_versioning():
    bucket = valid_bucket()
    bucket["versioning"] = "Sometimes"

    with pytest.raises(ValueError):
        validate_bucket(bucket)


def test_invalid_logging():
    bucket = valid_bucket()
    bucket["logging"] = "enabled"

    with pytest.raises(ValueError):
        validate_bucket(bucket)
