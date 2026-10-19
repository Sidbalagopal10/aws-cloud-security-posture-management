import json

import pytest

from scanner import s3_audit


def valid_bucket(name="test-bucket"):
    return {
        "name": name,
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


def write_fixture(tmp_path, monkeypatch, data):
    fixture = tmp_path / "s3_buckets.json"
    fixture.write_text(
        json.dumps(data),
        encoding="utf-8"
    )

    monkeypatch.setattr(
        s3_audit,
        "FIXTURE_PATH",
        fixture
    )


def test_valid_fixture_loads(tmp_path, monkeypatch):
    data = {
        "buckets": [
            valid_bucket("bucket-one"),
            valid_bucket("bucket-two")
        ]
    }

    write_fixture(tmp_path, monkeypatch, data)

    buckets = s3_audit.load_buckets()

    assert len(buckets) == 2
    assert buckets[0]["name"] == "bucket-one"


def test_invalid_configuration_rejected(
    tmp_path, monkeypatch
):
    bucket = valid_bucket()
    bucket["logging"] = "false"

    write_fixture(
        tmp_path,
        monkeypatch,
        {"buckets": [bucket]}
    )

    with pytest.raises(ValueError, match="logging"):
        s3_audit.load_buckets()


def test_duplicate_bucket_rejected(
    tmp_path, monkeypatch
):
    write_fixture(
        tmp_path,
        monkeypatch,
        {
            "buckets": [
                valid_bucket("duplicate-bucket"),
                valid_bucket("duplicate-bucket")
            ]
        }
    )

    with pytest.raises(
        ValueError,
        match="Duplicate bucket name"
    ):
        s3_audit.load_buckets()
