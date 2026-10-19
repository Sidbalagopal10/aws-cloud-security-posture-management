REQUIRED_PUBLIC_ACCESS_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets"
)

ALLOWED_ENCRYPTION = (
    "AES256",
    "aws:kms"
)

ALLOWED_VERSIONING = (
    "Enabled",
    "Disabled",
    "Suspended"
)


def validate_bucket(bucket):
    if not isinstance(bucket, dict):
        raise ValueError("Bucket configuration must be an object")

    name = bucket.get("name")

    if not isinstance(name, str) or not name.strip():
        raise ValueError("Bucket name must be a non-empty string")

    public_access = bucket.get("public_access_block")

    if not isinstance(public_access, dict):
        raise ValueError(
            f"{name}: public_access_block must be an object"
        )

    for setting in REQUIRED_PUBLIC_ACCESS_SETTINGS:
        if setting not in public_access:
            raise ValueError(
                f"{name}: missing public access setting: {setting}"
            )

        if not isinstance(public_access[setting], bool):
            raise ValueError(
                f"{name}: {setting} must be a Boolean"
            )

    encryption = bucket.get("encryption")

    if encryption not in ALLOWED_ENCRYPTION:
        raise ValueError(
            f"{name}: unsupported encryption configuration"
        )

    versioning = bucket.get("versioning")

    if versioning not in ALLOWED_VERSIONING:
        raise ValueError(
            f"{name}: invalid versioning configuration"
        )

    if not isinstance(bucket.get("logging"), bool):
        raise ValueError(
            f"{name}: logging must be a Boolean"
        )

    return True
