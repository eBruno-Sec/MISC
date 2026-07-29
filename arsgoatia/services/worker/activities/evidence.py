from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from temporalio import activity


@dataclass
class StoreEvidenceParams:
    engagement_id: str
    tenant_id: str
    action_id: str
    kind: str
    media_type: str
    payload: bytes
    metadata: dict[str, str] = field(default_factory=dict)


@activity.defn
async def store_evidence(params: StoreEvidenceParams) -> str:
    digest = hashlib.sha256(params.payload).hexdigest()
    object_key = (
        f"evidence/{params.tenant_id}/{params.engagement_id}"
        f"/{params.action_id}/{digest}"
    )

    import miniopy_async  # noqa: PLC0415

    client = miniopy_async.Minio(
        "minio:9000",
        access_key="arsgoatia",
        secret_key="arsgoatia",
        secure=False,
    )
    bucket = "arsgoatia-evidence"
    if not await client.bucket_exists(bucket):
        await client.make_bucket(bucket)

    from io import BytesIO  # noqa: PLC0415

    await client.put_object(
        bucket,
        object_key,
        BytesIO(params.payload),
        length=len(params.payload),
        content_type=params.media_type,
        metadata={
            "x-amz-meta-engagement-id": params.engagement_id,
            "x-amz-meta-tenant-id": params.tenant_id,
            "x-amz-meta-action-id": params.action_id,
            "x-amz-meta-kind": params.kind,
            "x-amz-meta-sha256": digest,
            **params.metadata,
        },
    )
    activity.logger.info(
        "Evidence stored",
        extra={"object_key": object_key, "digest": digest},
    )
    return f"sha256:{digest}"


@activity.defn
async def verify_evidence(evidence_id: str) -> bool:
    if not evidence_id.startswith("sha256:"):
        return False

    expected_digest = evidence_id.removeprefix("sha256:")

    import miniopy_async  # noqa: PLC0415

    client = miniopy_async.Minio(
        "minio:9000",
        access_key="arsgoatia",
        secret_key="arsgoatia",
        secure=False,
    )
    bucket = "arsgoatia-evidence"

    objects = []
    async for obj in client.list_objects(bucket, recursive=True):
        if obj.object_name and obj.object_name.endswith(f"/{expected_digest}"):
            objects.append(obj)
            break

    if not objects:
        activity.logger.warning(
            "Evidence not found", extra={"evidence_id": evidence_id}
        )
        return False

    response = await client.get_object(bucket, objects[0].object_name)
    try:
        data = await response.read()
    finally:
        response.close()
        await response.release()

    actual_digest = hashlib.sha256(data).hexdigest()
    verified = actual_digest == expected_digest
    if not verified:
        activity.logger.error(
            "Evidence integrity check failed",
            extra={
                "evidence_id": evidence_id,
                "expected": expected_digest,
                "actual": actual_digest,
            },
        )
    return verified
