from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from temporalio import activity

MINIO_ENDPOINT = os.getenv("ARSGOATIA_MINIO_ENDPOINT", "localhost:9100")
MINIO_ACCESS_KEY = os.getenv("ARSGOATIA_MINIO_ACCESS_KEY", "arsgoatia")
MINIO_SECRET_KEY = os.getenv("ARSGOATIA_MINIO_SECRET_KEY", "arsgoatia-dev-secret")
MINIO_BUCKET = os.getenv("ARSGOATIA_MINIO_BUCKET", "arsgoatia-evidence")


def _get_client():
    import miniopy_async  # noqa: PLC0415

    return miniopy_async.Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )


@dataclass
class StoreEvidenceParams:
    engagement_id: str
    tenant_id: str
    action_id: str
    kind: str
    media_type: str
    payload: bytes
    metadata: dict[str, str] = field(default_factory=dict)


async def _persist_evidence_row(
    *,
    tenant_id: str,
    engagement_id: str,
    action_id: str,
    kind: str,
    digest: str,
    size_bytes: int,
    media_type: str,
    storage_uri: str,
) -> None:
    """Write an evidence.evidence row so the API/UI can list it.

    Best-effort: DB errors are logged and swallowed so a broken control-plane
    never blocks the deterministic workflow from finishing.
    """
    from sqlalchemy import text  # noqa: PLC0415

    from packages.persistence import get_session_factory, set_tenant  # noqa: PLC0415

    try:
        factory = get_session_factory()
        async with factory() as session:
            async with session.begin():
                await set_tenant(session, tenant_id)
                # Coerce non-UUID action_id (recon uses labels) into a stable UUID
                # via SHA-1 namespace so the FK-less action_id column is still typed.
                try:
                    action_uuid = uuid.UUID(action_id)
                except ValueError:
                    action_uuid = uuid.uuid5(uuid.NAMESPACE_URL, action_id)
                await session.execute(
                    text(
                        """
                        INSERT INTO evidence.evidence
                            (id, tenant_id, engagement_id, action_id, kind, digest,
                             size_bytes, media_type, storage_uri, sensitivity, created_at)
                        VALUES
                            (:id, :tid, :eid, :aid, :kind, :dg, :size, :mt, :uri, 'restricted', :now)
                        ON CONFLICT (digest) DO NOTHING
                        """
                    ),
                    {
                        "id": uuid.uuid4(),
                        "tid": tenant_id,
                        "eid": engagement_id,
                        "aid": str(action_uuid),
                        "kind": kind,
                        "dg": digest,
                        "size": size_bytes,
                        "mt": media_type,
                        "uri": storage_uri,
                        "now": datetime.now(timezone.utc),
                    },
                )
    except Exception as exc:
        activity.logger.warning(f"evidence-row persist failed: {exc}")


@activity.defn
async def store_evidence(params: StoreEvidenceParams) -> str:
    digest = hashlib.sha256(params.payload).hexdigest()
    object_key = f"evidence/{params.tenant_id}/{params.engagement_id}/{params.action_id}/{digest}"

    client = _get_client()
    if not await client.bucket_exists(MINIO_BUCKET):
        await client.make_bucket(MINIO_BUCKET)

    from io import BytesIO  # noqa: PLC0415

    await client.put_object(
        MINIO_BUCKET,
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

    await _persist_evidence_row(
        tenant_id=params.tenant_id,
        engagement_id=params.engagement_id,
        action_id=params.action_id,
        kind=params.kind,
        digest=f"sha256:{digest}",
        size_bytes=len(params.payload),
        media_type=params.media_type,
        storage_uri=f"minio://{MINIO_BUCKET}/{object_key}",
    )

    return f"sha256:{digest}"


@activity.defn
async def verify_evidence(evidence_id: str) -> bool:
    if not evidence_id.startswith("sha256:"):
        return False

    expected_digest = evidence_id.removeprefix("sha256:")
    client = _get_client()

    objects = []
    async for obj in client.list_objects(MINIO_BUCKET, recursive=True):
        if obj.object_name and obj.object_name.endswith(f"/{expected_digest}"):
            objects.append(obj)
            break

    if not objects:
        activity.logger.warning("Evidence not found", extra={"evidence_id": evidence_id})
        return False

    response = await client.get_object(MINIO_BUCKET, objects[0].object_name)
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
