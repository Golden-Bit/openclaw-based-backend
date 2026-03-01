"""Client MinIO (S3-compatible).

Obiettivo: permettere al FE di caricare file direttamente su MinIO tramite presigned URL.
"""

from __future__ import annotations

import io
from datetime import timedelta

from minio import Minio
from minio.error import S3Error

from app.core.config import settings


def get_minio_client() -> Minio:
    return Minio(
        endpoint=settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
        region=settings.minio_region,
    )


def ensure_bucket(client: Minio, bucket: str) -> None:
    """Crea il bucket se non esiste."""
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
    except S3Error as e:
        # Se 409 (bucket already exists) ignoriamo.
        if getattr(e, "code", "") not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise


def presigned_put_url(client: Minio, bucket: str, object_key: str, expires_seconds: int = 900) -> str:
    return client.presigned_put_object(bucket, object_key, expires=timedelta(seconds=expires_seconds))


def presigned_get_url(client: Minio, bucket: str, object_key: str, expires_seconds: int = 3600) -> str:
    return client.presigned_get_object(bucket, object_key, expires=timedelta(seconds=expires_seconds))


def public_object_url(bucket: str, object_key: str) -> str:
    """Restituisce una URL 'pubblica' se MINIO_PUBLIC_BASE_URL è configurato.

    Utile quando il frontend deve passare a OpenClaw una URL raggiungibile.

    Esempio: MINIO_PUBLIC_BASE_URL=http://localhost:9000
    -> http://localhost:9000/<bucket>/<object_key>
    """
    if settings.minio_public_base_url:
        base = settings.minio_public_base_url.rstrip("/")
        return f"{base}/{bucket}/{object_key}"

    # Fallback: endpoint diretto (potrebbe non essere raggiungibile dal FE se in rete diversa)
    scheme = "https" if settings.minio_secure else "http"
    return f"{scheme}://{settings.minio_endpoint}/{bucket}/{object_key}"


def put_bytes(
    client: Minio,
    bucket: str,
    object_key: str,
    data: bytes,
    *,
    content_type: str | None = None,
    metadata: dict[str, str] | None = None,
) -> None:
    """Upload di bytes direttamente a MinIO."""

    bio = io.BytesIO(data)
    client.put_object(
        bucket,
        object_key,
        bio,
        length=len(data),
        content_type=content_type,
        metadata=metadata,
    )


def get_object_stream(client: Minio, bucket: str, object_key: str):
    """Ritorna lo stream dell'oggetto (response-like con .read/.close)."""
    return client.get_object(bucket, object_key)


def stat_object(client: Minio, bucket: str, object_key: str):
    return client.stat_object(bucket, object_key)


def remove_object(client: Minio, bucket: str, object_key: str) -> None:
    client.remove_object(bucket, object_key)
