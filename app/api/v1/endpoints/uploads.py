from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.minio_client import (
    ensure_bucket,
    get_minio_client,
    presigned_get_url,
    presigned_put_url,
    public_object_url,
)
from app.core.security import AuthenticatedUser, get_current_user
from app.db.models import Upload
from app.db.session import get_db
from app.schemas.uploads import CreateUploadRequest, CreateUploadResponse
from app.core.config import settings

router = APIRouter()


@router.post(
    "/uploads",
    summary="Crea un upload (presigned URL MinIO)",
    response_model=CreateUploadResponse,
)
async def create_upload(
    body: CreateUploadRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CreateUploadResponse:
    """Genera presigned URLs per upload su MinIO.

    Flusso:
    1) FE chiama questo endpoint
    2) BFF crea record in DB
    3) BFF genera `put_url` (upload diretto)
    4) FE fa PUT su `put_url`
    5) FE usa `public_url` negli attachments verso OpenClaw

    Nota: `public_url` funziona solo se MinIO è esposto/raggiungibile dal Gateway.
    """

    client = get_minio_client()
    ensure_bucket(client, settings.minio_bucket)

    upload_id = uuid.uuid4()
    object_key = f"{user.user_id}/{upload_id}/{body.filename}"

    put_url = presigned_put_url(client, settings.minio_bucket, object_key)
    get_url = presigned_get_url(client, settings.minio_bucket, object_key)
    pub_url = public_object_url(settings.minio_bucket, object_key)

    rec = Upload(
        id=upload_id,
        user_id=user.user_id,
        bucket=settings.minio_bucket,
        object_key=object_key,
        filename=body.filename,
        mime_type=body.mime_type,
        size_bytes=body.size_bytes,
        status="created",
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    return CreateUploadResponse(
        upload_id=rec.id,
        bucket=rec.bucket,
        object_key=rec.object_key,
        put_url=put_url,
        get_url=get_url,
        public_url=pub_url,
        created_at=rec.created_at,
    )
