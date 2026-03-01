from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.minio_client import (
    ensure_bucket,
    get_minio_client,
    presigned_get_url,
    presigned_put_url,
    public_object_url,
    put_bytes,
    get_object_stream,
    remove_object,
)
from app.core.security import AuthenticatedUser, get_current_user
from app.db.models import Upload
from app.db.session import get_db
from app.schemas.uploads import (
    UploadCreateBase64Request,
    UploadCreateResponse,
    UploadLinksResponse,
    UploadListResponse,
    UploadOut,
    UploadPresignRequest,
    UploadPresignResponse,
    UploadUpdateRequest,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize_filename(name: str) -> str:
    """Evita path traversal e normalizza il filename."""
    name = name.strip().replace("\\", "/")
    name = os.path.basename(name)
    return name or "file"


def _make_object_key(user_id: str, upload_id: uuid.UUID, filename: str) -> str:
    filename = _sanitize_filename(filename)
    return f"{user_id}/{upload_id}/{filename}"


def _download_url(upload_id: uuid.UUID) -> str:
    return f"/api/v1/uploads/{upload_id}/download"


def _to_out(
    rec: Upload,
    *,
    include_public_url: bool = True,
    include_presigned_get: bool = False,
    presigned_get_expires_seconds: int | None = None,
    minio_client=None,
) -> UploadOut:
    """Converte DB model -> schema.

    - public_url: URL diretta (stabile) calcolata da MINIO_PUBLIC_BASE_URL o MINIO_ENDPOINT.
      Nota: è *davvero pubblica* solo se l'infrastruttura/bucket policy lo consentono.
    - presigned_get_url: URL firmata, temporanea (download diretto senza passare dal BFF).
      Generarla ha un costo (firma) e, su liste, può diventare pesante: per questo è opt-in.
    """
    out = UploadOut(
        upload_id=rec.id,
        bucket=rec.bucket,
        object_key=rec.object_key,
        filename=rec.filename,
        mime_type=rec.mime_type,
        size_bytes=rec.size_bytes,
        sha256=rec.sha256,
        metadata=rec.metadata,
        tags=rec.tags,
        status=rec.status,
        is_deleted=rec.is_deleted,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
        download_url=_download_url(rec.id),
    )

    if include_public_url:
        out.public_url = public_object_url(rec.bucket, rec.object_key)

    if include_presigned_get:
        client = minio_client or get_minio_client()
        exp = presigned_get_expires_seconds or settings.upload_presign_get_expires_seconds
        out.presigned_get_url = presigned_get_url(client, rec.bucket, rec.object_key, expires_seconds=exp)
        out.presigned_get_expires_at = datetime.utcnow() + timedelta(seconds=exp)

    return out


async def _get_owned_upload_or_404(db: AsyncSession, user_id: str, upload_id: uuid.UUID) -> Upload:
    stmt = select(Upload).where(Upload.id == upload_id, Upload.user_id == user_id)
    res = await db.execute(stmt)
    rec = res.scalar_one_or_none()
    if rec is None:
        raise HTTPException(status_code=404, detail="Upload not found")
    return rec


def _parse_json_or_400(value: str | None, field_name: str) -> dict[str, Any] | None:
    if value is None or value == "":
        return None
    try:
        data = json.loads(value)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Invalid JSON for {field_name}: {e}")
    if data is None:
        return None
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail=f"{field_name} must be a JSON object")
    return data


def _parse_tags(value: str | None) -> list[str] | None:
    if value is None or value.strip() == "":
        return None
    tags = [t.strip() for t in value.split(",") if t.strip()]
    return tags or None


def _assert_size_ok(size: int) -> None:
    if size > settings.upload_max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large: {size} bytes (max {settings.upload_max_bytes})",
        )


# ---------------------------------------------------------------------------
# 0) Links endpoint: ottieni URL diretta + presigned GET (e opzionale PUT)
# ---------------------------------------------------------------------------


@router.get(
    "/uploads/{upload_id}/links",
    summary="Ritorna i link di accesso (download BFF, direct/public, presigned GET, opzionale PUT)",
    response_model=UploadLinksResponse,
)
async def get_upload_links(
    upload_id: uuid.UUID,
    expires_seconds: int = Query(default=3600, ge=60, le=7 * 24 * 3600, description="TTL dei presigned (GET/PUT)"),
    include_put: bool = Query(default=False, description="Se true ritorna anche un presigned PUT (attenzione: permette overwrite)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadLinksResponse:
    rec = await _get_owned_upload_or_404(db, user.user_id, upload_id)
    if rec.is_deleted:
        raise HTTPException(status_code=410, detail="Upload deleted")

    client = get_minio_client()
    get_url = presigned_get_url(client, rec.bucket, rec.object_key, expires_seconds=expires_seconds)
    exp_at = datetime.utcnow() + timedelta(seconds=expires_seconds)

    put_url = None
    if include_put:
        put_url = presigned_put_url(client, rec.bucket, rec.object_key, expires_seconds=expires_seconds)

    return UploadLinksResponse(
        upload_id=rec.id,
        download_url=_download_url(rec.id),
        public_url=public_object_url(rec.bucket, rec.object_key),
        presigned_get_url=get_url,
        presigned_get_expires_at=exp_at,
        presigned_put_url=put_url,
        presigned_put_expires_at=(exp_at if include_put else None),
    )


# ---------------------------------------------------------------------------
# 1) Upload diretto (server-side) - BYTES
# ---------------------------------------------------------------------------


@router.post(
    "/uploads",
    summary="Upload diretto (multipart/form-data)",
    response_model=UploadCreateResponse,
)
async def upload_file_multipart(
    file: UploadFile = File(..., description="File da caricare"),
    metadata_json: str | None = Form(default=None, description="Metadati JSON (stringa)"),
    tags: str | None = Form(default=None, description="Tag separati da virgola"),
    include_presigned_get: bool = Form(default=False, description="Se true include presigned_get_url nella risposta"),
    presigned_get_expires_seconds: int | None = Form(default=None, description="TTL presigned GET (secondi)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadCreateResponse:
    client = get_minio_client()
    ensure_bucket(client, settings.minio_bucket)

    filename = _sanitize_filename(file.filename or "file")
    mime_type = file.content_type

    data = await file.read()
    _assert_size_ok(len(data))

    sha = hashlib.sha256(data).hexdigest()
    upload_id = uuid.uuid4()
    object_key = _make_object_key(user.user_id, upload_id, filename)

    metadata = _parse_json_or_400(metadata_json, "metadata_json")
    tag_list = _parse_tags(tags)

    put_bytes(client, settings.minio_bucket, object_key, data, content_type=mime_type, metadata=None)

    rec = Upload(
        id=upload_id,
        user_id=user.user_id,
        bucket=settings.minio_bucket,
        object_key=object_key,
        filename=filename,
        mime_type=mime_type,
        size_bytes=len(data),
        sha256=sha,
        metadata=metadata,
        tags=tag_list,
        status="uploaded",
        is_deleted=False,
    )

    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    out = _to_out(
        rec,
        include_public_url=True,
        include_presigned_get=include_presigned_get,
        presigned_get_expires_seconds=presigned_get_expires_seconds,
        minio_client=client,
    )
    return UploadCreateResponse(**out.model_dump())


@router.post(
    "/uploads/bytes",
    summary="Upload diretto (application/octet-stream)",
    response_model=UploadCreateResponse,
)
async def upload_file_bytes(
    body: bytes,
    filename: str = Query(..., description="Nome file"),
    mime_type: str | None = Query(default=None, description="MIME type"),
    tags: str | None = Query(default=None, description="Tag separati da virgola"),
    metadata_json: str | None = Query(default=None, description="Metadati JSON (stringa)"),
    include_presigned_get: bool = Query(default=False, description="Se true include presigned_get_url nella risposta"),
    presigned_get_expires_seconds: int | None = Query(default=None, description="TTL presigned GET (secondi)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadCreateResponse:
    _assert_size_ok(len(body))

    client = get_minio_client()
    ensure_bucket(client, settings.minio_bucket)

    filename_s = _sanitize_filename(filename)
    sha = hashlib.sha256(body).hexdigest()
    upload_id = uuid.uuid4()
    object_key = _make_object_key(user.user_id, upload_id, filename_s)

    metadata = _parse_json_or_400(metadata_json, "metadata_json")
    tag_list = _parse_tags(tags)

    put_bytes(client, settings.minio_bucket, object_key, body, content_type=mime_type, metadata=None)

    rec = Upload(
        id=upload_id,
        user_id=user.user_id,
        bucket=settings.minio_bucket,
        object_key=object_key,
        filename=filename_s,
        mime_type=mime_type,
        size_bytes=len(body),
        sha256=sha,
        metadata=metadata,
        tags=tag_list,
        status="uploaded",
        is_deleted=False,
    )

    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    out = _to_out(
        rec,
        include_public_url=True,
        include_presigned_get=include_presigned_get,
        presigned_get_expires_seconds=presigned_get_expires_seconds,
        minio_client=client,
    )
    return UploadCreateResponse(**out.model_dump())


# ---------------------------------------------------------------------------
# 2) Upload base64
# ---------------------------------------------------------------------------


@router.post(
    "/uploads/base64",
    summary="Upload base64 (JSON)",
    response_model=UploadCreateResponse,
)
async def upload_file_base64(
    body: UploadCreateBase64Request,
    include_presigned_get: bool = Query(default=False, description="Se true include presigned_get_url nella risposta"),
    presigned_get_expires_seconds: int | None = Query(default=None, description="TTL presigned GET (secondi)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadCreateResponse:
    try:
        raw = base64.b64decode(body.content_base64, validate=True)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Invalid base64: {e}")

    _assert_size_ok(len(raw))

    client = get_minio_client()
    ensure_bucket(client, settings.minio_bucket)

    filename = _sanitize_filename(body.filename)
    sha = hashlib.sha256(raw).hexdigest()
    upload_id = uuid.uuid4()
    object_key = _make_object_key(user.user_id, upload_id, filename)

    put_bytes(client, settings.minio_bucket, object_key, raw, content_type=body.mime_type, metadata=None)

    rec = Upload(
        id=upload_id,
        user_id=user.user_id,
        bucket=settings.minio_bucket,
        object_key=object_key,
        filename=filename,
        mime_type=body.mime_type,
        size_bytes=len(raw),
        sha256=sha,
        metadata=body.metadata,
        tags=body.tags,
        status="uploaded",
        is_deleted=False,
    )

    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    out = _to_out(
        rec,
        include_public_url=True,
        include_presigned_get=include_presigned_get,
        presigned_get_expires_seconds=presigned_get_expires_seconds,
        minio_client=client,
    )
    return UploadCreateResponse(**out.model_dump())


# ---------------------------------------------------------------------------
# 3) Presigned URLs (compatibilità col vecchio flusso)
# ---------------------------------------------------------------------------


@router.post(
    "/uploads/presign",
    summary="Crea un upload (presigned URL MinIO) [compatibilità]",
    response_model=UploadPresignResponse,
)
async def create_upload_presign(
    body: UploadPresignRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadPresignResponse:
    client = get_minio_client()
    ensure_bucket(client, settings.minio_bucket)

    upload_id = uuid.uuid4()
    object_key = _make_object_key(user.user_id, upload_id, body.filename)

    put_url = presigned_put_url(client, settings.minio_bucket, object_key, expires_seconds=settings.upload_presign_put_expires_seconds)
    get_url = presigned_get_url(client, settings.minio_bucket, object_key, expires_seconds=settings.upload_presign_get_expires_seconds)
    pub_url = public_object_url(settings.minio_bucket, object_key)

    rec = Upload(
        id=upload_id,
        user_id=user.user_id,
        bucket=settings.minio_bucket,
        object_key=object_key,
        filename=_sanitize_filename(body.filename),
        mime_type=body.mime_type,
        size_bytes=body.size_bytes,
        metadata=body.metadata,
        tags=body.tags,
        status="created",
        is_deleted=False,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    return UploadPresignResponse(
        upload_id=rec.id,
        bucket=rec.bucket,
        object_key=rec.object_key,
        put_url=put_url,
        get_url=get_url,
        public_url=pub_url,
        created_at=rec.created_at,
    )


# ---------------------------------------------------------------------------
# 4) List / Search
# ---------------------------------------------------------------------------


@router.get(
    "/uploads",
    summary="Lista/ricerca uploads",
    response_model=UploadListResponse,
)
async def list_uploads(
    q: str | None = Query(default=None, description="Ricerca substring su filename"),
    mime_type: str | None = Query(default=None, description="Filtro MIME type"),
    tag: str | None = Query(default=None, description="Filtro tag (singolo)"),
    metadata_contains: str | None = Query(default=None, description="JSON object: filtra metadata che contengono questi campi"),
    include_deleted: bool = Query(default=False),
    include_presigned_get: bool = Query(default=False, description="Se true include presigned_get_url per ogni item (può essere costoso)"),
    presigned_get_expires_seconds: int | None = Query(default=None, description="TTL presigned GET (secondi)"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadListResponse:
    meta_filter = _parse_json_or_400(metadata_contains, "metadata_contains")

    where = [Upload.user_id == user.user_id]
    if not include_deleted:
        where.append(Upload.is_deleted.is_(False))

    if q:
        where.append(Upload.filename.ilike(f"%{q}%"))
    if mime_type:
        where.append(Upload.mime_type == mime_type)
    if tag:
        where.append(Upload.tags.contains([tag]))
    if meta_filter:
        where.append(Upload.metadata.op("@>")(meta_filter))

    total_stmt = select(func.count()).select_from(select(Upload.id).where(*where).subquery())
    total_res = await db.execute(total_stmt)
    total = int(total_res.scalar_one())

    stmt = select(Upload).where(*where).order_by(Upload.created_at.desc()).limit(limit).offset(offset)
    res = await db.execute(stmt)
    rows = res.scalars().all()

    minio_client = get_minio_client() if include_presigned_get else None

    return UploadListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[
            _to_out(
                r,
                include_public_url=True,
                include_presigned_get=include_presigned_get,
                presigned_get_expires_seconds=presigned_get_expires_seconds,
                minio_client=minio_client,
            )
            for r in rows
        ],
    )


# ---------------------------------------------------------------------------
# 5) Read details
# ---------------------------------------------------------------------------


@router.get(
    "/uploads/{upload_id}",
    summary="Dettagli upload",
    response_model=UploadOut,
)
async def get_upload(
    upload_id: uuid.UUID,
    include_presigned_get: bool = Query(default=False, description="Se true include presigned_get_url"),
    presigned_get_expires_seconds: int | None = Query(default=None, description="TTL presigned GET (secondi)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadOut:
    rec = await _get_owned_upload_or_404(db, user.user_id, upload_id)
    minio_client = get_minio_client() if include_presigned_get else None
    return _to_out(
        rec,
        include_public_url=True,
        include_presigned_get=include_presigned_get,
        presigned_get_expires_seconds=presigned_get_expires_seconds,
        minio_client=minio_client,
    )


# ---------------------------------------------------------------------------
# 6) Download via BFF
# ---------------------------------------------------------------------------


@router.get(
    "/uploads/{upload_id}/download",
    summary="Download file (stream dal BFF)",
)
async def download_upload(
    upload_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rec = await _get_owned_upload_or_404(db, user.user_id, upload_id)
    if rec.is_deleted:
        raise HTTPException(status_code=410, detail="Upload deleted")

    client = get_minio_client()
    try:
        obj = get_object_stream(client, rec.bucket, rec.object_key)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=404, detail=f"Object not found in storage: {e}")

    def iterfile():
        try:
            while True:
                chunk = obj.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            try:
                obj.close()
            except Exception:
                pass

    filename = rec.filename or "file"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    return StreamingResponse(iterfile(), media_type=rec.mime_type or "application/octet-stream", headers=headers)


# ---------------------------------------------------------------------------
# 7) Update metadata (DB-only)
# ---------------------------------------------------------------------------


@router.patch(
    "/uploads/{upload_id}",
    summary="Aggiorna metadati file (DB-only)",
    response_model=UploadOut,
)
async def update_upload_metadata(
    upload_id: uuid.UUID,
    body: UploadUpdateRequest,
    include_presigned_get: bool = Query(default=False, description="Se true include presigned_get_url in risposta"),
    presigned_get_expires_seconds: int | None = Query(default=None, description="TTL presigned GET (secondi)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadOut:
    rec = await _get_owned_upload_or_404(db, user.user_id, upload_id)

    if body.filename is not None:
        rec.filename = _sanitize_filename(body.filename)
    if body.mime_type is not None:
        rec.mime_type = body.mime_type
    if body.metadata is not None:
        rec.metadata = body.metadata
    if body.tags is not None:
        rec.tags = body.tags
    if body.status is not None:
        rec.status = body.status

    rec.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(rec)

    minio_client = get_minio_client() if include_presigned_get else None
    return _to_out(
        rec,
        include_public_url=True,
        include_presigned_get=include_presigned_get,
        presigned_get_expires_seconds=presigned_get_expires_seconds,
        minio_client=minio_client,
    )


# ---------------------------------------------------------------------------
# 8) Update content (overwrite object)
# ---------------------------------------------------------------------------


@router.put(
    "/uploads/{upload_id}/content",
    summary="Sostituisce il contenuto (multipart/form-data)",
    response_model=UploadOut,
)
async def replace_upload_content_multipart(
    upload_id: uuid.UUID,
    file: UploadFile = File(..., description="Nuovo contenuto"),
    include_presigned_get: bool = Query(default=False, description="Se true include presigned_get_url in risposta"),
    presigned_get_expires_seconds: int | None = Query(default=None, description="TTL presigned GET (secondi)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadOut:
    rec = await _get_owned_upload_or_404(db, user.user_id, upload_id)
    if rec.is_deleted:
        raise HTTPException(status_code=410, detail="Upload deleted")

    data = await file.read()
    _assert_size_ok(len(data))
    sha = hashlib.sha256(data).hexdigest()

    client = get_minio_client()
    ensure_bucket(client, rec.bucket)

    put_bytes(client, rec.bucket, rec.object_key, data, content_type=file.content_type, metadata=None)

    rec.size_bytes = len(data)
    rec.sha256 = sha
    rec.mime_type = file.content_type
    rec.status = "uploaded"
    rec.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(rec)

    return _to_out(
        rec,
        include_public_url=True,
        include_presigned_get=include_presigned_get,
        presigned_get_expires_seconds=presigned_get_expires_seconds,
        minio_client=(client if include_presigned_get else None),
    )


@router.put(
    "/uploads/{upload_id}/content/base64",
    summary="Sostituisce il contenuto (base64 JSON)",
    response_model=UploadOut,
)
async def replace_upload_content_base64(
    upload_id: uuid.UUID,
    body: UploadCreateBase64Request,
    include_presigned_get: bool = Query(default=False, description="Se true include presigned_get_url in risposta"),
    presigned_get_expires_seconds: int | None = Query(default=None, description="TTL presigned GET (secondi)"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UploadOut:
    rec = await _get_owned_upload_or_404(db, user.user_id, upload_id)
    if rec.is_deleted:
        raise HTTPException(status_code=410, detail="Upload deleted")

    try:
        raw = base64.b64decode(body.content_base64, validate=True)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Invalid base64: {e}")

    _assert_size_ok(len(raw))
    sha = hashlib.sha256(raw).hexdigest()

    client = get_minio_client()
    ensure_bucket(client, rec.bucket)

    put_bytes(client, rec.bucket, rec.object_key, raw, content_type=body.mime_type, metadata=None)

    if body.filename:
        rec.filename = _sanitize_filename(body.filename)

    rec.size_bytes = len(raw)
    rec.sha256 = sha
    rec.mime_type = body.mime_type
    rec.status = "uploaded"
    rec.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(rec)

    return _to_out(
        rec,
        include_public_url=True,
        include_presigned_get=include_presigned_get,
        presigned_get_expires_seconds=presigned_get_expires_seconds,
        minio_client=(client if include_presigned_get else None),
    )


# ---------------------------------------------------------------------------
# 9) Delete
# ---------------------------------------------------------------------------


@router.delete(
    "/uploads/{upload_id}",
    summary="Elimina file (soft-delete DB + remove MinIO)",
)
async def delete_upload(
    upload_id: uuid.UUID,
    hard: bool = Query(default=False, description="Se true elimina anche il record DB"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rec = await _get_owned_upload_or_404(db, user.user_id, upload_id)

    client = get_minio_client()
    try:
        remove_object(client, rec.bucket, rec.object_key)
    except Exception:
        pass

    if hard:
        await db.delete(rec)
    else:
        rec.is_deleted = True
        rec.status = "deleted"
        rec.updated_at = datetime.utcnow()

    await db.commit()
    return {"ok": True, "upload_id": str(upload_id), "hard": hard}
