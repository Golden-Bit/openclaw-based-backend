from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class UploadOut(BaseModel):
    """Rappresentazione standard di un file caricato (record DB + puntatore MinIO).

    NB:
    - download_url: endpoint BFF (controllato, richiede auth)
    - public_url: URL diretta MinIO (stabile). È 'pubblica' solo se la tua infra/bucket policy la rende accessibile.
    - presigned_get_url: URL firmata temporanea (download diretto senza passare dal BFF), opt-in.
    """

    upload_id: uuid.UUID = Field(description="ID del file")
    bucket: str
    object_key: str

    filename: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None

    metadata: dict[str, Any] | None = None
    tags: list[str] | None = None

    status: str
    is_deleted: bool

    created_at: datetime
    updated_at: datetime

    # Links
    download_url: str = Field(description="Endpoint BFF per scaricare lo stesso oggetto")
    public_url: str | None = Field(default=None, description="URL diretta (stabile) verso MinIO (se raggiungibile)")
    presigned_get_url: str | None = Field(default=None, description="URL presigned GET (temporanea)")
    presigned_get_expires_at: datetime | None = Field(default=None, description="Scadenza della presigned_get_url")


class UploadListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[UploadOut]


class UploadCreateResponse(UploadOut):
    """Risposta per create upload (caricamento già completato sul server)."""


class UploadCreateBase64Request(BaseModel):
    filename: str = Field(description="Nome file")
    mime_type: str | None = Field(default=None, description="MIME type")
    content_base64: str = Field(description="Contenuto base64 (senza data: prefix)")

    metadata: dict[str, Any] | None = Field(default=None, description="Metadati JSON")
    tags: list[str] | None = Field(default=None, description="Tag")


class UploadPresignRequest(BaseModel):
    filename: str = Field(description="Nome file")
    mime_type: str | None = Field(default=None, description="MIME type")
    size_bytes: int | None = Field(default=None, description="Dimensione in bytes (opzionale)")

    metadata: dict[str, Any] | None = Field(default=None, description="Metadati JSON")
    tags: list[str] | None = Field(default=None, description="Tag")


class UploadPresignResponse(BaseModel):
    upload_id: uuid.UUID = Field(description="ID upload")
    bucket: str
    object_key: str

    put_url: str = Field(description="Presigned PUT URL")
    get_url: str = Field(description="Presigned GET URL")
    public_url: str = Field(description="URL diretta (stabile), se raggiungibile dalla rete del client")

    created_at: datetime


class UploadLinksResponse(BaseModel):
    upload_id: uuid.UUID
    download_url: str

    public_url: str
    presigned_get_url: str
    presigned_get_expires_at: datetime

    presigned_put_url: str | None = None
    presigned_put_expires_at: datetime | None = None


class UploadUpdateRequest(BaseModel):
    filename: str | None = Field(default=None, description="Rinomina logica (non cambia object_key)")
    mime_type: str | None = Field(default=None, description="Aggiorna MIME type (solo DB)")

    metadata: dict[str, Any] | None = Field(default=None, description="Sostituisce i metadata")
    tags: list[str] | None = Field(default=None, description="Sostituisce i tag")

    status: str | None = Field(default=None, description="created|uploaded|failed|deleted (solo admin/debug)")
