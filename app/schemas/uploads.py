from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CreateUploadRequest(BaseModel):
    """Richiede un presigned URL per caricare un file su MinIO."""

    filename: str = Field(description="Nome file")
    mime_type: Optional[str] = Field(default=None, description="MIME type")
    size_bytes: Optional[int] = Field(default=None, description="Dimensione in bytes (opzionale)")


class CreateUploadResponse(BaseModel):
    upload_id: uuid.UUID = Field(description="ID upload")
    bucket: str
    object_key: str

    put_url: str = Field(description="Presigned PUT URL (il FE carica qui)")
    get_url: str = Field(description="Presigned GET URL (accesso temporaneo)")
    public_url: str = Field(description="URL 'pubblica' (da passare a OpenClaw se raggiungibile)")

    created_at: datetime
