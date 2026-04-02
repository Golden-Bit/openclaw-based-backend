from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class KnowledgeTreeItem(BaseModel):
    path: str
    name: str
    kind: str = Field(description="file|folder")
    size_bytes: Optional[int] = None
    updated_at: Optional[datetime] = None


class KnowledgeTreeResponse(BaseModel):
    agent_id: str
    workspace: str
    root: str
    path: str
    items: list[KnowledgeTreeItem] = Field(default_factory=list)


class KnowledgeFolderCreateRequest(BaseModel):
    path: str = Field(description="Path relativa cartella da creare")


class KnowledgeFolderMoveRequest(BaseModel):
    from_path: str
    to_path: str


class KnowledgeFolderDeleteResponse(BaseModel):
    deleted: bool
    agent_id: str
    path: str


class KnowledgeFolderMutationResponse(BaseModel):
    ok: bool
    agent_id: str
    path: str


class KnowledgeFileBase64UploadRequest(BaseModel):
    path: str = Field(default="", description="Path relativa cartella destinazione")
    filename: str
    content_base64: str
    mime_type: Optional[str] = None
    overwrite: bool = False


class KnowledgeFilePutRequest(BaseModel):
    path: str = Field(description="Path relativa file")
    content_base64: str
    mime_type: Optional[str] = None
    upsert: bool = False


class KnowledgeFileMutationResponse(BaseModel):
    ok: bool
    agent_id: str
    path: str
    filename: str
    size_bytes: int
    sha256: str
    mime_type: str
    updated_at: datetime


class KnowledgeFileDeleteResponse(BaseModel):
    deleted: bool
    agent_id: str
    path: str


class KnowledgeFileContentResponse(BaseModel):
    agent_id: str
    path: str
    filename: str
    size_bytes: int
    mime_type: str
    updated_at: datetime
    content_text: Optional[str] = None
    content_base64: Optional[str] = None


class KnowledgeReindexResponse(BaseModel):
    accepted: bool
    agent_id: str
    mode: str
    details: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)
