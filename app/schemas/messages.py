from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Attachment(BaseModel):
    """Attachment per messaggio (compatibile con OpenResponses via URL)."""

    type: str = Field(description="Tipo attachment (es. input_image, input_file)", examples=["input_file"])
    url: str = Field(description="URL raggiungibile (es. MinIO public URL)")
    mime_type: Optional[str] = Field(default=None, description="MIME type (opzionale)")
    filename: Optional[str] = Field(default=None, description="Nome file (opzionale)")


class MessageItem(BaseModel):
    id: uuid.UUID
    role: str = Field(description="Ruolo: user|assistant|system|tool")
    content: Optional[str] = Field(default=None, description="Testo del messaggio")
    raw: Optional[Dict[str, Any]] = Field(default=None, description="Payload raw (debug)")
    run_id: Optional[str] = Field(default=None, description="RunId (se disponibile)")
    seq: Optional[int] = Field(default=None, description="Sequenza evento (se disponibile)")
    created_at: datetime


class SendMessageRequest(BaseModel):
    """Invia un messaggio (non streaming)."""

    content: str = Field(description="Testo utente", examples=["Ciao, aiutami con..."])
    attachments: Optional[List[Attachment]] = Field(default=None, description="Allegati (opzionale)")
    client_message_id: Optional[str] = Field(default=None, description="ID client per idempotenza lato FE")


class SendMessageResponse(BaseModel):
    """Risposta non-stream."""

    conversation_id: uuid.UUID
    assistant_text: str = Field(description="Testo finale assistente")
    openclaw_response: Dict[str, Any] = Field(description="Risposta OpenResponses grezza")


class StreamMessageRequest(BaseModel):
    """Invia un messaggio in streaming SSE."""

    content: str = Field(description="Testo utente")
    attachments: Optional[List[Attachment]] = Field(default=None)
    client_message_id: Optional[str] = Field(default=None)


class AbortRequest(BaseModel):
    run_id: Optional[str] = Field(default=None, description="RunId (opzionale). Se assente: abort per sessione.")


class AbortResponse(BaseModel):
    aborted: bool = Field(description="True se abort richiesto")
    openclaw_result: Optional[Dict[str, Any]] = Field(default=None, description="Payload WS (se disponibile)")


class InjectRequest(BaseModel):
    content: str = Field(description="Messaggio da iniettare nel thread")
    label: Optional[str] = Field(default=None, description="Etichetta opzionale")


class InjectResponse(BaseModel):
    injected: bool
    openclaw_result: Optional[Dict[str, Any]] = None
