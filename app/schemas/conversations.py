from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ConversationCreateRequest(BaseModel):
    """Crea una nuova conversazione (public).

    `agent_id` è opzionale: se non fornito, si usa `OPENCLAW_DEFAULT_AGENT_ID`.
    """

    title: Optional[str] = Field(default=None, description="Titolo conversazione (opzionale)", examples=["Supporto tecnico"])
    agent_id: Optional[str] = Field(default=None, description="Agent OpenClaw da usare (opzionale)", examples=["main"])


class ConversationResponse(BaseModel):
    conversation_id: uuid.UUID = Field(description="ID pubblico della conversazione")
    title: Optional[str] = Field(default=None, description="Titolo")
    agent_id: Optional[str] = Field(default=None, description="Agent selezionato")
    created_at: datetime
    updated_at: datetime


class ConversationListItem(ConversationResponse):
    last_message_at: Optional[datetime] = Field(default=None, description="Timestamp ultimo messaggio (se disponibile)")


class ConversationPatchRequest(BaseModel):
    title: Optional[str] = Field(default=None, description="Nuovo titolo")
    agent_id: Optional[str] = Field(default=None, description="Nuovo agent_id")


class DeleteResponse(BaseModel):
    deleted: bool = Field(description="True se l'operazione è riuscita")
