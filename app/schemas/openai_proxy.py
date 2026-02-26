from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class OpenAIProxyMeta(BaseModel):
    """Metadati extra supportati dal BFF (non standard OpenAI).

    - `conversation_id`: forza una conversazione esistente.
    - `create_if_missing`: se true, crea conversazione se non esiste.

    Nota: per massima compatibilità, questi campi si passano tramite header `x-bff-*`
    oppure come `metadata` nei payload.
    """

    conversation_id: Optional[str] = Field(default=None, description="UUID conversazione")
    create_if_missing: bool = Field(default=True)


class OpenAIProxyRequest(BaseModel):
    """Body generico per endpoint OpenAI-compatible.

    Lo schema reale è quello OpenAI (Responses/ChatCompletions). Qui lo trattiamo come JSON.
    """

    payload: Dict[str, Any] = Field(description="Payload JSON OpenAI-like")


class OpenAIProxyResponse(BaseModel):
    payload: Dict[str, Any]
