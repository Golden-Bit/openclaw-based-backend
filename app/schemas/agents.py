from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AgentSummary(BaseModel):
    """Rappresentazione normalizzata di un agente OpenClaw."""

    agent_id: str = Field(description="Identificativo agente")
    name: Optional[str] = Field(default=None, description="Nome agente")
    workspace: Optional[str] = Field(default=None, description="Workspace associata")
    model: Optional[str] = Field(default=None, description="Model primary")
    model_fallbacks: Optional[List[str]] = Field(default=None, description="Model fallback configurati")
    is_default: bool = Field(default=False, description="True se è l'agente di default")


class AgentListResponse(BaseModel):
    """Lista agenti dal gateway OpenClaw."""

    default_agent_id: str = Field(description="Default agent id dal gateway")
    main_key: Optional[str] = Field(default=None, description="Main key sessionale gateway")
    scope: Optional[str] = Field(default=None, description="Scope sessionale gateway")
    items: List[AgentSummary] = Field(default_factory=list, description="Agenti disponibili")


class AgentDetailResponse(AgentSummary):
    """Dettaglio agente: summary + identity + file metadata (best-effort)."""

    identity: Optional[Dict[str, Any]] = Field(default=None, description="Identity agente (best-effort)")
    files: Optional[List[Dict[str, Any]]] = Field(default=None, description="File bootstrap/workspace (opzionale)")
    warnings: List[str] = Field(default_factory=list, description="Warning non bloccanti (es. metodo non supportato)")


class AgentCreateRequest(BaseModel):
    """Campi necessari/ammessi su OpenClaw agents.create."""

    name: str = Field(description="Nome nuovo agente")
    workspace: str = Field(description="Workspace nuovo agente")
    emoji: Optional[str] = Field(default=None, description="Emoji agente")
    avatar: Optional[str] = Field(default=None, description="Avatar agente")


class AgentCreateResponse(BaseModel):
    created: bool = Field(description="True se create richiesto con successo")
    agent_id: Optional[str] = Field(default=None, description="Identificativo agente creato")
    name: Optional[str] = Field(default=None, description="Nome agente creato")
    workspace: Optional[str] = Field(default=None, description="Workspace agente creato")
    openclaw_result: Optional[Dict[str, Any]] = Field(default=None, description="Payload upstream (best-effort)")


class AgentUpdateRequest(BaseModel):
    """Campi aggiornabili su OpenClaw agents.update."""

    name: Optional[str] = Field(default=None, description="Nuovo nome agente")
    workspace: Optional[str] = Field(default=None, description="Nuova workspace")
    model: Optional[str] = Field(default=None, description="Nuovo model")
    avatar: Optional[str] = Field(default=None, description="Avatar (URL/stringa)")


class AgentUpdateResponse(BaseModel):
    updated: bool = Field(description="True se update richiesto con successo")
    agent_id: str = Field(description="Agente aggiornato")
    openclaw_result: Optional[Dict[str, Any]] = Field(default=None, description="Payload upstream (best-effort)")


class AgentDeleteResponse(BaseModel):
    deleted: bool = Field(description="True se delete richiesto con successo")
    agent_id: str = Field(description="Agente eliminato")
    removed_bindings: Optional[int] = Field(default=None, description="Binding rimossi lato gateway")
    openclaw_result: Optional[Dict[str, Any]] = Field(default=None, description="Payload upstream (best-effort)")
