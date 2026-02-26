from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ToolsCatalogResponse(BaseModel):
    """Catalogo tool disponibili (best-effort)."""

    tools: List[Dict[str, Any]] = Field(description="Lista tool (shape dipende dal gateway)")
    source: str = Field(description="Origine dati: ws|fallback")


class ToolInvokeRequest(BaseModel):
    tool: str = Field(description="Nome tool", examples=["browser"])
    action: Optional[str] = Field(default=None, description="Azione (se prevista dal tool)")
    args: Dict[str, Any] = Field(default_factory=dict, description="Argomenti")


class ToolInvokeResponse(BaseModel):
    openclaw_result: Dict[str, Any]


class ToolResultRequest(BaseModel):
    """Ritorna a OpenResponses l'output di una function/tool call."""

    call_id: str = Field(description="ID chiamata tool (call_id)")
    output: Any = Field(description="Output del tool")
