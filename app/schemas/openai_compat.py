from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, ConfigDict


# =============================================================================
# OpenAI-compatible schemas (subset + extra fields allowed)
# =============================================================================

class ModelInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    object: str = "model"
    owned_by: str = "openclaw"


class ModelsListResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    object: str = "list"
    data: List[ModelInfo]


# -------------------------
# Chat Completions
# -------------------------

class ChatMessage(BaseModel):
    """Minimal OpenAI message param.

    We keep it permissive (extra allowed) because OpenAI supports many message
    variants (developer/system/user/assistant/tool, multimodal content, tool calls...).
    """
    model_config = ConfigDict(extra="allow")
    role: str
    content: Any = None
    name: Optional[str] = None


class ChatCompletionsRequest(BaseModel):
    """OpenAI-compatible /v1/chat/completions request (subset).

    See OpenAI API reference for full shape. Extra fields are accepted and forwarded.
    """
    model_config = ConfigDict(extra="allow")

    model: str = Field(..., description='Model id. For OpenClaw agents: "openclaw:<agentId>" or "agent:<agentId>" or "openclaw".')
    messages: List[ChatMessage] = Field(..., description="Conversation messages.")
    stream: bool = Field(default=False, description="If true, return SSE stream of chat.completion.chunk events.")
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None
    stop: Optional[Union[str, List[str]]] = None
    n: Optional[int] = None
    user: Optional[str] = Field(default=None, description="Stable session routing (OpenClaw derives session key from this).")


# -------------------------
# Completions (legacy)
# -------------------------

class CompletionsRequest(BaseModel):
    """OpenAI-compatible /v1/completions request (subset).

    This BFF implements completions by translating to /v1/chat/completions upstream.
    Extra fields are accepted but may be ignored in translation.
    """
    model_config = ConfigDict(extra="allow")

    model: str
    prompt: Union[str, List[str]] = Field(..., description="Prompt string or list of prompts.")
    stream: bool = False
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None
    stop: Optional[Union[str, List[str]]] = None
    n: Optional[int] = None
    user: Optional[str] = None


# -------------------------
# OpenResponses (/v1/responses)
# -------------------------

class OpenResponsesRequest(BaseModel):
    """OpenResponses-compatible /v1/responses request (subset).

    OpenClaw supports: input, instructions, tools, tool_choice, stream, max_output_tokens, user.
    Extra fields are accepted and forwarded.
    """
    model_config = ConfigDict(extra="allow")

    model: Optional[str] = Field(default=None, description='Model id or agent selector e.g. "openclaw:main".')
    input: Any = Field(..., description="String or list of OpenResponses items.")
    instructions: Optional[str] = None
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Any] = None
    stream: bool = False
    max_output_tokens: Optional[int] = None
    user: Optional[str] = None
