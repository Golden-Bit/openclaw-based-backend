from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import AuthenticatedUser, get_current_user
from app.db.models import Conversation, Message
from app.db.session import get_db
from app.schemas.conversations import (
    ConversationCreateRequest,
    ConversationListItem,
    ConversationPatchRequest,
    ConversationResponse,
    DeleteResponse,
)

router = APIRouter(prefix="/conversations")


def _make_session_key(user_id: str, conv_id: uuid.UUID) -> str:
    # sessionKey non deve essere guessable (evita di esporre raw userId)
    # Qui includiamo solo un prefix + uuid. L'ownership è gestita dal DB.
    return f"bff:{conv_id}"


@router.post(
    "",
    summary="Crea una conversazione",
    response_model=ConversationResponse,
)
async def create_conversation(
    body: ConversationCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConversationResponse:
    conv_id = uuid.uuid4()
    session_key = _make_session_key(user.user_id, conv_id)

    conv = Conversation(
        id=conv_id,
        user_id=user.user_id,
        title=body.title,
        agent_id=body.agent_id or settings.openclaw_default_agent_id,
        openclaw_session_key=session_key,
    )
    db.add(conv)
    await db.commit()
    await db.refresh(conv)

    return ConversationResponse(
        conversation_id=conv.id,
        title=conv.title,
        agent_id=conv.agent_id,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
    )


@router.get(
    "",
    summary="Lista conversazioni",
    response_model=List[ConversationListItem],
)
async def list_conversations(
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
) -> List[ConversationListItem]:
    stmt = (
        select(Conversation)
        .where(Conversation.user_id == user.user_id, Conversation.is_deleted.is_(False))
        .order_by(Conversation.updated_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()

    # last_message_at (best-effort): query max created_at per conv
    out: List[ConversationListItem] = []
    for conv in rows:
        last_stmt = (
            select(Message.created_at)
            .where(Message.conversation_id == conv.id)
            .order_by(Message.created_at.desc())
            .limit(1)
        )
        last = (await db.execute(last_stmt)).scalars().first()
        out.append(
            ConversationListItem(
                conversation_id=conv.id,
                title=conv.title,
                agent_id=conv.agent_id,
                created_at=conv.created_at,
                updated_at=conv.updated_at,
                last_message_at=last,
            )
        )
    return out


@router.get(
    "/{conversation_id}",
    summary="Dettaglio conversazione",
    response_model=ConversationResponse,
)
async def get_conversation(
    conversation_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConversationResponse:
    conv = (await db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.user_id == user.user_id,
            Conversation.is_deleted.is_(False),
        )
    )).scalars().first()

    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    return ConversationResponse(
        conversation_id=conv.id,
        title=conv.title,
        agent_id=conv.agent_id,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
    )


@router.patch(
    "/{conversation_id}",
    summary="Aggiorna metadati conversazione",
    response_model=ConversationResponse,
)
async def patch_conversation(
    conversation_id: uuid.UUID,
    body: ConversationPatchRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ConversationResponse:
    conv = (await db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.user_id == user.user_id,
            Conversation.is_deleted.is_(False),
        )
    )).scalars().first()

    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    if body.title is not None:
        conv.title = body.title
    if body.agent_id is not None:
        conv.agent_id = body.agent_id

    conv.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(conv)

    # (Opzionale) potresti chiamare sessions.patch via WS.

    return ConversationResponse(
        conversation_id=conv.id,
        title=conv.title,
        agent_id=conv.agent_id,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
    )


@router.delete(
    "/{conversation_id}",
    summary="Elimina conversazione (soft delete)",
    response_model=DeleteResponse,
)
async def delete_conversation(
    conversation_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DeleteResponse:
    res = await db.execute(
        update(Conversation)
        .where(
            Conversation.id == conversation_id,
            Conversation.user_id == user.user_id,
            Conversation.is_deleted.is_(False),
        )
        .values(is_deleted=True)
        .returning(Conversation.id)
    )
    deleted_id = res.scalar_one_or_none()
    if not deleted_id:
        raise HTTPException(status_code=404, detail="Conversation not found")
    await db.commit()
    return DeleteResponse(deleted=True)
