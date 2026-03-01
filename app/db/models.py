from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKey, Text, Boolean, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Conversation(Base):
    """Conversazione FE (public id) -> OpenClaw sessionKey (privato)."""

    __tablename__ = "conversations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(200), index=True)

    title: Mapped[str | None] = mapped_column(String(300), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(200), nullable=True)

    openclaw_session_key: Mapped[str] = mapped_column(String(500), unique=True, index=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    messages: Mapped[list["Message"]] = relationship(back_populates="conversation", cascade="all, delete-orphan")


class Message(Base):
    """Messaggio persistito in DB (per list/render e caching).

    Nota: La sorgente di verità può essere OpenClaw (chat.history). Il DB serve per:
    - mapping ownership
    - caching UI
    - storage di stream (opzionale)
    """

    __tablename__ = "messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"), index=True)

    role: Mapped[str] = mapped_column(String(50), index=True)  # user|assistant|system|tool
    content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Raw payload per debug o rendering avanzato
    raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Run tracking (quando disponibile)
    run_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    seq: Mapped[int | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    conversation: Mapped[Conversation] = relationship(back_populates="messages")


class Upload(Base):
    """File caricati dall'utente.

    Il backend genera presigned URL MinIO; il FE carica direttamente.
    L'oggetto poi può essere referenziato come URL negli attachments OpenResponses.
    """

    __tablename__ = "uploads"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(200), index=True)

    bucket: Mapped[str] = mapped_column(String(200))
    object_key: Mapped[str] = mapped_column(String(800), unique=True, index=True)

    filename: Mapped[str | None] = mapped_column(String(500), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(nullable=True)

    # Metadati applicativi (ricercabili lato DB).
    # Nota: i metadata *S3* non sono aggiornabili in-place: per questo li teniamo in DB.
    metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    status: Mapped[str] = mapped_column(String(50), default="created")  # created|uploaded|failed

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class ConversationAlias(Base):
    """Mapping per compatibilità OpenAI/OpenResponses.

    Alcune UI (es. OpenWebUI) usano il campo `user` come identificativo utente.
    Noi lo usiamo come *alias* per individuare/creare una conversazione.

    Vincolo: (user_id, alias) unico.
    """

    __tablename__ = "conversation_aliases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(200), index=True)

    alias: Mapped[str] = mapped_column(String(300))
    conversation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "alias", name="uq_user_alias"),
        Index("ix_alias_user", "user_id", "alias"),
    )
