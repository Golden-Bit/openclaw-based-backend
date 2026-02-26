from __future__ import annotations

# noqa: F401
from app.db import models  # importa i modelli per registrare metadata

from sqlalchemy.ext.asyncio import AsyncEngine

from app.db.base import Base


async def init_db(engine: AsyncEngine) -> None:
    """Crea le tabelle se non esistono.

    In produzione è preferibile usare migrazioni Alembic.
    Per un MVP locale questa strategia è pratica e riduce complessità.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
