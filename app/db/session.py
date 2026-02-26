from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.core.config import settings

engine = create_async_engine(settings.database_url, echo=settings.db_echo, future=True)

AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    """Dependency FastAPI: restituisce una sessione DB async."""
    async with AsyncSessionLocal() as session:
        yield session
