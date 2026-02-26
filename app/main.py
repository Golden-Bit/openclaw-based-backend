from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.minio_client import ensure_bucket, get_minio_client
from app.core.openclaw_ws import OpenClawWSClient
from app.db.init_db import init_db
from app.db.session import engine

from app.api.v1.router import api_router
from app.api.openai_compat import router as openai_router

logger = logging.getLogger(__name__)


# Singleton WS client (riutilizzato da tutti gli endpoint)
_ws_client: OpenClawWSClient | None = None


def get_ws_client() -> OpenClawWSClient:
    global _ws_client
    if _ws_client is None:
        _ws_client = OpenClawWSClient(settings.openclaw_ws_url)
    return _ws_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Logging
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
    logger.info("Starting %s (%s)", settings.app_name, settings.app_env)

    # DB init
    await init_db(engine)
    logger.info("DB ready")

    # MinIO init
    try:
        mc = get_minio_client()
        ensure_bucket(mc, settings.minio_bucket)
        logger.info("MinIO bucket ensured: %s", settings.minio_bucket)
    except Exception as e:  # noqa: BLE001
        logger.warning("MinIO init failed (continuing): %s", e)

    # WS client is lazy; we don't force connect here.

    yield

    # Shutdown
    try:
        ws = get_ws_client()
        await ws.close()
    except Exception:
        pass

    await engine.dispose()
    logger.info("Shutdown complete")


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description=(
        "Backend for Frontend (BFF) per OpenClaw. "
        "Espone una Public REST API (/api/v1) per un frontend stile ChatGPT, "
        "più endpoint OpenAI-compatible (/v1/*) per integrazioni (es. OpenWebUI)."
    ),
    lifespan=lifespan,
)

# CORS
origins = [o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()] if settings.cors_allow_origins != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"] ,
)

# Routers
app.include_router(api_router)
app.include_router(openai_router)
