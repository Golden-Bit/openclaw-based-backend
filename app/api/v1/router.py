from fastapi import APIRouter

from app.api.v1.endpoints import health, conversations, messages, uploads, tools

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(conversations.router, tags=["Conversations"])
api_router.include_router(messages.router, tags=["Messages"])
api_router.include_router(uploads.router, tags=["Uploads"])
api_router.include_router(tools.router, tags=["Tools"])
