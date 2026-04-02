from fastapi import APIRouter

from app.api.v1.endpoints.agents import router as agents_router
from app.api.v1.endpoints.conversations import router as conversations_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.messages import router as messages_router
from app.api.v1.endpoints.tools import router as tools_router
from app.api.v1.endpoints.uploads import router as uploads_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health_router, tags=["Health"])
api_router.include_router(conversations_router, tags=["Conversations"])
api_router.include_router(messages_router, tags=["Messages"])
api_router.include_router(uploads_router, tags=["Uploads"])
api_router.include_router(tools_router, tags=["Tools"])
api_router.include_router(agents_router, tags=["Agents"])
