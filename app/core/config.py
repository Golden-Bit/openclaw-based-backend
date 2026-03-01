"""Configurazione applicativa.

Tutte le impostazioni sono lette da variabili d'ambiente (supporto .env via uvicorn).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = Field(default="OpenClaw BFF", alias="APP_NAME")
    app_env: str = Field(default="local", alias="APP_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    cors_allow_origins: str = Field(default="*", alias="CORS_ALLOW_ORIGINS")

    # DB
    database_url: str = Field(default="postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/openclaw_bff", alias="DATABASE_URL")
    db_echo: bool = Field(default=False, alias="DB_ECHO")

    # MinIO
    minio_endpoint: str = Field(default="127.0.0.1:9000", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(default="minioadmin", alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(default="minioadmin", alias="MINIO_SECRET_KEY")
    minio_secure: bool = Field(default=False, alias="MINIO_SECURE")
    minio_bucket: str = Field(default="openclaw-bff", alias="MINIO_BUCKET")
    minio_region: str = Field(default="us-east-1", alias="MINIO_REGION")
    minio_public_base_url: str | None = Field(default=None, alias="MINIO_PUBLIC_BASE_URL")

    # OpenClaw
    openclaw_http_base: str = Field(default="http://127.0.0.1:3434", alias="OPENCLAW_HTTP_BASE")
    openclaw_ws_url: str = Field(default="ws://127.0.0.1:3434/ws", alias="OPENCLAW_WS_URL")
    openclaw_bearer_token: str | None = Field(default=None, alias="OPENCLAW_BEARER_TOKEN")
    openclaw_default_agent_id: str = Field(default="main", alias="OPENCLAW_DEFAULT_AGENT_ID")
    # OpenClaw client identity (schema-valid)
    openclaw_client_id: str = Field(default="gateway-client", alias="OPENCLAW_CLIENT_ID")
    openclaw_client_mode: str = Field(default="backend", alias="OPENCLAW_CLIENT_MODE")
    # Authz
    openclaw_role: str = Field(default="operator", alias="OPENCLAW_ROLE")
    openclaw_scopes: str = Field(default="operator.read,operator.write", alias="OPENCLAW_SCOPES")
    # Device identity persistence
    openclaw_state_dir: str | None = Field(default=None, alias="OPENCLAW_STATE_DIR")
    openclaw_identity_file: str | None = Field(default=None, alias="OPENCLAW_IDENTITY_FILE")
    openclaw_use_device_token: bool = Field(default=True, alias="OPENCLAW_USE_DEVICE_TOKEN")
    # WS timeouts
    openclaw_ws_connect_timeout: float = Field(default=10.0, alias="OPENCLAW_WS_CONNECT_TIMEOUT")
    openclaw_ws_rpc_timeout: float = Field(default=20.0, alias="OPENCLAW_WS_RPC_TIMEOUT")
    openclaw_ws_challenge_timeout: float = Field(default=2.0, alias="OPENCLAW_WS_CHALLENGE_TIMEOUT")

    # Keycloak
    keycloak_enabled: bool = Field(default=False, alias="KEYCLOAK_ENABLED")
    keycloak_issuer: str | None = Field(default=None, alias="KEYCLOAK_ISSUER")
    keycloak_jwks_url: str | None = Field(default=None, alias="KEYCLOAK_JWKS_URL")
    keycloak_audience: str | None = Field(default=None, alias="KEYCLOAK_AUDIENCE")
    keycloak_verify_aud: bool = Field(default=True, alias="KEYCLOAK_VERIFY_AUD")
    keycloak_verify_iss: bool = Field(default=True, alias="KEYCLOAK_VERIFY_ISS")

    dev_user_id: str = Field(default="dev-user", alias="DEV_USER_ID")

    # Behavior
    allow_raw_openclaw_session_key: bool = Field(default=False, alias="ALLOW_RAW_OPENCLAW_SESSION_KEY")
    persist_streamed_messages: bool = Field(default=True, alias="PERSIST_STREAMED_MESSAGES")

    # Uploads
    upload_max_bytes: int = Field(default=10_000_000, alias="UPLOAD_MAX_BYTES")  # 10MB
    upload_presign_put_expires_seconds: int = Field(default=900, alias="UPLOAD_PRESIGN_PUT_EXPIRES_SECONDS")
    upload_presign_get_expires_seconds: int = Field(default=3600, alias="UPLOAD_PRESIGN_GET_EXPIRES_SECONDS")


settings = Settings()  # singleton
