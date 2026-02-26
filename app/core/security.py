"""Autenticazione e autorizzazione.

- In modalità DEV (KEYCLOAK_ENABLED=false):
  - nessuna verifica JWT
  - userId = header `X-Debug-User` se presente, altrimenti `DEV_USER_ID`

- In modalità Keycloak (KEYCLOAK_ENABLED=true):
  - richiede `Authorization: Bearer <JWT>`
  - valida firma con JWKS
  - opzionalmente valida iss/aud

Il BFF usa `sub` come user_id canonico.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, HTTPException, Header
from jose import jwt

from app.core.config import settings


@dataclass
class AuthenticatedUser:
    user_id: str
    claims: Dict[str, Any]


class JWKSCache:
    """Cache semplice per JWKS (evita fetch ad ogni request)."""

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._jwks: Optional[Dict[str, Any]] = None
        self._expires_at: float = 0

    async def get(self) -> Dict[str, Any]:
        now = time.time()
        if self._jwks is not None and now < self._expires_at:
            return self._jwks

        if not settings.keycloak_jwks_url:
            raise RuntimeError("KEYCLOAK_JWKS_URL non configurato")

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(settings.keycloak_jwks_url)
            resp.raise_for_status()
            self._jwks = resp.json()
            self._expires_at = now + self.ttl_seconds
            return self._jwks


jwks_cache = JWKSCache()


async def get_current_user(
    authorization: str | None = Header(default=None, description="Bearer JWT (solo se KEYCLOAK_ENABLED=true)"),
    x_debug_user: str | None = Header(default=None, alias="X-Debug-User", description="UserId forzato solo in DEV"),
) -> AuthenticatedUser:
    """Dependency: restituisce l'utente autenticato."""

    if not settings.keycloak_enabled:
        user_id = x_debug_user or settings.dev_user_id
        return AuthenticatedUser(user_id=user_id, claims={"mode": "dev"})

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = authorization.split(" ", 1)[1].strip()
    jwks = await jwks_cache.get()

    options = {
        "verify_aud": bool(settings.keycloak_verify_aud),
        "verify_iss": bool(settings.keycloak_verify_iss),
    }

    try:
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256", "RS384", "RS512"],
            audience=settings.keycloak_audience if settings.keycloak_verify_aud else None,
            issuer=settings.keycloak_issuer if settings.keycloak_verify_iss else None,
            options=options,
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing 'sub'")

    return AuthenticatedUser(user_id=sub, claims=claims)
