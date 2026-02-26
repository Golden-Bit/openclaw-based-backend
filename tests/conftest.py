import os
import pytest
import httpx

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
KEYCLOAK_ENABLED = os.getenv("KEYCLOAK_ENABLED", "false").lower() == "true"

KC_BASE = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080")
KC_REALM = os.getenv("KEYCLOAK_REALM", "openclaw-bff")
KC_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "openclaw-bff-api")
KC_TEST_USER = os.getenv("KEYCLOAK_TEST_USER", "testuser")
KC_TEST_PASS = os.getenv("KEYCLOAK_TEST_PASSWORD", "testpassword")

DEBUG_USER = os.getenv("DEV_USER_ID", "dev-user")


def _get_token() -> str:
    # Password grant (Direct Access Grants must be enabled on the client)
    url = f"{KC_BASE}/realms/{KC_REALM}/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": KC_CLIENT_ID,
        "username": KC_TEST_USER,
        "password": KC_TEST_PASS,
    }
    r = httpx.post(url, data=data, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers() -> dict:
    if not KEYCLOAK_ENABLED:
        return {"X-Debug-User": DEBUG_USER}
    token = _get_token()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def client(auth_headers):
    with httpx.Client(base_url=BASE_URL, headers=auth_headers, timeout=30) as c:
        yield c


def is_openclaw_reachable() -> bool:
    # Best-effort reachability check: call backend gateway info (should hit OpenClaw)
    try:
        r = httpx.get(f"{BASE_URL}/api/v1/gateway/info", headers=auth_headers(), timeout=3)
        return r.status_code < 500
    except Exception:
        return False
