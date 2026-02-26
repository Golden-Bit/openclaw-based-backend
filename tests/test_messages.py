import pytest
import httpx
import os

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

def _openclaw_ok(headers):
    try:
        r = httpx.get(f"{BASE_URL}/api/v1/gateway/info", headers=headers, timeout=3)
        return r.status_code == 200
    except Exception:
        return False

@pytest.mark.skipif(True, reason="Enable this test when OpenClaw is running on host and the BFF is configured to reach it.")
def test_send_message_non_stream(client, auth_headers):
    # create conversation
    r = client.post("/api/v1/conversations", json={"title":"MsgTest", "agentId":"main"})
    cid = r.json()["conversationId"]

    # send message (requires OpenClaw)
    r = client.post(f"/api/v1/conversations/{cid}/messages", json={"content":"ciao", "clientMessageId":"m1"})
    assert r.status_code == 200
