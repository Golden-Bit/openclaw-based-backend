import pytest
import os
import httpx

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

@pytest.mark.skipif(True, reason="Enable this test when OpenClaw is running and SSE proxy is configured.")
def test_streaming_sse(auth_headers):
    # Create conversation
    r = httpx.post(f"{BASE_URL}/api/v1/conversations", headers=auth_headers, json={"title":"SSE", "agentId":"main"}, timeout=10)
    r.raise_for_status()
    cid = r.json()["conversationId"]

    # Stream call
    with httpx.stream(
        "POST",
        f"{BASE_URL}/api/v1/conversations/{cid}/messages/stream",
        headers={**auth_headers, "Accept":"text/event-stream"},
        json={"content":"ciao", "clientMessageId":"m1"},
        timeout=60,
    ) as s:
        assert s.status_code == 200
        # read a few bytes
        chunk = next(s.iter_text())
        assert chunk is not None
