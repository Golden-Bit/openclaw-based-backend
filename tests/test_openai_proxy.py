import pytest


@pytest.mark.asyncio
async def test_openai_responses_proxy_creates_conversation_alias(client):
    # Call openai-compatible endpoint with user alias
    r = await client.post("/v1/responses", json={"model": "openclaw:main", "input": "hi", "user": "alice", "stream": False})
    assert r.status_code == 200
    j = r.json()
    assert j.get("mock") is True
