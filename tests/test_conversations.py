def test_conversation_crud(client):
    # create
    r = client.post("/api/v1/conversations", json={"title":"Test", "agentId":"main"})
    assert r.status_code in (200, 201)
    conv = r.json()
    cid = conv["conversationId"]

    # list
    r = client.get("/api/v1/conversations")
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(x["conversationId"] == cid for x in items)

    # get
    r = client.get(f"/api/v1/conversations/{cid}")
    assert r.status_code == 200

    # patch
    r = client.patch(f"/api/v1/conversations/{cid}", json={"title":"Test2"})
    assert r.status_code == 200

    # delete
    r = client.delete(f"/api/v1/conversations/{cid}")
    assert r.status_code in (200, 204)
