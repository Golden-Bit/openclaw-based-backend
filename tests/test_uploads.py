def test_upload_create(client):
    r = client.post("/api/v1/uploads", json={"filename":"hello.txt","contentType":"text/plain"})
    assert r.status_code == 200
    data = r.json()
    assert "uploadId" in data
    assert "putUrl" in data
    assert "getUrl" in data
