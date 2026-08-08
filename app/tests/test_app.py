from app import app


def client():
    app.testing = True
    return app.test_client()


def test_index():
    resp = client().get("/")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_healthz():
    resp = client().get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "healthy"


def test_version():
    resp = client().get("/version")
    assert resp.status_code == 200
    assert "version" in resp.get_json()
