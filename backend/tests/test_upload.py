from fastapi.testclient import TestClient

from app.api import upload as upload_api
from app.main import app
from app.utils.hash_utils import calculate_sha256


def test_upload_file_saves_file_and_returns_analysis(monkeypatch, tmp_path):
    stored = {}

    def fake_create_analysis(analysis):
        stored.update(analysis)
        return analysis

    monkeypatch.setattr(upload_api.settings, "upload_dir", tmp_path)
    monkeypatch.setattr(upload_api, "create_analysis", fake_create_analysis)

    client = TestClient(app)
    content = b'{"event": "sample"}\n'
    response = client.post(
        "/upload",
        files={"file": ("sample log.json", content, "application/json")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "sample log.json"
    assert body["sha256"] == calculate_sha256(content)
    assert body["status"] == "uploaded"
    assert "sample_log.json" in body["saved_path"]
    assert stored["analysis_id"] == body["analysis_id"]


def test_upload_rejects_unsupported_extension(monkeypatch, tmp_path):
    monkeypatch.setattr(upload_api.settings, "upload_dir", tmp_path)

    client = TestClient(app)
    response = client.post(
        "/upload",
        files={"file": ("sample.exe", b"not allowed", "application/octet-stream")},
    )

    assert response.status_code == 400
    assert "Unsupported file type" in response.json()["detail"]
