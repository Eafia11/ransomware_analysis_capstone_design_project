from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import sandbox as sandbox_api
from app.core.config import settings
from app.main import app


def test_sandbox_run_accepts_exe_and_schedules_background_task(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "sandbox_upload_dir", tmp_path / "sandbox_uploads")
    monkeypatch.setattr(settings, "sandbox_state_dir", tmp_path / "sandbox_sessions")

    started = []

    def fake_run_sandbox_session(session_id: str):
        started.append(session_id)

    monkeypatch.setattr(sandbox_api, "run_sandbox_session", fake_run_sandbox_session)

    client = TestClient(app)
    response = client.post(
        "/sandbox/run",
        data={"runtime_seconds": "45"},
        files={"file": ("payload.exe", b"MZ fake exe", "application/octet-stream")},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["filename"] == "payload.exe"
    assert body["runtime_seconds"] == 45
    assert body["session_id"] in started


def test_sandbox_run_rejects_non_exe(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "sandbox_upload_dir", tmp_path / "sandbox_uploads")
    monkeypatch.setattr(settings, "sandbox_state_dir", tmp_path / "sandbox_sessions")

    client = TestClient(app)
    response = client.post(
        "/sandbox/run",
        files={"file": ("events.jsonl", b"{}", "application/json")},
    )

    assert response.status_code == 400
    assert "Only .exe" in response.json()["detail"]


def test_sandbox_status_returns_saved_session(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "sandbox_upload_dir", tmp_path / "sandbox_uploads")
    monkeypatch.setattr(settings, "sandbox_state_dir", tmp_path / "sandbox_sessions")

    session = sandbox_api.create_sandbox_session(
        filename="payload.exe",
        content=b"MZ fake exe",
        runtime_seconds=60,
    )

    client = TestClient(app)
    response = client.get(f"/sandbox/status/{session['session_id']}")

    assert response.status_code == 200
    assert response.json()["session_id"] == session["session_id"]
