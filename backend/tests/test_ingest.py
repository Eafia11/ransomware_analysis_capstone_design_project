from fastapi.testclient import TestClient

from app.api import analyze as analyze_api
from app.core.config import settings
from app.main import app
from app.services import ingest_service


def test_ingest_winlogbeat_appends_events_and_returns_analysis(monkeypatch, tmp_path):
    records = {}

    def fake_create_analysis(analysis):
        records[analysis["analysis_id"]] = analysis
        return analysis

    def fake_get_analysis(analysis_id):
        return records.get(analysis_id)

    def fake_update_analysis(analysis_id, **updates):
        records[analysis_id].update(updates)
        return records[analysis_id]

    monkeypatch.setattr(ingest_service.settings, "ingest_dir", tmp_path)
    monkeypatch.setattr(ingest_service, "create_analysis", fake_create_analysis)
    monkeypatch.setattr(ingest_service, "get_analysis", fake_get_analysis)
    monkeypatch.setattr(ingest_service, "update_analysis", fake_update_analysis)

    client = TestClient(app)
    event = {
        "@timestamp": "2026-05-29T10:00:00Z",
        "host": {"name": "analysis-vm-01"},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "event_data": {"Image": r"C:\Windows\System32\cmd.exe"},
        },
    }

    first_response = client.post("/ingest/winlogbeat", json=event)
    second_response = client.post("/ingest/winlogbeat", json=event)

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    first = first_response.json()
    second = second_response.json()

    assert first["analysis_id"] == second["analysis_id"]
    assert first["stream_id"] == "analysis-vm-01"
    assert first["source_host"] == "analysis-vm-01"
    assert first["event_count"] == 1
    assert second["event_count"] == 2
    assert second["status"] == "uploaded"
    assert tmp_path.joinpath("analysis-vm-01.jsonl").is_file()
    assert len(tmp_path.joinpath("analysis-vm-01.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_ingest_winlogbeat_rejects_empty_body():
    client = TestClient(app)

    response = client.post("/ingest/winlogbeat", json={})

    assert response.status_code == 400
    assert response.json()["detail"] == "Event body cannot be empty."


def test_logs_endpoint_uses_winlogbeat_ingest_pipeline(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "api_key", None)
    records = {}

    def fake_create_analysis(analysis):
        records[analysis["analysis_id"]] = analysis
        return analysis

    def fake_get_analysis(analysis_id):
        return records.get(analysis_id)

    def fake_update_analysis(analysis_id, **updates):
        records[analysis_id].update(updates)
        return records[analysis_id]

    monkeypatch.setattr(ingest_service.settings, "ingest_dir", tmp_path)
    monkeypatch.setattr(ingest_service, "create_analysis", fake_create_analysis)
    monkeypatch.setattr(ingest_service, "get_analysis", fake_get_analysis)
    monkeypatch.setattr(ingest_service, "update_analysis", fake_update_analysis)

    client = TestClient(app)
    event = {
        "@timestamp": "2026-05-29T10:00:00Z",
        "winlog": {
            "computer_name": "sandbox-win-01",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "event_data": {"CommandLine": "calc.exe"},
        },
    }

    response = client.post("/logs", json=event)

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"]
    assert body["stream_id"] == "sandbox-win-01"
    assert body["source_host"] == "sandbox-win-01"
    assert body["status"] == "uploaded"
    assert body["event_count"] == 1
    assert tmp_path.joinpath("sandbox-win-01.jsonl").is_file()


def test_logs_endpoint_rejects_public_requests_when_api_key_is_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "api_key", "test-secret")
    monkeypatch.setattr(ingest_service.settings, "ingest_dir", tmp_path)

    client = TestClient(app)
    event = {
        "winlog": {
            "computer_name": "sandbox-win-01",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
        },
    }

    missing = client.post(
        "/logs",
        headers={"X-Forwarded-For": "203.0.113.55"},
        json=event,
    )
    wrong = client.post(
        "/logs",
        headers={
            "X-Forwarded-For": "203.0.113.55",
            "X-NetGuardian-Api-Key": "wrong",
        },
        json=event,
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401


def test_logs_endpoint_allows_loopback_logstash_without_api_key(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "api_key", "test-secret")
    records = {}

    def fake_create_analysis(analysis):
        records[analysis["analysis_id"]] = analysis
        return analysis

    monkeypatch.setattr(ingest_service.settings, "ingest_dir", tmp_path)
    monkeypatch.setattr(ingest_service, "create_analysis", fake_create_analysis)
    monkeypatch.setattr(ingest_service, "get_analysis", lambda analysis_id: records.get(analysis_id))
    monkeypatch.setattr(
        ingest_service,
        "update_analysis",
        lambda analysis_id, **updates: records[analysis_id].update(updates)
        or records[analysis_id],
    )

    client = TestClient(app)
    response = client.post(
        "/logs",
        headers={"X-Forwarded-For": "127.0.0.1"},
        json={
            "winlog": {
                "computer_name": "sandbox-win-01",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["stream_id"] == "sandbox-win-01"


def test_analyze_stream_reuses_existing_analysis_flow(monkeypatch):
    analysis_id = "stream-analysis-id"

    monkeypatch.setattr(
        analyze_api,
        "get_analysis",
        lambda requested_id: {
            "analysis_id": requested_id,
            "filename": "analysis-vm-01.jsonl",
            "saved_path": "ignored.jsonl",
            "sha256": "a" * 64,
            "status": "uploaded",
            "result": None,
            "error": None,
        },
    )
    monkeypatch.setattr(analyze_api, "set_analysis_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        analyze_api,
        "analyze_winlogbeat_file",
        lambda *args, **kwargs: {"summary": {}},
    )
    monkeypatch.setattr(
        analyze_api,
        "set_analysis_result",
        lambda requested_id, result: {"analysis_id": requested_id, "status": "completed"},
    )

    client = TestClient(app)
    response = client.post(f"/analyze/stream/{analysis_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == analysis_id
    assert body["status"] == "completed"
    assert body["result"]["summary"]["parsed_events"] == 0
