from fastapi.testclient import TestClient

from app.api import analyze as analyze_api
from app.main import app


def test_analyze_returns_404_for_unknown_analysis(monkeypatch):
    monkeypatch.setattr(analyze_api, "get_analysis", lambda analysis_id: None)

    client = TestClient(app)
    response = client.post("/analyze/missing-id")

    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis ID was not found."


def test_analyze_runs_report_service_and_stores_result(monkeypatch):
    result = {
        "summary": {
            "parsed_events": 1,
            "sysmon_events": 1,
            "sysmon_core_events": 1,
            "attack_chains": 0,
            "suspicious_chains": 0,
            "events_by_type": {
                "total": 1,
                "by_channel": {},
                "by_provider": {},
                "by_event_id": {},
            },
        },
        "attack_chains": [],
        "abstracted_attack_chains": [],
        "rule_results": [],
        "suspicious_results": [],
    }
    stored = {}

    monkeypatch.setattr(
        analyze_api,
        "get_analysis",
        lambda analysis_id: {
            "analysis_id": analysis_id,
            "filename": "sample.json",
            "saved_path": "../data/uploads/sample.json",
            "sha256": "0" * 64,
            "status": "uploaded",
        },
    )
    monkeypatch.setattr(
        analyze_api,
        "set_analysis_status",
        lambda analysis_id, status: stored.update({"status": status}),
    )
    monkeypatch.setattr(
        analyze_api,
        "analyze_winlogbeat_file",
        lambda saved_path, analysis_id=None: result,
    )
    monkeypatch.setattr(
        analyze_api,
        "set_analysis_result",
        lambda analysis_id, analysis_result: {
            "analysis_id": analysis_id,
            "status": "completed",
            "result": analysis_result,
        },
    )

    client = TestClient(app)
    response = client.post("/analyze/analysis-1")

    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"] == "analysis-1"
    assert body["status"] == "completed"
    assert body["result"]["summary"]["parsed_events"] == 1
    assert stored["status"] == "analyzing"
