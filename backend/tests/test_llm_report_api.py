from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import llm_report as llm_report_api
from app.main import app


def test_generate_llm_report_updates_completed_analysis(monkeypatch):
    stored = {}

    monkeypatch.setattr(
        llm_report_api,
        "get_analysis",
        lambda analysis_id: {
            "analysis_id": analysis_id,
            "filename": "events.jsonl",
            "saved_path": "data/uploads/events.jsonl",
            "sha256": "0" * 64,
            "status": "completed",
            "result": {
                "summary": {"risk_level": "high"},
                "llm_report": {"analysis_id": analysis_id, "summary": {"risk_level": "high"}},
                "artifact_paths": {"llm_report": "data/reports/analysis-1_llm_input.json"},
            },
            "error": None,
        },
    )
    monkeypatch.setattr(
        llm_report_api,
        "create_ai_analysis_report",
        lambda analysis_id, result: {
            "analysis_id": analysis_id,
            "status": "completed",
            "provider": "openai",
            "model": "gpt-test",
            "response_id": "resp_123",
            "report": "AI ransomware report",
            "saved_path": "data/reports/analysis-1_ai_report.md",
            "metadata_path": "data/reports/analysis-1_ai_report_metadata.json",
        },
    )
    monkeypatch.setattr(
        llm_report_api,
        "update_analysis",
        lambda analysis_id, **updates: stored.update(
            {"analysis_id": analysis_id, **updates}
        ),
    )

    response = TestClient(app).post("/llm-report/analysis-1")

    assert response.status_code == 200
    body = response.json()
    assert body["report"] == "AI ransomware report"
    assert stored["analysis_id"] == "analysis-1"
    assert stored["result"]["ai_report"] == "AI ransomware report"
    assert stored["result"]["artifact_paths"]["ai_report"].endswith("_ai_report.md")


def test_generate_llm_report_requires_completed_analysis(monkeypatch):
    monkeypatch.setattr(
        llm_report_api,
        "get_analysis",
        lambda analysis_id: {
            "analysis_id": analysis_id,
            "filename": "events.jsonl",
            "saved_path": "data/uploads/events.jsonl",
            "sha256": "0" * 64,
            "status": "uploaded",
            "result": None,
            "error": None,
        },
    )

    response = TestClient(app).post("/llm-report/analysis-1")

    assert response.status_code == 409
    assert "Analysis must be completed" in response.json()["detail"]
