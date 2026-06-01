from pathlib import Path

from app.core.config import settings
from app.services import llm_report_service
from app.services.report_service import build_llm_report


def test_build_llm_report_contains_korean_prompt_and_evidence_contract():
    llm_report = build_llm_report(
        artifact_id="analysis-llm",
        summary={
            "parsed_events": 3,
            "sysmon_events": 3,
            "sysmon_core_events": 3,
            "attack_chains": 1,
            "suspicious_chains": 1,
            "risk_level": "high",
            "ioc_counts": {"ransom_notes": 1},
        },
        key_findings=["\uc804\uccb4 \uc704\ud5d8\ub3c4\ub294 \ub192\uc74c\uc785\ub2c8\ub2e4."],
        iocs={"ransom_notes": ["HOW_TO_DECRYPT.txt"]},
        suspicious_results=[
            {
                "image": r"C:\Windows\System32\vssadmin.exe",
                "command_line": "vssadmin delete shadows /all /quiet",
                "score": 10,
                "reasons": ["\ubcf5\uad6c \ubc29\ud574 \uba85\ub839 \uc2e4\ud589"],
                "mitre_attack": [
                    {
                        "technique_id": "T1490",
                        "technique": "Inhibit System Recovery",
                        "tactic": "Impact",
                        "evidence": ["vssadmin delete shadows /all /quiet"],
                        "confidence": "high",
                    }
                ],
            }
        ],
        abstracted_attack_chains=[
            {
                "process": r"C:\Windows\System32\vssadmin.exe",
                "summary": "shadow copy deletion",
            }
        ],
    )

    assert llm_report["schema_version"] == "1.0"
    assert llm_report["analysis_id"] == "analysis-llm"
    assert (
        "\ud55c\uad6d\uc5b4 \ub79c\uc12c\uc6e8\uc5b4 \ubd84\uc11d \ubcf4\uace0\uc11c"
        in llm_report["reporting_instruction"]
    )
    assert "\uc624\ud0d0 \uac00\ub2a5\uc131" in llm_report["reporting_instruction"]
    assert llm_report["mitre_attack"][0]["technique_id"] == "T1490"
    assert llm_report["mitre_attack"][0]["confidence"] == "high"
    assert llm_report["mitre_attack"][0]["evidence"] == [
        "vssadmin delete shadows /all /quiet"
    ]
    assert llm_report["suspicious_processes"][0]["reasons"] == [
        "\ubcf5\uad6c \ubc29\ud574 \uba85\ub839 \uc2e4\ud589"
    ]


def test_create_ai_analysis_report_calls_responses_api_and_saves_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    monkeypatch.setattr(settings, "llm_model", "gpt-test")
    monkeypatch.setattr(settings, "reports_dir", tmp_path)

    captured = {}

    class FakeResponse:
        id = "resp_test"
        output_text = "AI 보고서 본문"

    class FakeResponses:
        def create(self, **kwargs):
            captured.update(kwargs)
            return FakeResponse()

    class FakeClient:
        responses = FakeResponses()

    response = llm_report_service.create_ai_analysis_report(
        analysis_id="analysis-llm",
        result={
            "llm_report": {
                "analysis_id": "analysis-llm",
                "summary": {"risk_level": "high"},
            }
        },
        client_factory=lambda **kwargs: FakeClient(),
    )

    assert captured["model"] == "gpt-test"
    assert "Do not invent evidence" in captured["instructions"]
    assert '"risk_level": "high"' in captured["input"]
    assert response["report"] == "AI 보고서 본문"
    assert Path(response["saved_path"]).read_text(encoding="utf-8") == "AI 보고서 본문"
    assert Path(response["metadata_path"]).exists()
