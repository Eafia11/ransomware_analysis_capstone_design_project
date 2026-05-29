from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.attack_chain_builder import (
    build_abstracted_attack_chains,
    build_attack_chain_candidates,
    filter_core_sysmon_events,
)
from app.services.ioc_extractor import extract_iocs_from_analysis, summarize_iocs
from app.services.mitre_mapper import enrich_results_with_mitre
from app.services.ml_detector import predict_chains_with_model
from app.services.normalizer import filter_events, summarize_events
from app.services.rule_detector import detect_malicious_chains, filter_suspicious_results
from app.services.winlogbeat_parser import parse_winlogbeat_file, save_json
from app.utils.file_utils import ensure_data_directories


def analyze_winlogbeat_file(
    file_path: str | Path,
    analysis_id: str | None = None,
    persist_artifacts: bool = True,
) -> dict[str, Any]:
    file_path = Path(file_path)
    artifact_id = analysis_id or file_path.stem
    parsed_events = parse_winlogbeat_file(str(file_path))
    sysmon_events = filter_events(
        parsed_events,
        channel="Microsoft-Windows-Sysmon/Operational",
    )
    sysmon_core_events = filter_core_sysmon_events(sysmon_events)
    attack_chains = build_attack_chain_candidates(sysmon_core_events)
    abstracted_attack_chains = build_abstracted_attack_chains(attack_chains)
    rule_results = detect_malicious_chains(attack_chains)
    rule_results = enrich_results_with_mitre(rule_results)
    rule_results = predict_chains_with_model(rule_results)
    suspicious_results = filter_suspicious_results(rule_results)
    iocs = extract_iocs_from_analysis(parsed_events, attack_chains)
    risk_level = calculate_risk_level(suspicious_results, iocs)
    key_findings = build_key_findings(suspicious_results, iocs, risk_level)
    llm_report = build_llm_report(
        artifact_id=artifact_id,
        summary={
            "parsed_events": len(parsed_events),
            "sysmon_events": len(sysmon_events),
            "sysmon_core_events": len(sysmon_core_events),
            "attack_chains": len(attack_chains),
            "suspicious_chains": len(suspicious_results),
            "risk_level": risk_level,
            "ioc_counts": summarize_iocs(iocs),
        },
        key_findings=key_findings,
        iocs=iocs,
        suspicious_results=suspicious_results,
        abstracted_attack_chains=abstracted_attack_chains,
    )

    result = {
        "summary": {
            "parsed_events": len(parsed_events),
            "sysmon_events": len(sysmon_events),
            "sysmon_core_events": len(sysmon_core_events),
            "attack_chains": len(attack_chains),
            "suspicious_chains": len(suspicious_results),
            "risk_level": risk_level,
            "ioc_counts": summarize_iocs(iocs),
            "events_by_type": summarize_events(parsed_events),
        },
        "risk_level": risk_level,
        "key_findings": key_findings,
        "iocs": iocs,
        "llm_report": llm_report,
        "attack_chains": attack_chains,
        "abstracted_attack_chains": abstracted_attack_chains,
        "rule_results": rule_results,
        "suspicious_results": suspicious_results,
    }

    if persist_artifacts:
        result["artifact_paths"] = save_analysis_artifacts(
            artifact_id=artifact_id,
            parsed_events=parsed_events,
            sysmon_events=sysmon_events,
            sysmon_core_events=sysmon_core_events,
            attack_chains=attack_chains,
            abstracted_attack_chains=abstracted_attack_chains,
            rule_results=rule_results,
            suspicious_results=suspicious_results,
            llm_report=llm_report,
            report=result,
        )

    return result


def save_analysis_artifacts(
    artifact_id: str,
    parsed_events: list[dict[str, Any]],
    sysmon_events: list[dict[str, Any]],
    sysmon_core_events: list[dict[str, Any]],
    attack_chains: list[dict[str, Any]],
    abstracted_attack_chains: list[dict[str, Any]],
    rule_results: list[dict[str, Any]],
    suspicious_results: list[dict[str, Any]],
    llm_report: dict[str, Any],
    report: dict[str, Any],
) -> dict[str, str]:
    ensure_data_directories(
        settings.parsed_dir,
        settings.normalized_dir,
        settings.analyzed_dir,
        settings.reports_dir,
    )

    artifact_paths = {
        "parsed_events": str(settings.parsed_dir / f"{artifact_id}_parsed_logs.json"),
        "sysmon_events": str(settings.normalized_dir / f"{artifact_id}_sysmon_only.json"),
        "sysmon_core_events": str(settings.normalized_dir / f"{artifact_id}_sysmon_core.json"),
        "attack_chains": str(settings.analyzed_dir / f"{artifact_id}_attack_chains.json"),
        "abstracted_attack_chains": str(
            settings.analyzed_dir / f"{artifact_id}_abstracted_attack_chains.json"
        ),
        "rule_results": str(settings.analyzed_dir / f"{artifact_id}_rule_detection_results.json"),
        "suspicious_results": str(settings.analyzed_dir / f"{artifact_id}_suspicious_only.json"),
        "llm_report": str(settings.reports_dir / f"{artifact_id}_llm_input.json"),
        "report": str(settings.reports_dir / f"{artifact_id}_analysis_report.json"),
    }

    save_json(parsed_events, artifact_paths["parsed_events"])
    save_json(sysmon_events, artifact_paths["sysmon_events"])
    save_json(sysmon_core_events, artifact_paths["sysmon_core_events"])
    save_json(attack_chains, artifact_paths["attack_chains"])
    save_json(abstracted_attack_chains, artifact_paths["abstracted_attack_chains"])
    save_json(rule_results, artifact_paths["rule_results"])
    save_json(suspicious_results, artifact_paths["suspicious_results"])
    save_json(llm_report, artifact_paths["llm_report"])
    save_json({**report, "artifact_paths": artifact_paths}, artifact_paths["report"])

    return artifact_paths


def calculate_risk_level(
    suspicious_results: list[dict[str, Any]],
    iocs: dict[str, list[str]],
) -> str:
    highest_score = max((result.get("score", 0) for result in suspicious_results), default=0)
    ransomware_ioc_count = _count_ransomware_iocs(iocs)

    if highest_score >= 12:
        return "high"

    if highest_score >= 8 and ransomware_ioc_count > 0:
        return "high"

    if len(suspicious_results) >= 3 and highest_score >= 5:
        return "high"

    if highest_score >= 5 or suspicious_results:
        return "medium"

    if ransomware_ioc_count >= 2:
        return "medium"

    return "low"


def _count_ransomware_iocs(iocs: dict[str, list[str]]) -> int:
    ransomware_ioc_keys = {
        "ransom_notes",
        "encrypted_extensions",
        "suspicious_file_names",
        "bitcoin_addresses",
    }
    return sum(len(iocs.get(key, [])) for key in ransomware_ioc_keys)


def build_key_findings(
    suspicious_results: list[dict[str, Any]],
    iocs: dict[str, list[str]],
    risk_level: str,
) -> list[str]:
    risk_labels = {
        "low": "\ub0ae\uc74c",
        "medium": "\uc911\uac04",
        "high": "\ub192\uc74c",
    }
    findings = [f"\uc804\uccb4 \uc704\ud5d8\ub3c4\ub294 {risk_labels.get(risk_level, risk_level)}\uc785\ub2c8\ub2e4."]

    if suspicious_results:
        top_result = suspicious_results[0]
        process_name = top_result.get("image") or "\uc54c \uc218 \uc5c6\ub294 \ud504\ub85c\uc138\uc2a4"
        findings.append(
            "\uac00\uc7a5 \ub192\uc740 \uc810\uc218\uc758 \uc758\uc2ec \uccb4\uc778: "
            f"{process_name} "
            f"(\uc810\uc218 {top_result.get('score', 0)})."
        )
    else:
        findings.append("\ub8f0 \uc784\uacc4\uac12\uc744 \ub118\uc740 \uc758\uc2ec \uacf5\uaca9 \uccb4\uc778\uc740 \uc5c6\uc2b5\ub2c8\ub2e4.")

    ioc_counts = summarize_iocs(iocs)
    total_iocs = sum(ioc_counts.values())
    findings.append(f"{len(ioc_counts)}\uac1c \uce74\ud14c\uace0\ub9ac\uc5d0\uc11c IOC \uac12 {total_iocs}\uac1c\ub97c \ucd94\ucd9c\ud588\uc2b5\ub2c8\ub2e4.")

    return findings


def build_llm_report(
    artifact_id: str,
    summary: dict[str, Any],
    key_findings: list[str],
    iocs: dict[str, list[str]],
    suspicious_results: list[dict[str, Any]],
    abstracted_attack_chains: list[dict[str, Any]],
) -> dict[str, Any]:
    top_suspicious = suspicious_results[:10]

    return {
        "schema_version": "1.0",
        "analysis_id": artifact_id,
        "summary": summary,
        "key_findings": key_findings,
        "iocs": iocs,
        "mitre_attack": collect_mitre_techniques(top_suspicious),
        "suspicious_processes": [
            {
                "image": result.get("image"),
                "command_line": result.get("command_line"),
                "score": result.get("score"),
                "reasons": result.get("reasons", []),
                "mitre_attack": result.get("mitre_attack", []),
            }
            for result in top_suspicious
        ],
        "attack_chain_summaries": abstracted_attack_chains[:10],
        "reporting_instruction": (
            "\uc694\uc57d, IOC, MITRE ATT&CK, \uc758\uc2ec \ud504\ub85c\uc138\uc2a4, "
            "\uacf5\uaca9 \uccb4\uc778 \uadfc\uac70\ub97c \uc0ac\uc6a9\ud574 \ud55c\uad6d\uc5b4 "
            "\ub79c\uc12c\uc6e8\uc5b4 \ubd84\uc11d \ubcf4\uace0\uc11c\ub97c \uac04\uacb0\ud558\uac8c \uc791\uc131\ud558\uc138\uc694. "
            "\ud310\ub2e8 \uadfc\uac70\uc640 \uc624\ud0d0 \uac00\ub2a5\uc131\uc744 \ud568\uaed8 \uc124\uba85\ud558\uc138\uc694."
        ),
    }


def collect_mitre_techniques(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    techniques = []

    for result in results:
        for technique in result.get("mitre_attack", []):
            key = (technique.get("technique_id"), technique.get("tactic"))
            if key not in seen:
                seen.add(key)
                techniques.append({**technique})
                continue

            existing = next(
                item
                for item in techniques
                if (item.get("technique_id"), item.get("tactic")) == key
            )
            existing["evidence"] = _merge_unique_limited([
                *existing.get("evidence", []),
                *technique.get("evidence", []),
            ])
            existing["confidence"] = _higher_mitre_confidence(
                existing.get("confidence"),
                technique.get("confidence"),
            )

    return techniques


def _merge_unique_limited(values: list[str], limit: int = 5) -> list[str]:
    merged = []
    for value in values:
        if value and value not in merged:
            merged.append(value)
        if len(merged) >= limit:
            break
    return merged


def _higher_mitre_confidence(left: str | None, right: str | None) -> str | None:
    order = {"low": 0, "medium": 1, "high": 2}
    if left is None:
        return right
    if right is None:
        return left
    return left if order[left] >= order[right] else right
