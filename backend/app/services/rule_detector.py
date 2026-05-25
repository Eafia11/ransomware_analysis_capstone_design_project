from __future__ import annotations

from typing import Any

from app.services.feature_extractor import extract_chain_features


def score_chain(features: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if features["uses_suspicious_process"] == 1:
        score += 2
        reasons.append("suspicious process used")

    if features["uses_suspicious_command"] == 1:
        score += 3
        reasons.append("suspicious command keyword found")

    if features["file_create_count"] >= 3:
        score += 2
        reasons.append("multiple file creation events")

    if features["registry_modify_count"] >= 2:
        score += 2
        reasons.append("multiple registry modification events")

    if features["network_connect_count"] >= 1:
        score += 1
        reasons.append("network connection observed")

    if features["has_multiple_behaviors"] == 1:
        score += 2
        reasons.append("multiple behavior categories observed")

    if features["event_count"] >= 5:
        score += 1
        reasons.append("high event count")

    return score, reasons


def classify_chain(score: int) -> str:
    if score >= 5:
        return "suspicious"
    return "benign"


def detect_malicious_chains(attack_chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []

    for chain in attack_chains:
        features = extract_chain_features(chain)
        score, reasons = score_chain(features)
        label = classify_chain(score)
        parent_process = chain.get("parent_process") or {}

        results.append({
            "process_guid": chain.get("process_guid"),
            "image": chain.get("image"),
            "command_line": chain.get("command_line"),
            "parent_image": parent_process.get("image"),
            "user": chain.get("user"),
            "start_time": chain.get("start_time"),
            "event_count": chain.get("event_count"),
            "features": features,
            "score": score,
            "label": label,
            "reasons": reasons,
            "actions": chain.get("actions", []),
        })

    results.sort(key=lambda x: (-x["score"], x.get("start_time") or ""))
    return results


def filter_suspicious_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [result for result in results if result.get("label") == "suspicious"]
