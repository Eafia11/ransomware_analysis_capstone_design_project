from __future__ import annotations

from typing import Any


SUSPICIOUS_PROCESS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "vssadmin",
    "wmic",
]


SUSPICIOUS_COMMAND_KEYWORDS = [
    "encodedcommand",
    "frombase64string",
    "invoke-expression",
    "iex ",
    "downloadstring",
    "downloadfile",
    "net user",
    "shadowcopy",
    "delete shadows",
    "wbadmin",
    "bcdedit",
    "cipher",
]


def extract_chain_features(chain: dict[str, Any]) -> dict[str, Any]:
    actions = chain.get("actions", [])

    feature = {
        "event_count": len(actions),
        "process_create_count": 0,
        "file_create_count": 0,
        "registry_modify_count": 0,
        "network_connect_count": 0,
        "uses_suspicious_process": 0,
        "uses_suspicious_command": 0,
        "has_multiple_behaviors": 0,
    }

    behavior_flags = {
        "process": 0,
        "file": 0,
        "registry": 0,
        "network": 0,
    }

    for action in actions:
        event_id = str(action.get("event_id") or "")
        image = (action.get("image") or "").lower()
        command_line = (action.get("command_line") or "").lower()
        combined = f"{image} {command_line}"

        if event_id == "1":
            feature["process_create_count"] += 1
            behavior_flags["process"] = 1
        elif event_id == "11":
            feature["file_create_count"] += 1
            behavior_flags["file"] = 1
        elif event_id in ["12", "13", "14"]:
            feature["registry_modify_count"] += 1
            behavior_flags["registry"] = 1
        elif event_id == "3":
            feature["network_connect_count"] += 1
            behavior_flags["network"] = 1

        if any(keyword in combined for keyword in SUSPICIOUS_PROCESS_KEYWORDS):
            feature["uses_suspicious_process"] = 1

        if any(keyword in combined for keyword in SUSPICIOUS_COMMAND_KEYWORDS):
            feature["uses_suspicious_command"] = 1

    behavior_count = sum(behavior_flags.values())
    feature["has_multiple_behaviors"] = 1 if behavior_count >= 2 else 0

    return feature


def score_chain(features: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if features["uses_suspicious_process"] == 1:
        score += 2
        reasons.append("의심 프로세스 사용")

    if features["uses_suspicious_command"] == 1:
        score += 3
        reasons.append("의심 명령어 포함")

    if features["file_create_count"] >= 3:
        score += 2
        reasons.append("파일 생성 다수")

    if features["registry_modify_count"] >= 2:
        score += 2
        reasons.append("레지스트리 수정 다수")

    if features["network_connect_count"] >= 1:
        score += 1
        reasons.append("네트워크 연결 존재")

    if features["has_multiple_behaviors"] == 1:
        score += 2
        reasons.append("복합 행위 발생")

    if features["event_count"] >= 5:
        score += 1
        reasons.append("이벤트 수 많음")

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

        results.append({
            "process_guid": chain.get("process_guid"),
            "image": chain.get("image"),
            "command_line": chain.get("command_line"),
            "parent_image": chain.get("parent_image"),
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
    return [r for r in results if r.get("label") == "suspicious"]