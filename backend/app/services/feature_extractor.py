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


ML_FEATURE_COLUMNS = [
    "event_count",
    "process_create_count",
    "file_create_count",
    "registry_modify_count",
    "network_connect_count",
    "uses_suspicious_process",
    "uses_suspicious_command",
    "has_multiple_behaviors",
]


def extract_chain_features(chain: dict[str, Any]) -> dict[str, Any]:
    actions = chain.get("actions", [])
    features = {
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
            features["process_create_count"] += 1
            behavior_flags["process"] = 1
        elif event_id == "11":
            features["file_create_count"] += 1
            behavior_flags["file"] = 1
        elif event_id in {"12", "13", "14"}:
            features["registry_modify_count"] += 1
            behavior_flags["registry"] = 1
        elif event_id == "3":
            features["network_connect_count"] += 1
            behavior_flags["network"] = 1

        if any(keyword in combined for keyword in SUSPICIOUS_PROCESS_KEYWORDS):
            features["uses_suspicious_process"] = 1

        if any(keyword in combined for keyword in SUSPICIOUS_COMMAND_KEYWORDS):
            features["uses_suspicious_command"] = 1

    features["has_multiple_behaviors"] = 1 if sum(behavior_flags.values()) >= 2 else 0
    return features


def features_to_vector(features: dict[str, Any]) -> list[float]:
    return [float(features.get(column, 0) or 0) for column in ML_FEATURE_COLUMNS]


def chains_to_feature_rows(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [extract_chain_features(chain) for chain in chains]
