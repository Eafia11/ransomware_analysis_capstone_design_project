from __future__ import annotations

from typing import Any


MITRE_RULES = [
    {
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
        "keywords": ["powershell", "encodedcommand", "frombase64string", "downloadstring", "iex "],
    },
    {
        "technique_id": "T1059.003",
        "technique": "Windows Command Shell",
        "tactic": "Execution",
        "keywords": ["cmd.exe", "/c "],
    },
    {
        "technique_id": "T1105",
        "technique": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["downloadfile", "downloadstring", "certutil", "bitsadmin"],
    },
    {
        "technique_id": "T1490",
        "technique": "Inhibit System Recovery",
        "tactic": "Impact",
        "keywords": ["vssadmin", "delete shadows", "shadowcopy", "wbadmin", "bcdedit"],
    },
    {
        "technique_id": "T1112",
        "technique": "Modify Registry",
        "tactic": "Defense Evasion",
        "event_ids": {"12", "13", "14"},
        "keywords": [],
    },
]


def map_action_to_mitre(action: dict[str, Any]) -> list[dict[str, str]]:
    event_id = str(action.get("event_id") or "")
    combined = " ".join([
        str(action.get("image") or ""),
        str(action.get("command_line") or ""),
        str(action.get("target_object") or ""),
        str(action.get("details") or ""),
    ]).lower()
    matches = []

    for rule in MITRE_RULES:
        event_ids = rule.get("event_ids")
        keyword_match = any(keyword in combined for keyword in rule.get("keywords", []))
        event_match = event_ids is not None and event_id in event_ids

        if keyword_match or event_match:
            matches.append({
                "technique_id": rule["technique_id"],
                "technique": rule["technique"],
                "tactic": rule["tactic"],
            })

    return matches


def map_chain_to_mitre(chain: dict[str, Any]) -> list[dict[str, str]]:
    seen = set()
    mapped = []

    for action in chain.get("actions", []):
        for match in map_action_to_mitre(action):
            key = (match["technique_id"], match["tactic"])
            if key in seen:
                continue
            seen.add(key)
            mapped.append(match)

    return mapped


def enrich_results_with_mitre(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **result,
            "mitre_attack": map_chain_to_mitre(result),
        }
        for result in results
    ]
